---
title: "Kruise"
date: 2025-08-18T21:29:19+08:00
summary: 注入过程,原地升级原理
categories:
  - kubernetes
---



## 基本知识

### v1.27.1新特性 InPlacePodVerticalScaling(就地垂直伸缩）

InPlacePodVerticalScaling（就地垂直伸缩）是 Kubernetes 中v1.27.1的一个特性，它允许在不重启 Pod 的情况下动态调整 Pod 中容器的资源限制（Resource Limits）

传统上，在 Kubernetes 中更新 Pod 的资源限制需要重新创建 Pod，这会导致应用程序中断和服务不可用的情况。但是，通过使用 InPlacePodVerticalScaling，可以实现对 Pod 进行资源限制的动态更新，而无需重新创建 Pod。


## 注入过程

```go
var (
	// HandlerGetterMap contains admission webhook handlers
	HandlerGetterMap = map[string]types.HandlerGetter{
		// key 为 path 
		"mutate-pod": func(mgr manager.Manager) admission.Handler {
			return &PodCreateHandler{
				Client:  mgr.GetClient(),
				Decoder: admission.NewDecoder(mgr.GetScheme()),
			}
		},
	}
)

```

```go
func (h *PodCreateHandler) Handle(ctx context.Context, req admission.Request) admission.Response {
	obj := &corev1.Pod{}

	err := h.Decoder.Decode(req, obj)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	// when pod.namespace is empty, using req.namespace
	if obj.Namespace == "" {
		obj.Namespace = req.Namespace
	}
	oriObj := obj.DeepCopy()
	var changed bool
    // 注入pod的readiness probe
	if skip := injectPodReadinessGate(req, obj); !skip {
		changed = true
	}

	if utilfeature.DefaultFeatureGate.Enabled(features.WorkloadSpread) {
		if skip, err := h.workloadSpreadMutatingPod(ctx, req, obj); err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		} else if !skip {
			changed = true
		}
	}
    // 这里来注入sidecar容器
	if skip, err := h.sidecarsetMutatingPod(ctx, req, obj); err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	} else if !skip {
		changed = true
	}

	//  // 初始化容器的启动顺序
	if skip, err := h.containerLaunchPriorityInitialization(ctx, req, obj); err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	} else if !skip {
		changed = true
	}

	// patch related-pub annotation in pod
	if utilfeature.DefaultFeatureGate.Enabled(features.PodUnavailableBudgetUpdateGate) ||
		utilfeature.DefaultFeatureGate.Enabled(features.PodUnavailableBudgetDeleteGate) {
		if skip, err := h.pubMutatingPod(ctx, req, obj); err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		} else if !skip {
			changed = true
		}
	}

	// persistent pod state 
	if skip, err := h.persistentPodStateMutatingPod(ctx, req, obj); err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	} else if !skip {
		changed = true
	}

	// EnhancedLivenessProbe enabled
	if utilfeature.DefaultFeatureGate.Enabled(features.EnhancedLivenessProbeGate) {
		if skip, err := h.enhancedLivenessProbeWhenPodCreate(ctx, req, obj); err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		} else if !skip {
			changed = true
		}
	}

	if utilfeature.DefaultFeatureGate.Enabled(features.EnablePodProbeMarkerOnServerless) {
		if skip, err := h.podProbeMarkerMutatingPod(ctx, req, obj); err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		} else if !skip {
			changed = true
		}
	}

	if !changed {
		return admission.Allowed("")
	}
	marshalled, err := json.Marshal(obj)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	original, err := json.Marshal(oriObj)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(original, marshalled)
}

```




## 原地升级

{{<figure src="./in-place_update_process.png#center" width=800px >}}


### 需求

当我们升级 Pod 中一些 sidecar 容器（如采集日志、监控等）时，其实并不希望干扰到业务容器的运行。
但面对这种场景，Deployment 或 StatefulSet 的升级都会将整个 Pod 重建，势必会对业务造成一定的影响。而容器级别的原地升级变动的范围非常可控，只会将需要升级的容器做重建，其余容器包括网络、挂载盘都不会受到影响。


### 优点
- 节省了调度的耗时，Pod 的位置、资源都不发生变化； 节省了分配网络的耗时，Pod 还使用原有的 IP； 节省了分配、挂载远程盘的耗时，Pod 还使用原有的 PV（且都是已经在 Node 上挂载好的）；
- 节省了大部分拉取镜像的耗时，因为 Node 上已经存在了应用的旧镜像，当拉取新版本镜像时只需要下载很少的几层 layer。
- pod 的其他容器可以不受影响


### 原理
每个 Node 上的 Kubelet，会针对本机上所有 Pod.spec.containers 中的每个 container 计算一个 hash 值，并记录到实际创建的容器中。

如果我们修改了 Pod 中某个 container 的 image 字段，kubelet 会发现 container 的 hash 发生了变化、与机器上过去创建的容器 hash 不一致，而后 kubelet 就会把旧容器停掉，然后根据最新 Pod spec 中的 container 来创建新的容器。


```go
func (m *kubeGenericRuntimeManager) computePodActions(ctx context.Context, pod *v1.Pod, podStatus *kubecontainer.PodStatus) podActions {
	klog.V(5).InfoS("Syncing Pod", "pod", klog.KObj(pod))

	createPodSandbox, attempt, sandboxID := runtimeutil.PodSandboxChanged(pod, podStatus)
	changes := podActions{
		KillPod:           createPodSandbox,
		CreateSandbox:     createPodSandbox,
		SandboxID:         sandboxID,
		Attempt:           attempt,
		ContainersToStart: []int{},
		ContainersToKill:  make(map[kubecontainer.ContainerID]containerToKillInfo),
	}

    // ..
	// check the status of containers.
	for idx, container := range pod.Spec.Containers {
		containerStatus := podStatus.FindContainerStatusByName(container.Name)

        // ...
		
		// The container is running, but kill the container if any of the following condition is met.
		var message string
		var reason containerKillReason
		restart := shouldRestartOnFailure(pod)
		// Do not restart if only the Resources field has changed with InPlacePodVerticalScaling enabled
		if _, _, changed := containerChanged(&container, containerStatus); changed &&
			(!isInPlacePodVerticalScalingAllowed(pod) ||
				kubecontainer.HashContainerWithoutResources(&container) != containerStatus.HashWithoutResources) {
			// 没有开启原地升级,且除了资源后的 hash 更改
			message = fmt.Sprintf("Container %s definition changed", container.Name)
			// Restart regardless of the restart policy because the container
			// spec changed.
			restart = true
		} else if liveness, found := m.livenessManager.Get(containerStatus.ID); found && liveness == proberesults.Failure {
			// If the container failed the liveness probe, we should kill it.
			message = fmt.Sprintf("Container %s failed liveness probe", container.Name)
			reason = reasonLivenessProbe
		} else if startup, found := m.startupManager.Get(containerStatus.ID); found && startup == proberesults.Failure {
			// If the container failed the startup probe, we should kill it.
			message = fmt.Sprintf("Container %s failed startup probe", container.Name)
			reason = reasonStartupProbe
		} else if isInPlacePodVerticalScalingAllowed(pod) && !m.computePodResizeAction(pod, idx, containerStatus, &changes) {
			// computePodResizeAction updates 'changes' if resize policy requires restarting this container
			continue
		} else {
			// Keep the container.
			keepCount++
			continue
		}

		// We need to kill the container, but if we also want to restart the
		// container afterwards, make the intent clear in the message. Also do
		// not kill the entire pod since we expect container to be running eventually.
		if restart {
			message = fmt.Sprintf("%s, will be restarted", message)
			changes.ContainersToStart = append(changes.ContainersToStart, idx)
		}

		changes.ContainersToKill[containerStatus.ID] = containerToKillInfo{
			name:      containerStatus.Name,
			container: &pod.Spec.Containers[idx],
			message:   message,
			reason:    reason,
		}
		klog.V(2).InfoS("Message for Container of pod", "containerName", container.Name, "containerStatusID", containerStatus.ID, "pod", klog.KObj(pod), "containerMessage", message)
	}

	if keepCount == 0 && len(changes.ContainersToStart) == 0 {
		changes.KillPod = true
	}

	return changes
}

```



```go
// https://github.com/kubernetes/kubernetes/blob/9ddf1a02bd436e8ce16fb71ab832f4e0eca57a3a/pkg/kubelet/kuberuntime/kuberuntime_manager.go

// container 判断
func containerChanged(container *v1.Container, containerStatus *kubecontainer.Status) (uint64, uint64, bool) {
	// 计算 hash 
	expectedHash := kubecontainer.HashContainer(container)
	return expectedHash, containerStatus.Hash, containerStatus.Hash != expectedHash
}
```

```go
func HashContainer(container *v1.Container) uint64 {
	hash := fnv.New32a()
	// Omit nil or empty field when calculating hash value
	// Please see https://github.com/kubernetes/kubernetes/issues/53644
	containerJSON, _ := json.Marshal(container)
	hashutil.DeepHashObject(hash, containerJSON)
	return uint64(hash.Sum32())
}

```

```go
// 不带资源计算container的hash
func HashContainerWithoutResources(container *v1.Container) uint64 {
	// InPlacePodVerticalScaling enables mutable Resources field.
	// Changes to this field may not require container restart depending on policy.
	// Compute hash over fields besides the Resources field
	// NOTE: This is needed during alpha and beta so that containers using Resources but
	//       not subject to In-place resize are not unexpectedly restarted when
	//       InPlacePodVerticalScaling feature-gate is toggled.
	//TODO(vinaykul,InPlacePodVerticalScaling): Remove this in GA+1 and make HashContainerWithoutResources to become Hash.
	hashWithoutResources := fnv.New32a()
	containerCopy := container.DeepCopy()
	containerCopy.Resources = v1.ResourceRequirements{}
	containerJSON, _ := json.Marshal(containerCopy)
	hashutil.DeepHashObject(hashWithoutResources, containerJSON)
	return uint64(hashWithoutResources.Sum32())
}

```


### kruise 原地升级原理

#### ContainerRecreateRequest
https://openkruise.io/docs/user-manuals/containerrecreaterequest

{{<figure src="./ContainerRecreateRequest.png#center" width=800px >}}
```go
func (c *Controller) manage(crr *appsv1alpha1.ContainerRecreateRequest) error {
	runtimeManager, err := c.newRuntimeManager(c.runtimeFactory, crr)
	if err != nil {
		klog.ErrorS(err, "Failed to find runtime service", "namespace", crr.Namespace, "name", crr.Name)
		return c.completeCRRStatus(crr, fmt.Sprintf("failed to find runtime service: %v", err))
	}

	pod := convertCRRToPod(crr)

	// 获取 pod 状态
	podStatus, err := runtimeManager.GetPodStatus(context.TODO(), pod.UID, pod.Name, pod.Namespace)
	if err != nil {
		return fmt.Errorf("failed to GetPodStatus %s/%s with uid %s: %v", pod.Namespace, pod.Name, pod.UID, err)
	}
	klog.V(5).InfoS("CRR for Pod GetPodStatus", "namespace", crr.Namespace, "name", crr.Name, "podName", pod.Name, "podStatus", util.DumpJSON(podStatus))

	newCRRContainerRecreateStates := getCurrentCRRContainersRecreateStates(crr, podStatus)
	if !reflect.DeepEqual(crr.Status.ContainerRecreateStates, newCRRContainerRecreateStates) {
		return c.patchCRRContainerRecreateStates(crr, newCRRContainerRecreateStates)
	}

	var completedCount int
	for i := range newCRRContainerRecreateStates {
		state := &newCRRContainerRecreateStates[i]
		switch state.Phase {
		case appsv1alpha1.ContainerRecreateRequestSucceeded:
			completedCount++
			continue
		case appsv1alpha1.ContainerRecreateRequestFailed:
			completedCount++
			if crr.Spec.Strategy.FailurePolicy == appsv1alpha1.ContainerRecreateRequestFailurePolicyIgnore {
				continue
			}
			return c.completeCRRStatus(crr, "")
		case appsv1alpha1.ContainerRecreateRequestPending, appsv1alpha1.ContainerRecreateRequestRecreating:
		}

		if state.Phase == appsv1alpha1.ContainerRecreateRequestRecreating {
			state.IsKilled = true
			if crr.Spec.Strategy.OrderedRecreate {
				break
			}
			continue
		}

		kubeContainerStatus := podStatus.FindContainerStatusByName(state.Name)
		if kubeContainerStatus == nil {
			break
		}
        
		// 从pod状态中获取容器id，调用cri停止对应容器
		msg := fmt.Sprintf("Stopping container %s by ContainerRecreateRequest %s", state.Name, crr.Name)
		err := runtimeManager.KillContainer(pod, kubeContainerStatus.ID, state.Name, msg, nil)
		if err != nil {
			klog.ErrorS(err, "Failed to kill container in Pod for CRR", "containerName", state.Name, "podNamespace", pod.Namespace, "podName", pod.Name, "crrNamespace", crr.Namespace, "crrName", crr.Name)
			state.Phase = appsv1alpha1.ContainerRecreateRequestFailed
			state.Message = fmt.Sprintf("kill container error: %v", err)
			if crr.Spec.Strategy.FailurePolicy == appsv1alpha1.ContainerRecreateRequestFailurePolicyIgnore {
				continue
			}
			return c.patchCRRContainerRecreateStates(crr, newCRRContainerRecreateStates)
		}
		state.IsKilled = true
		state.Phase = appsv1alpha1.ContainerRecreateRequestRecreating
		break
	}
	
    //  更新CCR状态
	if !reflect.DeepEqual(crr.Status.ContainerRecreateStates, newCRRContainerRecreateStates) {
		return c.patchCRRContainerRecreateStates(crr, newCRRContainerRecreateStates)
	}

	// check if all containers have completed
	if completedCount == len(newCRRContainerRecreateStates) {
		return c.completeCRRStatus(crr, "")
	}

	if crr.Spec.Strategy != nil && crr.Spec.Strategy.MinStartedSeconds > 0 {
		c.queue.AddAfter(objectKey(crr), time.Duration(crr.Spec.Strategy.MinStartedSeconds)*time.Second)
	}
	return nil
}
```
#### SidecarSet

SidecarSet 是 OpenKruise 的一个 CRD，它支持通过 admission webhook 来自动为集群中创建的符合条件的 Pod 注入 sidecar 容器。SidecarSet 将 sidecar 容器的定义和生命周期与业务容器解耦。
它主要用于管理无状态的 sidecar 容器，比如监控、日志等 agent。

```go
// https://github.com/openkruise/kruise/blob/6968bd8972ea176a584b676f4cd25379169e9389/pkg/util/inplaceupdate/inplace_update.go

// 原地升级接口
type Interface interface {
	CanUpdateInPlace(oldRevision, newRevision *apps.ControllerRevision, opts *UpdateOptions) bool
	Update(pod *v1.Pod, oldRevision, newRevision *apps.ControllerRevision, opts *UpdateOptions) UpdateResult
	Refresh(pod *v1.Pod, opts *UpdateOptions) RefreshResult
}
```

具体实现
```go
func (c *realControl) CanUpdateInPlace(oldRevision, newRevision *apps.ControllerRevision, opts *UpdateOptions) bool {
	// 默认选项
	opts = SetOptionsDefaults(opts)
	// 如果不为nil 则可原地升级
	return opts.CalculateSpec(oldRevision, newRevision, opts) != nil
}


func SetOptionsDefaults(opts *UpdateOptions) *UpdateOptions {
	if opts == nil {
		opts = &UpdateOptions{}
	}

	if opts.CalculateSpec == nil {   // 计算更新的字段, 也用于判断是否可以原地升级
		opts.CalculateSpec = defaultCalculateInPlaceUpdateSpec
	}

	if opts.PatchSpecToPod == nil {  // 更新字段
		opts.PatchSpecToPod = defaultPatchUpdateSpecToPod
	}

	if opts.CheckPodUpdateCompleted == nil {  // 检查更新状态
		opts.CheckPodUpdateCompleted = DefaultCheckInPlaceUpdateCompleted
	}

	if opts.CheckContainersUpdateCompleted == nil {   // 检查容器更新状态
		opts.CheckContainersUpdateCompleted = defaultCheckContainersInPlaceUpdateCompleted
	}

	if opts.CheckPodNeedsBeUnready == nil {
		opts.CheckPodNeedsBeUnready = defaultCheckPodNeedsBeUnready
	}

	return opts
}
```

```go
// 默认CalculateSpec函数, 这里体现出只支持label、annotation、镜像的更新的原地升级
func defaultCalculateInPlaceUpdateSpec(oldRevision, newRevision *apps.ControllerRevision, opts *UpdateOptions) *UpdateSpec {
	if oldRevision == nil || newRevision == nil {
		return nil
	}
	opts = SetOptionsDefaults(opts)

	patches, err := jsonpatch.CreatePatch(oldRevision.Data.Raw, newRevision.Data.Raw)
	if err != nil {
		return nil
	}

	// RecreatePodWhenChangeVCTInCloneSetGate enabled
	if utilfeature.DefaultFeatureGate.Enabled(features.RecreatePodWhenChangeVCTInCloneSetGate) {
		if !opts.IgnoreVolumeClaimTemplatesHashDiff {
			canInPlace := volumeclaimtemplate.CanVCTemplateInplaceUpdate(oldRevision, newRevision)
			if !canInPlace {
				return nil
			}
		}
	}

	oldTemp, err := GetTemplateFromRevision(oldRevision)
	if err != nil {
		return nil
	}
	newTemp, err := GetTemplateFromRevision(newRevision)
	if err != nil {
		return nil
	}

	updateSpec := &UpdateSpec{
		Revision:             newRevision.Name,
		ContainerImages:      make(map[string]string),
		ContainerResources:   make(map[string]v1.ResourceRequirements),
		ContainerRefMetadata: make(map[string]metav1.ObjectMeta),
		GraceSeconds:         opts.GracePeriodSeconds,
	}
	if opts.GetRevision != nil {
		updateSpec.Revision = opts.GetRevision(newRevision)
	}

	// all patches for podSpec can just update images in pod spec
	var metadataPatches []jsonpatch.Operation
	for _, op := range patches {
		op.Path = strings.Replace(op.Path, "/spec/template", "", 1)

		if !strings.HasPrefix(op.Path, "/spec/") {
			if strings.HasPrefix(op.Path, "/metadata/") {
				metadataPatches = append(metadataPatches, op)
				continue
			}
			return nil
		}

		if op.Operation != "replace" {
			return nil
		}
		if containerImagePatchRexp.MatchString(op.Path) {
			// for example: /spec/containers/0/image
			words := strings.Split(op.Path, "/")
			idx, _ := strconv.Atoi(words[3])
			if len(oldTemp.Spec.Containers) <= idx {
				return nil
			}
			updateSpec.ContainerImages[oldTemp.Spec.Containers[idx].Name] = op.Value.(string)
			continue
		}

		if utilfeature.DefaultFeatureGate.Enabled(features.InPlaceWorkloadVerticalScaling) &&
			containerResourcesPatchRexp.MatchString(op.Path) {
			err = verticalUpdateImpl.UpdateInplaceUpdateMetadata(&op, oldTemp, updateSpec)
			if err != nil {
				klog.InfoS("UpdateInplaceUpdateMetadata error", "err", err)
				return nil
			}
			continue
		}
		return nil
	}
	if utilfeature.DefaultFeatureGate.Enabled(features.InPlaceWorkloadVerticalScaling) &&
		len(updateSpec.ContainerResources) != 0 {
		// when container resources changes exist, we should check pod qos
		if changed := verticalUpdateImpl.IsPodQoSChanged(oldTemp, newTemp); changed {
			klog.InfoS("can not inplace update when qos changed")
			return nil
		}
	}

	if len(metadataPatches) > 0 {
		if utilfeature.DefaultFeatureGate.Enabled(features.InPlaceUpdateEnvFromMetadata) {
			// for example: /metadata/labels/my-label-key
			for _, op := range metadataPatches {
				if op.Operation != "replace" && op.Operation != "add" {
					continue
				}
				words := strings.SplitN(op.Path, "/", 4)
				if len(words) != 4 || (words[2] != "labels" && words[2] != "annotations") {
					continue
				}
				key := rfc6901Decoder.Replace(words[3])

				for i := range newTemp.Spec.Containers {
					c := &newTemp.Spec.Containers[i]
					objMeta := updateSpec.ContainerRefMetadata[c.Name]
					switch words[2] {
					case "labels":
						if !utilcontainermeta.IsContainerReferenceToMeta(c, "metadata.labels", key) {
							continue
						}
						if objMeta.Labels == nil {
							objMeta.Labels = make(map[string]string)
						}
						objMeta.Labels[key] = op.Value.(string)
						delete(oldTemp.ObjectMeta.Labels, key)
						delete(newTemp.ObjectMeta.Labels, key)

					case "annotations":
						if !utilcontainermeta.IsContainerReferenceToMeta(c, "metadata.annotations", key) {
							continue
						}
						if objMeta.Annotations == nil {
							objMeta.Annotations = make(map[string]string)
						}
						objMeta.Annotations[key] = op.Value.(string)
						delete(oldTemp.ObjectMeta.Annotations, key)
						delete(newTemp.ObjectMeta.Annotations, key)
					}

					updateSpec.ContainerRefMetadata[c.Name] = objMeta
					updateSpec.UpdateEnvFromMetadata = true
				}
			}
		}

		oldBytes, _ := json.Marshal(v1.Pod{ObjectMeta: oldTemp.ObjectMeta})
		newBytes, _ := json.Marshal(v1.Pod{ObjectMeta: newTemp.ObjectMeta})
		patchBytes, err := strategicpatch.CreateTwoWayMergePatch(oldBytes, newBytes, &v1.Pod{})
		if err != nil {
			return nil
		}
		updateSpec.MetaDataPatch = patchBytes
	}

	return updateSpec
}

```





## 参考

- [如何为 Kubernetes 实现原地升级](https://developer.aliyun.com/article/765421)
- [OpenKruise SidecarSet 源码浅析](https://juejin.cn/post/7208084427393515578#heading-26)
