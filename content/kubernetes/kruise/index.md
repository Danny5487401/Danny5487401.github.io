---
title: "Kruise"
date: 2025-08-18T21:29:19+08:00
summary: 注入过程,原地升级原理
categories:
  - kubernetes
---



## 基本知识

### v1.27.1 新特性 InPlacePodVerticalScaling(就地垂直伸缩）

InPlacePodVerticalScaling（就地垂直伸缩）是 Kubernetes 中v1.27.1的一个特性，它允许在不重启 Pod 的情况下动态调整 Pod 中容器的资源限制（Resource Limits）

传统上，在 Kubernetes 中更新 Pod 的资源限制需要重新创建 Pod，这会导致应用程序中断和服务不可用的情况。但是，通过使用 InPlacePodVerticalScaling，可以实现对 Pod 进行资源限制的动态更新，而无需重新创建 Pod。


## 注入过程

MutatingWebhookConfiguration 配置


```yaml
# 默认配置
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: kruise-mutating-webhook-configuration
# ...
webhooks:
- admissionReviewVersions:
  - v1
  - v1beta1
  clientConfig:
    caBundle: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURGRENDQWZ5Z0F3SUJBZ0lJTFNMdVVrUm1VWkl3RFFZSktvWklodmNOQVFFTEJRQXdHakVZTUJZR0ExVUUKQXhNUGQyVmlhRzl2YXkxalpYSjBMV05oTUI0WERUSTFNRGd5TXpFMU1EUTBNRm9YRFRNMU1EZ3lNVEUxTURRMApNRm93R2pFWU1CWUdBMVVFQXhNUGQyVmlhRzl2YXkxalpYSjBMV05oTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGCkFBT0NBUThBTUlJQkNnS0NBUUVBa2FONnN3YmNjRWx3YzdSTSsyZTJNUE5pTkpyNERtQnJsZFdudkVlRkdhT1IKWFJjWk1PbnFmVG1OREdHMmlmOXlRTWZLci9mejNvWUIrZTd4U2puN0F3elBnSm9iNUhHQ3B5Y3EyUjNJUjRWSwpaeFd4My9CdS9FMUpNT2tSU1l5bWcxaENvaFZjMjZxQWdDT01UTEF1MWxRejM5RXZ4Vkdobmo3QWVuUDVkS0xTCmVnbzIvQklEd1lBYTJYM3ljc1hHM1VNMlZuemZXSEVaUnZiTXJPMkd1MWVmemVmTTNwYlZtMGJHcHF2OWt4bUYKY0dCQithVHlMdUxiU1BWaHdqcjBOVk1LMEU5RzJFYjFJRXE2d0FHRTU2YTNuaFQrVmxoZVJwMFRlTWJvTnAvSwpOTkNjUnozM2xXMCtUeEhRdnExTy9qdDNjM3hmQjZubHNsNWFrQnY5cXdJREFRQUJvMTR3WERBT0JnTlZIUThCCkFmOEVCQU1DQXFRd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBZEJnTlZIUTRFRmdRVXdSWVFrbjdrNzB0WmYzNTAKdTZNak9PVFZFWFF3R2dZRFZSMFJCQk13RVlJUGQyVmlhRzl2YXkxalpYSjBMV05oTUEwR0NTcUdTSWIzRFFFQgpDd1VBQTRJQkFRQXhldkV0d0QrVy9HVWs2a2xwL2pRRGJlZzBBdjNscTlmVzlJNlUrb1VPYXNYQy93VnBEM0hGCks2WmhaTHplV2VCcHJrejBhN2pWc0tkRU5hNXZEUFBvemh1UUxmSm1LMEgyb29oZFlGb2lVc1JRUTAxKzRvWG8KWHRoNnEyYkxyQVEwbnhLSnhpWVlEOW1UM2ZudldmSGpCMmFUVFQ3cC9TRWlROFk4dksyeFhidCtOcGJ4c0ZUTgpUakhYVzA3RjlLMnY2RFVNQmpaT01qd2NNcjIvNlpEWEdRT3pTTXluVnloRTdZSU41WUZlWnFmVjl2RzRIaGptCk5JdDRpV0lJVVl0dTlnWi9FT3Y0WjQ1VzVINCtrWHNMUzVidzArNDFEOHZmaUpvdTVJLzh4aVgrNzIyMUF4RDcKZ3dKWUwxQmRZdWpNQStsbHEwZGN6L1lXeW9CZ0hPL28KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
    service:
      name: kruise-webhook-service
      namespace: kruise-system
      path: /mutate-pod
      port: 443
  failurePolicy: Fail
  matchPolicy: Equivalent
  name: mpod.kb.io
  namespaceSelector:
    matchExpressions:
    - key: control-plane
      operator: NotIn
      values:
      - openkruise
    - key: kubernetes.io/metadata.name
      operator: NotIn
      values:
      - kube-system
  objectSelector: {}
  reinvocationPolicy: Never
  # 创建 pod 的时候
  rules:
  - apiGroups:
    - ""
    apiVersions:
    - v1
    operations:
    - CREATE
    resources:
    - pods
    scope: '*'
  sideEffects: None
  timeoutSeconds: 30

# ....
- admissionReviewVersions:
    - v1
    - v1beta1
  clientConfig:
    caBundle: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURGRENDQWZ5Z0F3SUJBZ0lJTFNMdVVrUm1VWkl3RFFZSktvWklodmNOQVFFTEJRQXdHakVZTUJZR0ExVUUKQXhNUGQyVmlhRzl2YXkxalpYSjBMV05oTUI0WERUSTFNRGd5TXpFMU1EUTBNRm9YRFRNMU1EZ3lNVEUxTURRMApNRm93R2pFWU1CWUdBMVVFQXhNUGQyVmlhRzl2YXkxalpYSjBMV05oTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGCkFBT0NBUThBTUlJQkNnS0NBUUVBa2FONnN3YmNjRWx3YzdSTSsyZTJNUE5pTkpyNERtQnJsZFdudkVlRkdhT1IKWFJjWk1PbnFmVG1OREdHMmlmOXlRTWZLci9mejNvWUIrZTd4U2puN0F3elBnSm9iNUhHQ3B5Y3EyUjNJUjRWSwpaeFd4My9CdS9FMUpNT2tSU1l5bWcxaENvaFZjMjZxQWdDT01UTEF1MWxRejM5RXZ4Vkdobmo3QWVuUDVkS0xTCmVnbzIvQklEd1lBYTJYM3ljc1hHM1VNMlZuemZXSEVaUnZiTXJPMkd1MWVmemVmTTNwYlZtMGJHcHF2OWt4bUYKY0dCQithVHlMdUxiU1BWaHdqcjBOVk1LMEU5RzJFYjFJRXE2d0FHRTU2YTNuaFQrVmxoZVJwMFRlTWJvTnAvSwpOTkNjUnozM2xXMCtUeEhRdnExTy9qdDNjM3hmQjZubHNsNWFrQnY5cXdJREFRQUJvMTR3WERBT0JnTlZIUThCCkFmOEVCQU1DQXFRd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBZEJnTlZIUTRFRmdRVXdSWVFrbjdrNzB0WmYzNTAKdTZNak9PVFZFWFF3R2dZRFZSMFJCQk13RVlJUGQyVmlhRzl2YXkxalpYSjBMV05oTUEwR0NTcUdTSWIzRFFFQgpDd1VBQTRJQkFRQXhldkV0d0QrVy9HVWs2a2xwL2pRRGJlZzBBdjNscTlmVzlJNlUrb1VPYXNYQy93VnBEM0hGCks2WmhaTHplV2VCcHJrejBhN2pWc0tkRU5hNXZEUFBvemh1UUxmSm1LMEgyb29oZFlGb2lVc1JRUTAxKzRvWG8KWHRoNnEyYkxyQVEwbnhLSnhpWVlEOW1UM2ZudldmSGpCMmFUVFQ3cC9TRWlROFk4dksyeFhidCtOcGJ4c0ZUTgpUakhYVzA3RjlLMnY2RFVNQmpaT01qd2NNcjIvNlpEWEdRT3pTTXluVnloRTdZSU41WUZlWnFmVjl2RzRIaGptCk5JdDRpV0lJVVl0dTlnWi9FT3Y0WjQ1VzVINCtrWHNMUzVidzArNDFEOHZmaUpvdTVJLzh4aVgrNzIyMUF4RDcKZ3dKWUwxQmRZdWpNQStsbHEwZGN6L1lXeW9CZ0hPL28KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
    service:
      name: kruise-webhook-service
      namespace: kruise-system
      path: /mutate-apps-kruise-io-v1alpha1-sidecarset
      port: 443
  failurePolicy: Fail
  matchPolicy: Equivalent
  name: msidecarset.kb.io
  namespaceSelector: {}
  objectSelector: {}
  reinvocationPolicy: Never
  # 修改创建 sidecarsets 的时候
  rules:
    - apiGroups:
        - apps.kruise.io
      apiVersions:
        - v1alpha1
      operations:
        - CREATE
        - UPDATE
      resources:
        - sidecarsets
      scope: '*'
  sideEffects: None
  timeoutSeconds: 30
```

### pod 创建接口
```go
var (
	// 修改 pod 接口
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


### sidecarset webhook 

```go
var (
	// HandlerGetterMap contains admission webhook handlers
	HandlerGetterMap = map[string]types.HandlerGetter{
		"mutate-apps-kruise-io-v1alpha1-sidecarset": func(mgr manager.Manager) admission.Handler {
			return &SidecarSetCreateHandler{Decoder: admission.NewDecoder(mgr.GetScheme())}
		},
	}
)
```

```go
func (h *SidecarSetCreateHandler) Handle(ctx context.Context, req admission.Request) admission.Response {
	obj := &appsv1alpha1.SidecarSet{}

	err := h.Decoder.Decode(req, obj)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	var copy runtime.Object = obj.DeepCopy()
	switch req.AdmissionRequest.Operation {
	case admissionv1.Create, admissionv1.Update:
		defaults.SetDefaultsSidecarSet(obj)
		// 设置 hash 信息
		if err := setHashSidecarSet(obj); err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}
	}
	klog.V(4).InfoS("sidecarset after mutating", "object", util.DumpJSON(obj))
	if reflect.DeepEqual(obj, copy) {
		return admission.Allowed("")
	}
	marshalled, err := json.Marshal(obj)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(req.AdmissionRequest.Object.Raw, marshalled)
}


func setHashSidecarSet(sidecarset *appsv1alpha1.SidecarSet) error {
	if sidecarset.Annotations == nil {
		sidecarset.Annotations = make(map[string]string)
	}

	hash, err := sidecarcontrol.SidecarSetHash(sidecarset)
	if err != nil {
		return err
	}
	sidecarset.Annotations[sidecarcontrol.SidecarSetHashAnnotation] = hash

	hash, err = sidecarcontrol.SidecarSetHashWithoutImage(sidecarset)
	if err != nil {
		return err
	}
	sidecarset.Annotations[sidecarcontrol.SidecarSetHashWithoutImageAnnotation] = hash

	return nil
}
```


## 原地升级
https://openkruise.io/zh/docs/core-concepts/inplace-update

{{<figure src="./in-place_update_process.png#center" width=800px >}}

目前支持原地升级的 Workload：

- CloneSet: 高效管理无状态应用的能力，它可以对标原生的 Deployment.提供了很多增强功能: 支持 PVC 模板,多了 指定 Pod 缩容,
- Advanced StatefulSet
- Advanced DaemonSet
- SidecarSet

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

这个功能，其实就是针对单个 Pod 的原地升级的核心原理。


```go
func (m *kubeGenericRuntimeManager) SyncPod(ctx context.Context, pod *v1.Pod, podStatus *kubecontainer.PodStatus, pullSecrets []v1.Secret, backOff *flowcontrol.Backoff) (result kubecontainer.PodSyncResult) {
	// Step 1: 计算 sandbox and container 变化.
	podContainerChanges := m.computePodActions(ctx, pod, podStatus)
	klog.V(3).InfoS("computePodActions got for pod", "podActions", podContainerChanges, "pod", klog.KObj(pod))
	if podContainerChanges.CreateSandbox {
		ref, err := ref.GetReference(legacyscheme.Scheme, pod)
		if err != nil {
			klog.ErrorS(err, "Couldn't make a ref to pod", "pod", klog.KObj(pod))
		}
		if podContainerChanges.SandboxID != "" {
			m.recorder.Eventf(ref, v1.EventTypeNormal, events.SandboxChanged, "Pod sandbox changed, it will be killed and re-created.")
		} else {
			klog.V(4).InfoS("SyncPod received new pod, will create a sandbox for it", "pod", klog.KObj(pod))
		}
	}

	// Step 2: 杀掉 pod 如果 sandbox 变化
	if podContainerChanges.KillPod {
		if podContainerChanges.CreateSandbox {
			klog.V(4).InfoS("Stopping PodSandbox for pod, will start new one", "pod", klog.KObj(pod))
		} else {
			klog.V(4).InfoS("Stopping PodSandbox for pod, because all other containers are dead", "pod", klog.KObj(pod))
		}

		killResult := m.killPodWithSyncResult(ctx, pod, kubecontainer.ConvertPodStatusToRunningPod(m.runtimeName, podStatus), nil)
		result.AddPodSyncResult(killResult)
		if killResult.Error() != nil {
			klog.ErrorS(killResult.Error(), "killPodWithSyncResult failed")
			return
		}

		if podContainerChanges.CreateSandbox {
			m.purgeInitContainers(ctx, pod, podStatus)
		}
	} else {
		// Step 3: 杀掉不需要的 容器
		for containerID, containerInfo := range podContainerChanges.ContainersToKill {
			klog.V(3).InfoS("Killing unwanted container for pod", "containerName", containerInfo.name, "containerID", containerID, "pod", klog.KObj(pod))
			killContainerResult := kubecontainer.NewSyncResult(kubecontainer.KillContainer, containerInfo.name)
			result.AddSyncResult(killContainerResult)
			if err := m.killContainer(ctx, pod, containerID, containerInfo.name, containerInfo.message, containerInfo.reason, nil); err != nil {
				killContainerResult.Fail(kubecontainer.ErrKillContainer, err.Error())
				klog.ErrorS(err, "killContainer for pod failed", "containerName", containerInfo.name, "containerID", containerID, "pod", klog.KObj(pod))
				return
			}
		}
	}

	// ....
 }
```


```go

// https://github.com/kubernetes/kubernetes/blob/9ddf1a02bd436e8ce16fb71ab832f4e0eca57a3a/pkg/kubelet/kuberuntime/kuberuntime_manager.go

func (m *kubeGenericRuntimeManager) computePodActions(ctx context.Context, pod *v1.Pod, podStatus *kubecontainer.PodStatus) podActions {
	klog.V(5).InfoS("Syncing Pod", "pod", klog.KObj(pod))

	createPodSandbox, attempt, sandboxID := runtimeutil.PodSandboxChanged(pod, podStatus)
	// pod 需改变的信息
	changes := podActions{
		KillPod:           createPodSandbox,
		CreateSandbox:     createPodSandbox,
		SandboxID:         sandboxID,
		Attempt:           attempt,
		ContainersToStart: []int{},
		ContainersToKill:  make(map[kubecontainer.ContainerID]containerToKillInfo),
	}

    // ..
	// 检查 container 状态
	for idx, container := range pod.Spec.Containers {
		containerStatus := podStatus.FindContainerStatusByName(container.Name)

        // ...
		
		// The container is running, but kill the container if any of the following condition is met.
		var message string
		var reason containerKillReason
		restart := shouldRestartOnFailure(pod)
		// 容器变化判断
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

		// 需要删除的容器
		changes.ContainersToKill[containerStatus.ID] = containerToKillInfo{
			name:      containerStatus.Name,
			container: &pod.Spec.Containers[idx],
			message:   message,
			reason:    reason,
		}
		klog.V(2).InfoS("Message for Container of pod", "containerName", container.Name, "containerStatusID", containerStatus.ID, "pod", klog.KObj(pod), "containerMessage", message)
	}

	if keepCount == 0 && len(changes.ContainersToStart) == 0 {
		// 需要杀掉 pod 
		changes.KillPod = true
	}

	return changes
}


// container 变化判断
func containerChanged(container *v1.Container, containerStatus *kubecontainer.Status) (uint64, uint64, bool) {
	// 计算 hash 
	expectedHash := kubecontainer.HashContainer(container)
	return expectedHash, containerStatus.Hash, containerStatus.Hash != expectedHash
}
```

```go
// 对容器进行 hash 计算
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



删除容器

```go
func (m *kubeGenericRuntimeManager) killContainer(ctx context.Context, pod *v1.Pod, containerID kubecontainer.ContainerID, containerName string, message string, reason containerKillReason, gracePeriodOverride *int64) error {
	var containerSpec *v1.Container
	if pod != nil {
		if containerSpec = kubecontainer.GetContainerSpec(pod, containerName); containerSpec == nil {
			return fmt.Errorf("failed to get containerSpec %q (id=%q) in pod %q when killing container for reason %q",
				containerName, containerID.String(), format.Pod(pod), message)
		}
	} else {
		// Restore necessary information if one of the specs is nil.
		restoredPod, restoredContainer, err := m.restoreSpecsFromContainerLabels(ctx, containerID)
		if err != nil {
			return err
		}
		pod, containerSpec = restoredPod, restoredContainer
	}

	// From this point, pod and container must be non-nil.
	gracePeriod := setTerminationGracePeriod(pod, containerSpec, containerName, containerID, reason)

	if len(message) == 0 {
		message = fmt.Sprintf("Stopping container %s", containerSpec.Name)
	}
	m.recordContainerEvent(pod, containerSpec, containerID.ID, v1.EventTypeNormal, events.KillingContainer, message)

	// Run the pre-stop lifecycle hooks if applicable and if there is enough time to run it
	if containerSpec.Lifecycle != nil && containerSpec.Lifecycle.PreStop != nil && gracePeriod > 0 {
		gracePeriod = gracePeriod - m.executePreStopHook(ctx, pod, containerID, containerSpec, gracePeriod)
	}
	// always give containers a minimal shutdown window to avoid unnecessary SIGKILLs
	if gracePeriod < minimumGracePeriodInSeconds {
		gracePeriod = minimumGracePeriodInSeconds
	}
	if gracePeriodOverride != nil {
		gracePeriod = *gracePeriodOverride
		klog.V(3).InfoS("Killing container with a grace period override", "pod", klog.KObj(pod), "podUID", pod.UID,
			"containerName", containerName, "containerID", containerID.String(), "gracePeriod", gracePeriod)
	}

	klog.V(2).InfoS("Killing container with a grace period", "pod", klog.KObj(pod), "podUID", pod.UID,
		"containerName", containerName, "containerID", containerID.String(), "gracePeriod", gracePeriod)

	err := m.runtimeService.StopContainer(ctx, containerID.ID, gracePeriod)
	if err != nil && !crierror.IsNotFound(err) {
		klog.ErrorS(err, "Container termination failed with gracePeriod", "pod", klog.KObj(pod), "podUID", pod.UID,
			"containerName", containerName, "containerID", containerID.String(), "gracePeriod", gracePeriod)
		return err
	}
	klog.V(3).InfoS("Container exited normally", "pod", klog.KObj(pod), "podUID", pod.UID,
		"containerName", containerName, "containerID", containerID.String())

	return nil
}
```

### kruise  in-place 原地升级原理

#### ContainerRecreateRequest 重启/重建存量 Pod

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
https://openkruise.io/zh/docs/user-manuals/sidecarset#sidecar%E7%83%AD%E5%8D%87%E7%BA%A7%E7%89%B9%E6%80%A7

SidecarSet 是 OpenKruise 的一个 CRD，它支持通过 admission webhook 来自动为集群中创建的符合条件的 Pod 注入 sidecar 容器。SidecarSet 将 sidecar 容器的定义和生命周期与业务容器解耦。
它主要用于管理无状态的 sidecar 容器，比如监控、日志等 agent。

协调
```go
func (r *ReconcileSidecarSet) Reconcile(_ context.Context, request reconcile.Request) (reconcile.Result, error) {
	// Fetch the SidecarSet instance
	sidecarSet := &appsv1alpha1.SidecarSet{}
	err := r.Get(context.TODO(), request.NamespacedName, sidecarSet)
    // ..
	return r.processor.UpdateSidecarSet(sidecarSet)
}

```

原地升级 in-place 和 热升级 Hot Upgrade

热升级特性总共包含以下两个过程：

1. Pod创建时，注入热升级容器
2. 原地升级时，完成热升级流程
   - Upgrade: 将empty容器升级为当前最新的sidecar容器，例如：envoy-2.Image = envoy:1.17.0
   - Migration: lifecycle.postStart完成热升级流程中的状态迁移，当迁移完成后退出。(注意:PostStartHook在迁移过程中必须阻塞，迁移完成后退出。)
   - Reset: 状态迁移完成后，热升级流程将设置envoy-1容器为empty镜像，例如：envoy-1.Image = empty:1.0


```go
func (p *Processor) UpdateSidecarSet(sidecarSet *appsv1alpha1.SidecarSet) (reconcile.Result, error) {
	control := sidecarcontrol.New(sidecarSet)
	
	// 判断活跃情况
	if !control.IsActiveSidecarSet() {
		return reconcile.Result{}, nil
	}
	// 1. 过滤符合条件的pod
	pods, err := p.getMatchingPods(sidecarSet)
	if err != nil {
		klog.ErrorS(err, "SidecarSet get matching pods error", "sidecarSet", klog.KObj(sidecarSet))
		return reconcile.Result{}, err
	}

	// register new revision if this sidecarSet is the latest;
	// return the latest revision that corresponds to this sidecarSet.
	latestRevision, collisionCount, err := p.registerLatestRevision(sidecarSet, pods)
	if latestRevision == nil {
		klog.ErrorS(err, "SidecarSet register the latest revision error", "sidecarSet", klog.KObj(sidecarSet))
		return reconcile.Result{}, err
	}

	// 2. calculate SidecarSet status based on pod and revision information
	status := calculateStatus(control, pods, latestRevision, collisionCount)
	//update sidecarSet status in store
	if err := p.updateSidecarSetStatus(sidecarSet, status); err != nil {
		return reconcile.Result{}, err
	}
	sidecarSet.Status = *status

	// in case of informer cache latency
	for _, pod := range pods {
		sidecarcontrol.UpdateExpectations.ObserveUpdated(sidecarSet.Name, sidecarcontrol.GetSidecarSetRevision(sidecarSet), pod)
	}
	allUpdated, _, inflightPods := sidecarcontrol.UpdateExpectations.SatisfiedExpectations(sidecarSet.Name, sidecarcontrol.GetSidecarSetRevision(sidecarSet))
	if !allUpdated {
		klog.V(3).InfoS("Sidecarset matched pods has some update in flight, will sync later", "sidecarSet", klog.KObj(sidecarSet), "pods", inflightPods)
		return reconcile.Result{RequeueAfter: time.Second}, nil
	}

	// 3. If sidecar container hot upgrade complete, then set the other one(empty sidecar container) image to HotUpgradeEmptyImage
	if isSidecarSetHasHotUpgradeContainer(sidecarSet) {
		var podsInHotUpgrading []*corev1.Pod
		for _, pod := range pods {
			// flip other hot sidecar container to empty, in the following:
			// 1. the empty sidecar container image isn't equal HotUpgradeEmptyImage
			// 2. all containers with exception of empty sidecar containers is updated and consistent
			// 3. all containers with exception of empty sidecar containers is ready

			// don't contain sidecar empty containers
			sidecarContainers := sidecarcontrol.GetSidecarContainersInPod(sidecarSet)
			for _, sidecarContainer := range sidecarSet.Spec.Containers {
				if sidecarcontrol.IsHotUpgradeContainer(&sidecarContainer) { // 如果策略是 HotUpgrade
					_, emptyContainer := sidecarcontrol.GetPodHotUpgradeContainers(sidecarContainer.Name, pod)
					sidecarContainers.Delete(emptyContainer)
				}
			}
			if isPodSidecarInHotUpgrading(sidecarSet, pod) && control.IsPodStateConsistent(pod, sidecarContainers) &&
				isHotUpgradingReady(sidecarSet, pod) {
				podsInHotUpgrading = append(podsInHotUpgrading, pod)
			}
		}
		if err := p.flipHotUpgradingContainers(control, podsInHotUpgrading); err != nil {
			return reconcile.Result{}, err
		}
	}

	// 4. SidecarSet upgrade strategy type is NotUpdate
	if isSidecarSetNotUpdate(sidecarSet) {
		return reconcile.Result{}, nil
	}

	// 5. sidecarset already updates all matched pods, then return
	if isSidecarSetUpdateFinish(status) {
		klog.V(3).InfoS("SidecarSet matched pods were latest, and don't need update", "sidecarSet", klog.KObj(sidecarSet), "matchedPodCount", len(pods))
		return reconcile.Result{}, nil
	}

	// 6. Paused indicates that the SidecarSet is paused to update matched pods
	if sidecarSet.Spec.UpdateStrategy.Paused {
		klog.V(3).InfoS("SidecarSet was paused", "sidecarSet", klog.KObj(sidecarSet))
		return reconcile.Result{}, nil
	}

	// 7. upgrade pod sidecar
	if err := p.updatePods(control, pods); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}
```


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
		// 开启元数据修改特性
		if utilfeature.DefaultFeatureGate.Enabled(features.InPlaceUpdateEnvFromMetadata) {
			// for example: /metadata/labels/my-label-key
            // ... 
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
