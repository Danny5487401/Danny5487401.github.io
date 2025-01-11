---
title: "Csi(container-storage-interface)架构和原理"
date: 2025-01-11T10:51:59+08:00
summary: "csi 部署方式及源码实现"
categories:
  - kubernetes
authors:
  - Danny
tags:
  - k8s
  - csi
  - 源码
---


CSI 是由来自 Kubernetes、Mesos、 Cloud Foundry 等社区成员联合制定的一个行业标准接口规范，旨在将任意存储系统暴露给容器化应用程序

CSI 的 cloud providers 有两种类型，一种为 in-tree 类型，一种为 out-of-tree 类型.

```go
var (
	inTreePlugins = map[string]plugins.InTreePlugin{
		plugins.GCEPDDriverName:     plugins.NewGCEPersistentDiskCSITranslator(),
		plugins.AWSEBSDriverName:    plugins.NewAWSElasticBlockStoreCSITranslator(),
		plugins.CinderDriverName:    plugins.NewOpenStackCinderCSITranslator(),
		plugins.AzureDiskDriverName: plugins.NewAzureDiskCSITranslator(),
		plugins.AzureFileDriverName: plugins.NewAzureFileCSITranslator(),
		plugins.VSphereDriverName:   plugins.NewvSphereCSITranslator(),
		plugins.PortworxDriverName:  plugins.NewPortworxCSITranslator(),
		plugins.RBDDriverName:       plugins.NewRBDCSITranslator(),
	}
)
```



## 存储架构和csi架构




- PV Controller：负责 PV/PVC 的绑定，并根据需求进行数据卷的 Provision/Delete 操作
- AD Controller：负责存储设备的 Attach/Detach 操作，将设备挂载到目标节点
- Volume Manager：管理卷的 Mount/Unmount 操作、卷设备的格式化等操作
- Volume Plugin：扩展各种存储类型的卷管理能力，实现第三方存储的各种操作能力和 Kubernetes 存储系统结合



{{<figure src="./csi_with_external_plugin.png#center" width=800px >}}


{{<figure src="./csi_deploy_structure.png#center" width=800px >}}

```yaml
# lvm 部署参考
# https://github.com/openebs/lvm-localpv/blob/v1.6.1/deploy/yamls/lvm-driver.yaml
---

# CSIDriver 用于定义和配置 CSI 驱动程序的属性和行为，是集群范围的资源对象
apiVersion: storage.k8s.io/v1
kind: CSIDriver
metadata:
  name: local.csi.openebs.io
spec:
  # do not require volumeattachment
  attachRequired: false
  podInfoOnMount: true
  storageCapacity: true

---

kind: Deployment
apiVersion: apps/v1
metadata:
  name: openebs-lvm-controller
  namespace: kube-system
  # ...
spec:
  replicas: 1
  template:
    # ...
    spec:
      # ...
      containers:
        # sidecar 组件
        - name: csi-resizer
          image: registry.k8s.io/sig-storage/csi-resizer:v1.8.0
          # ...
        - name: csi-snapshotter
          image: registry.k8s.io/sig-storage/csi-snapshotter:v6.2.2
          # ...
        - name: snapshot-controller
          image: registry.k8s.io/sig-storage/snapshot-controller:v6.2.2
          # ...
        - name: csi-provisioner
          image: registry.k8s.io/sig-storage/csi-provisioner:v3.5.0
          # ...
        - name: openebs-lvm-plugin
          image: openebs/lvm-driver:ci
          # ...

---

kind: DaemonSet
apiVersion: apps/v1
metadata:
  name: openebs-lvm-node
  namespace: kube-system
  labels:
    openebs.io/component-name: openebs-lvm-node
    openebs.io/version: ci
spec:
  # ...
  template:
    spec:
      containers:
        - name: csi-node-driver-registrar
          image: registry.k8s.io/sig-storage/csi-node-driver-registrar:v2.8.0
          # ..
        - name: openebs-lvm-plugin
          image: openebs/lvm-driver:ci
          # ...

```




### PV controller

pv 的状态
```go
type PersistentVolumePhase string

const (
	VolumePending PersistentVolumePhase = "Pending"
	VolumeAvailable PersistentVolumePhase = "Available"
	VolumeBound PersistentVolumePhase = "Bound"
	VolumeReleased PersistentVolumePhase = "Released"
	VolumeFailed PersistentVolumePhase = "Failed"
)

```

```go
func NewControllerInitializers(loopMode ControllerLoopMode) map[string]InitFunc {
	// ...
	// 注册初始化函数
    register("persistentvolume-binder", startPersistentVolumeBinderController)
}
```

```go
func startPersistentVolumeBinderController(ctx context.Context, controllerContext ControllerContext) (controller.Interface, bool, error) {
	logger := klog.FromContext(ctx)
	plugins, err := ProbeControllerVolumePlugins(logger, controllerContext.Cloud, controllerContext.ComponentConfig.PersistentVolumeBinderController.VolumeConfiguration)
    // ...
	params := persistentvolumecontroller.ControllerParameters{
		KubeClient:                controllerContext.ClientBuilder.ClientOrDie("persistent-volume-binder"),
		SyncPeriod:                controllerContext.ComponentConfig.PersistentVolumeBinderController.PVClaimBinderSyncPeriod.Duration,
		VolumePlugins:             plugins,
		Cloud:                     controllerContext.Cloud,
		ClusterName:               controllerContext.ComponentConfig.KubeCloudShared.ClusterName,
		// 以下是监听的资源,pv,pvc,storageclass,pods,nodes
		VolumeInformer:            controllerContext.InformerFactory.Core().V1().PersistentVolumes(),
		ClaimInformer:             controllerContext.InformerFactory.Core().V1().PersistentVolumeClaims(),
		ClassInformer:             controllerContext.InformerFactory.Storage().V1().StorageClasses(),
		PodInformer:               controllerContext.InformerFactory.Core().V1().Pods(),
		NodeInformer:              controllerContext.InformerFactory.Core().V1().Nodes(),
		EnableDynamicProvisioning: controllerContext.ComponentConfig.PersistentVolumeBinderController.VolumeConfiguration.EnableDynamicProvisioning,
		FilteredDialOptions:       filteredDialOptions,
	}
	volumeController, volumeControllerErr := persistentvolumecontroller.NewController(ctx, params)
	if volumeControllerErr != nil {
		return nil, true, fmt.Errorf("failed to construct persistentvolume controller: %v", volumeControllerErr)
	}
	// 启动
	go volumeController.Run(ctx)
	return nil, true, nil
}

```

```go
func (ctrl *PersistentVolumeController) Run(ctx context.Context) {
    // ...

	go wait.Until(func() { ctrl.resync(ctx) }, ctrl.resyncPeriod, ctx.Done())
	// volume 管理
	go wait.UntilWithContext(ctx, ctrl.volumeWorker, time.Second)
	// claim 管理
	go wait.UntilWithContext(ctx, ctrl.claimWorker, time.Second)

    // ..

	<-ctx.Done()
}
```


#### 默认插件
```go
func ProbeControllerVolumePlugins(logger klog.Logger, cloud cloudprovider.Interface, config persistentvolumeconfig.VolumeConfiguration) ([]volume.VolumePlugin, error) {
	allPlugins := []volume.VolumePlugin{}

    // ...
	allPlugins = append(allPlugins, hostpath.ProbeVolumePlugins(hostPathConfig)...) // host-path 插件

    // ...
	allPlugins = append(allPlugins, nfs.ProbeVolumePlugins(nfsConfig)...) // nfs 插件
 
    // ..

	allPlugins = append(allPlugins, local.ProbeVolumePlugins()...)  // local-volume 插件
	allPlugins = append(allPlugins, csi.ProbeVolumePlugins()...) // csi 插件

	return allPlugins, nil
}
```

- hostPath类型则是映射node文件系统中的文件或者目录到pod里
- Local volume 允许用户通过标准PVC接口以简单且可移植的方式访问node节点的本地存储。


## 第三方插件

第三方存储提供方（即 SP，Storage Provider）需要实现 Controller 和 Node 两个插件.

CSI 插件与 kubelet 以及 k8s 外部组件是通过 Unix Domain Socket gRPC 来进行交互调用的。CSI 定义了三套 RPC 接口，SP 需要实现这三组接口，以便与 k8s 外部组件进行通信。

三组接口分别是：CSI Identity、CSI Controller 和 CSI Node

### CSI Controller
主要以 StatefulSet或Deployment的pod 的形式运行在集群里面，主要负责 provision 和 attach 工作.

用于实现创建/删除 volume、volume 快照、volume 扩缩容等功能
```protobuf
// https://github.com/container-storage-interface/spec/blob/v1.11.0/csi.proto

service Controller {
  rpc CreateVolume (CreateVolumeRequest)
    returns (CreateVolumeResponse) {}

  rpc DeleteVolume (DeleteVolumeRequest)
    returns (DeleteVolumeResponse) {}

  rpc ControllerPublishVolume (ControllerPublishVolumeRequest)
    returns (ControllerPublishVolumeResponse) {}

  rpc ControllerUnpublishVolume (ControllerUnpublishVolumeRequest)
    returns (ControllerUnpublishVolumeResponse) {}

  rpc ValidateVolumeCapabilities (ValidateVolumeCapabilitiesRequest)
    returns (ValidateVolumeCapabilitiesResponse) {}

  rpc ListVolumes (ListVolumesRequest)
    returns (ListVolumesResponse) {}

  rpc GetCapacity (GetCapacityRequest)
    returns (GetCapacityResponse) {}

  rpc ControllerGetCapabilities (ControllerGetCapabilitiesRequest)
    returns (ControllerGetCapabilitiesResponse) {}

  rpc CreateSnapshot (CreateSnapshotRequest)
    returns (CreateSnapshotResponse) {}

  rpc DeleteSnapshot (DeleteSnapshotRequest)
    returns (DeleteSnapshotResponse) {}

  rpc ListSnapshots (ListSnapshotsRequest)
    returns (ListSnapshotsResponse) {}

  rpc ControllerExpandVolume (ControllerExpandVolumeRequest)
    returns (ControllerExpandVolumeResponse) {}

  rpc ControllerGetVolume (ControllerGetVolumeRequest)
    returns (ControllerGetVolumeResponse) {
        option (alpha_method) = true;
    }

  rpc ControllerModifyVolume (ControllerModifyVolumeRequest)
    returns (ControllerModifyVolumeResponse) {
        option (alpha_method) = true;
    }
}
```

- CreateVolume/DeleteVolume 配合 external-provisioner 实现创建/删除 volume 的功能；
- ControllerPublishVolume/ControllerUnpublishVolume 配合 external-attacher 实现 volume 的 attach/detach 功能等

### CSI Node & CSI Identity
```protobuf
service Node {
  rpc NodeStageVolume (NodeStageVolumeRequest)
    returns (NodeStageVolumeResponse) {}

  rpc NodeUnstageVolume (NodeUnstageVolumeRequest)
    returns (NodeUnstageVolumeResponse) {}

  rpc NodePublishVolume (NodePublishVolumeRequest)
    returns (NodePublishVolumeResponse) {}

  rpc NodeUnpublishVolume (NodeUnpublishVolumeRequest)
    returns (NodeUnpublishVolumeResponse) {}

  rpc NodeGetVolumeStats (NodeGetVolumeStatsRequest)
    returns (NodeGetVolumeStatsResponse) {}


  rpc NodeExpandVolume(NodeExpandVolumeRequest)
    returns (NodeExpandVolumeResponse) {}


  rpc NodeGetCapabilities (NodeGetCapabilitiesRequest)
    returns (NodeGetCapabilitiesResponse) {}

  rpc NodeGetInfo (NodeGetInfoRequest)
    returns (NodeGetInfoResponse) {}
}
```
- NodeStageVolume 用来实现多个 pod 共享一个 volume 的功能,将 volume 挂载到一个临时目录
- NodePublishVolume 将其挂载到 pod 中


```protobuf
service Identity {
  rpc GetPluginInfo(GetPluginInfoRequest)
    returns (GetPluginInfoResponse) {}

  rpc GetPluginCapabilities(GetPluginCapabilitiesRequest)
    returns (GetPluginCapabilitiesResponse) {}

  rpc Probe (ProbeRequest)
    returns (ProbeResponse) {}
}
```
CSI Identity 是用来告诉 Controller，我现在是哪一个 CSI 插件，它实现的接口会被 node-driver-registrar 调用给 Controller 去注册自己

## SideCar 组件

out-of-tree 类型的插件主要是通过 gRPC 接口跟 k8s 组件交互，并且 k8s 提供了大量的 SideCar 组件来配合 CSI 插件实现丰富的功能

- github.com/kubernetes-csi/external-provisioner:用于 watch Kubernetes 的 PVC 对象并调用 CSI 的 CreateVolume 和 DeleteVolume 操作
- github.com/kubernetes-csi/external-attacher: 用于 Attach/Detach 阶段，通过 watch Kubernetes 的 VolumeAttachment 对象并调用 CSI 的
- github.com/kubernetes-csi/external-snapshotter
- github.com/kubernetes-csi/external-resizer
- github.com/kubernetes-csi/node-driver-registrar:用于将插件注册到 kubelet 的 sidecar 容器，并将驱动程序自定义的 NodeId 添加到节点的 Annotations 上，通过与 CSI 上面的 Identity 服务进行通信调用 CSI 的 GetNodeId 方法来完成该操作
```go
// kubelet 接口
type RegistrationServer interface {
	GetInfo(context.Context, *InfoRequest) (*PluginInfo, error)
	NotifyRegistrationStatus(context.Context, *RegistrationStatus) (*RegistrationStatusResponse, error)
}

```
```go
func (e registrationServer) GetInfo(ctx context.Context, req *registerapi.InfoRequest) (*registerapi.PluginInfo, error) {
    // ..

	return &registerapi.PluginInfo{
		Type:              registerapi.CSIPlugin,
		Name:              e.driverName,
		Endpoint:          e.endpoint,
		SupportedVersions: e.version,
	}, nil
}
```
将 CSI driver 的信息通过 kubelet 的插件注册机制在对应节点的 kubelet 上进行注册


## 工作流程


### Provision 创盘

{{<figure src="./provision_process.png#center" width=800px >}}

1. 集群管理员创建 StorageClass 资源，该 StorageClass 中包含 CSI 插件名称；

2. 用户创建 PVC 资源，PVC 指定存储大小及 StorageClass；
```go
func (ctrl *PersistentVolumeController) setClaimProvisioner(ctx context.Context, claim *v1.PersistentVolumeClaim, provisionerName string) (*v1.PersistentVolumeClaim, error) {
	if val, ok := claim.Annotations[storagehelpers.AnnStorageProvisioner]; ok && val == provisionerName {
		// annotation is already set, nothing to do
		return claim, nil
	}

	// The volume from method args can be pointing to watcher cache. We must not
	// modify these, therefore create a copy.
	claimClone := claim.DeepCopy()
	// TODO: remove the beta storage provisioner anno after the deprecation period
	logger := klog.FromContext(ctx)
	// 打 annotation 
	metav1.SetMetaDataAnnotation(&claimClone.ObjectMeta, storagehelpers.AnnBetaStorageProvisioner, provisionerName)
	metav1.SetMetaDataAnnotation(&claimClone.ObjectMeta, storagehelpers.AnnStorageProvisioner, provisionerName)
	updateMigrationAnnotations(logger, ctrl.csiMigratedPluginManager, ctrl.translator, claimClone.Annotations, true)
	newClaim, err := ctrl.kubeClient.CoreV1().PersistentVolumeClaims(claim.Namespace).Update(ctx, claimClone, metav1.UpdateOptions{})
	if err != nil {
		return newClaim, err
	}
	_, err = ctrl.storeClaimUpdate(logger, newClaim)
	if err != nil {
		return newClaim, err
	}
	return newClaim, nil
}
```
3. 卷控制器（PV Controller）观察到集群中新创建的 PVC 没有与之匹配的 PV，且其使用的存储类型为 out-of-tree，于是为 PVC 打 annotation：volume.beta.kubernetes.io/storage-provisioner=[out-of-tree CSI 插件名称]

```go
// sigs.k8s.io/sig-storage-lib-external-provisioner/v10/controller/controller.go
func (ctrl *ProvisionController) shouldProvision(ctx context.Context, claim *v1.PersistentVolumeClaim) (bool, error) {
	if claim.Spec.VolumeName != "" {
		return false, nil
	}

	if qualifier, ok := ctrl.provisioner.(Qualifier); ok {
		if !qualifier.ShouldProvision(ctx, claim) {
			return false, nil
		}
	}

	provisioner, found := claim.Annotations[annStorageProvisioner]
	if !found {
		provisioner, found = claim.Annotations[annBetaStorageProvisioner]
	}

	if found {
		if ctrl.knownProvisioner(provisioner) {
			claimClass := util.GetPersistentVolumeClaimClass(claim)
			class, err := ctrl.getStorageClass(claimClass)
			if err != nil {
				return false, err
			}
			if class.VolumeBindingMode != nil && *class.VolumeBindingMode == storage.VolumeBindingWaitForFirstConsumer {
				// When claim is in delay binding mode, annSelectedNode is
				// required to provision volume.
				// Though PV controller set annStorageProvisioner only when
				// annSelectedNode is set, but provisioner may remove
				// annSelectedNode to notify scheduler to reschedule again.
				if selectedNode, ok := claim.Annotations[annSelectedNode]; ok && selectedNode != "" {
					return true, nil
				}
				return false, nil
			}
			return true, nil
		}
	}

	return false, nil
}
```
4. External Provisioner 组件观察到 PVC 的 annotation 中包含 volume.beta.kubernetes.io/storage-provisioner且其 value 是自己，于是开始创盘流程：
```go
func (ctrl *ProvisionController) provisionClaimOperation(ctx context.Context, claim *v1.PersistentVolumeClaim) (ProvisioningState, error) {
	// Most code here is identical to that found in controller.go of kube's PV controller...
	claimClass := util.GetPersistentVolumeClaimClass(claim)
    // ...
	
	
	// For any issues getting fields from StorageClass (including reclaimPolicy & mountOptions),
	// retry the claim because the storageClass can be fixed/(re)created independently of the claim
	class, err := ctrl.getStorageClass(claimClass)
    // ..
	/// 
	volume, result, err := ctrl.provisioner.Provision(ctx, options)
    // ..
	// Set ClaimRef and the PV controller will bind and set annBoundByController for us
	volume.Spec.ClaimRef = claimRef

	// Add external provisioner finalizer if it doesn't already have it
	if ctrl.addFinalizer && !ctrl.checkFinalizer(volume, finalizerPV) {
		volume.ObjectMeta.Finalizers = append(volume.ObjectMeta.Finalizers, finalizerPV)
	}

	metav1.SetMetaDataAnnotation(&volume.ObjectMeta, annDynamicallyProvisioned, class.Provisioner)
	volume.Spec.StorageClassName = claimClass
	

	// 集群创建一个 PersistentVolume 资源
	if err := ctrl.volumeStore.StoreVolume(logger, claim, volume); err != nil {
		return ProvisioningFinished, err
	}
	if err = ctrl.volumes.Add(volume); err != nil {
		utilruntime.HandleError(err)
	}
	return ProvisioningFinished, nil
}

```
- 获取相关 StorageClass 资源并从中获取参数，用于后面 CSI 函数调用

- 通过 unix domain socket 调用外部 CSI 插件的CreateVolume 函数

5. 外部 CSI 插件返回成功后表示盘创建完成，此时External Provisioner 组件会在集群创建一个 PersistentVolume 资源。

6. 卷控制器会将 PV 与 PVC 进行绑定。


### Attach 将 volume 附着到节点

{{<figure src="./attach_process.png#center" width=800px >}}

1. AD 控制器（AttachDetachController）观察到使用 CSI 类型 PV 的 Pod 被调度到某一节点，此时AD 控制器会调用内部 in-tree CSI 插件（csiAttacher）的 Attach 函数；

2. 内部 in-tree CSI 插件（csiAttacher）会创建一个 VolumeAttachment 对象到集群中；

3. External Attacher 观察到该 VolumeAttachment 对象，并调用外部 CSI插件的ControllerPublish 函数以将卷挂接到对应节点上。当外部 CSI 插件挂载成功后，External Attacher会更新相关 VolumeAttachment 对象的 .Status.Attached 为 true；

4. AD 控制器内部 in-tree CSI 插件（csiAttacher）观察到 VolumeAttachment 对象的 .Status.Attached 设置为 true，于是更新AD 控制器内部状态（ActualStateOfWorld），该状态会显示在 Node 资源的 .Status.VolumesAttached 上；

### Mounting 将 volume 挂载到 pod 里

{{<figure src="./mount_process.png#center" width=800px >}}
1. Volume Manager（Kubelet 组件）观察到有新的使用 CSI 类型 PV 的 Pod 调度到本节点上，于是调用内部 in-tree CSI 插件（csiAttacher）的 WaitForAttach 函数；

2. 内部 in-tree CSI 插件（csiAttacher）等待集群中 VolumeAttachment 对象状态 .Status.Attached 变为 true；

3. in-tree CSI 插件（csiAttacher）调用 MountDevice 函数，该函数内部通过 unix domain socket 调用外部 CSI 插件的NodeStageVolume 函数；之后插件（csiAttacher）调用内部 in-tree CSI 插件（csiMountMgr）的 SetUp 函数，该函数内部会通过 unix domain socket 调用外部 CSI 插件的NodePublishVolume 函数；

## 参考

- https://github.com/container-storage-interface/spec
- [一篇汇总k8s存储架构、csi原理和实现](https://blog.csdn.net/willinux20130812/article/details/120411540)
- [浅析 CSI 工作原理](https://blog.hdls.me/16255765577465.html)
- [CSI架构和原理](https://www.cnblogs.com/hgzero/p/17464313.html)