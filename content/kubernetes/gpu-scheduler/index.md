---
title: "Gpu Scheduler"
date: 2024-10-16T10:37:57+08:00
summary: "在 Kubernetes 中调度 GPU 资源"
categories:
  - kubernetes
tags:
  - gpu
  - k8s
---

## 背景

- 随着 AI 热度越来越高，更多的业务 Pod 需要申请 GPU 资源

## 基本概念

### CUDA
2006年，NVIDIA公司发布了CUDA(Compute Unified Device Architecture)，是一种新的操作GPU计算的硬件和软件架构，是建立在NVIDIA的GPUs上的一个通用并行计算平台和编程模型，它提供了GPU编程的简易接口，基于CUDA编程可以构建基于GPU计算的应用程序，利用GPUs的并行计算引擎来更加高效地解决比较复杂的计算难题。


{{<figure src="./cuda_structure.png#center" width=800px >}}


CUDA（Compute Unified Device Architecture）的软件堆栈由驱动层、运行时层和函数库层构成。

CUDA软件堆栈中的驱动层API和运行时层API的区别如下

- 驱动层API（Driver API）：功能较完整，但是使用复杂。

- 运行时API（CUDA Runtime API）：封装了部分驱动的API，将某些驱动初始化操作隐藏，使用方便


典型的CUDA程序的执行流程如下：

1. 分配host内存，并进行数据初始化；
2. 分配device内存，并从host将数据拷贝到device上；
3. 调用CUDA的核函数在device上完成指定的运算；
4. 将device上的运算结果拷贝到host上；
5. 释放device和host上分配的内存。

### CPU 对比 GPU（Graphics Processing Unit）
{{<figure src="./gpu_vs_cpu.png#center" width=800px >}}

CPU（Central Processing Unit）是一块超大规模的集成电路，是一台计算机的运算核心（Core）和控制核心（ Control Unit）。它的功能主要是解释计算机指令以及处理计算机软件中的数据


CPU主要包括运算器（算术逻辑运算单元，ALU，Arithmetic Logic Unit）、控制单元（CU, Control Unit）、寄存器（Register）、和高速缓冲存储器（Cache）及实现它们之间联系的数据（Data）、控制及状态的总线（Bus）。简单来说就是：计算单元、控制单元和存储单元。CPU遵循的是冯诺依曼架构，其核心就是：存储程序，顺序执行。


GPU这个概念由NVIDIA公司于1999年提出。GPU是显卡上的一块芯片，就像CPU是主板上的一块芯片


## 使用

- 对于裸机环境，只需要安装对应的 GPU Driver 以及 CUDA Toolkit 。

- 对应 Docker 环境，需要额外安装 nvidia-container-toolkit 并配置 docker 使用 nvidia runtime。
```shell
$ cat /etc/docker/daemon.json
{
    "runtimes": {
        "nvidia": {
            "args": [],
            "path": "nvidia-container-runtime"
        }
    }
}
$ docker run --rm -it --gpus all tensorflow/tensorflow:2.6.0-gpu bash
```

- 对应 k8s 环境，需要额外安装对应的 device-plugin 使得 kubelet 能够感知到节点上的 GPU 设备，以便 k8s 能够进行 GPU 管理
```shell
$ cat /etc/containerd/config.toml
[plugins."io.containerd.grpc.v1.cri".containerd]
  default_runtime_name = "runc"
  snapshotter = "overlayfs"
 
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes]
 
    [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.nvidia]
      runtime_engine = ""
      runtime_root = ""
      runtime_type = "io.containerd.runc.v2"
 
      [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.nvidia.options]
        BinaryName = "/usr/bin/nvidia-container-runtime"
        SystemdCgroup = true
        
        
$  kubectl create -f https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/v0.14.3/nvidia-device-plugin.yml
```


## Device Plugin

在 k8s 环境中使用 GPU，就是靠 Device Plugin 机制，通过该机制使得 k8s 能感知到节点上的 GPU 资源，就像原生的 CPU 和 Memory 资源一样使用

在 1.8 版本引入了 device plugin 机制，通过插件形式来接入其他资源，设备厂家只需要开发对应的 xxx-device-plugin 就可以将资源接入到 k8s 了。


比如 NVIDIA 的device plugin : https://github.com/NVIDIA/k8s-device-plugin/tree/v0.16.2


### Device Plugin 原理
Device Plugin 的工作原理其实不复杂，可以分为 插件注册 和 kubelet 调用插件两部分。

- 插件注册：DevicePlugin 启动时会想节点上的 Kubelet 发起注册，这样 Kubelet就可以感知到该插件的存在了
- kubelet 调用插件：注册完成后，当有 Pod 申请对于资源时，kubelet 就会调用该插件 API 实现具体功能

```protobuf
service Registration {
    rpc Register(RegisterRequest) returns (Empty) {}
}

message RegisterRequest {
	// Version of the API the Device Plugin was built against
	string version = 1;
	// Name of the unix socket the device plugin is listening on
	// PATH = path.Join(DevicePluginPath, endpoint)
	string endpoint = 2;
	// Schedulable resource name. As of now it's expected to be a DNS Label
	string resource_name = 3;
	// Options to be communicated with Device Manager
	DevicePluginOptions options = 4;
}

```
device plugin 可以调用该接口向 Kubelet 进行注册，注册接口需要提供三个参数：

- device plugin 对应的 unix socket 名字：后续 kubelet 根据名称找到对应的 unix socket，并向插件发起调用

- device plugin 调 API version：用于区分不同版本的插件

- device plugin 提供的 ResourceName：遇到不能处理的资源申请时(CPU和Memory之外的资源)，Kubelet 就会根据申请的资源名称来匹配对应的插件

ResourceName 需要按照vendor-domain/resourcetype 格式，例如nvidia.com/gpu


```protobuf
// DevicePlugin is the service advertised by Device Plugins
service DevicePlugin {
	// GetDevicePluginOptions returns options to be communicated with Device
	// Manager
	rpc GetDevicePluginOptions(Empty) returns (DevicePluginOptions) {}

	// ListAndWatch returns a stream of List of Devices
	// Whenever a Device state change or a Device disappears, ListAndWatch
	// returns the new list
	rpc ListAndWatch(Empty) returns (stream ListAndWatchResponse) {}

	// GetPreferredAllocation returns a preferred set of devices to allocate
	// from a list of available ones. The resulting preferred allocation is not
	// guaranteed to be the allocation ultimately performed by the
	// devicemanager. It is only designed to help the devicemanager make a more
	// informed allocation decision when possible.
	rpc GetPreferredAllocation(PreferredAllocationRequest) returns (PreferredAllocationResponse) {}

	// Allocate is called during container creation so that the Device
	// Plugin can run device specific operations and instruct Kubelet
	// of the steps to make the Device available in the container
	rpc Allocate(AllocateRequest) returns (AllocateResponse) {}

	// PreStartContainer is called, if indicated by Device Plugin during registeration phase,
	// before each container start. Device plugin can run device specific operations
	// such as resetting the device before making devices available to the container
	rpc PreStartContainer(PreStartContainerRequest) returns (PreStartContainerResponse) {}
}

```
device plugin 插件需要实现以下接口：

- GetDevicePluginOptions：这个接口用于获取设备插件的信息，可以在其返回的响应中指定一些设备插件的配置选项，可以看做是插件的元数据

- ListAndWatch：该接口用于列出可用的设备并持续监视这些设备的状态变化。

- GetPreferredAllocation：将分配偏好信息提供给 device plugin,以便 device plugin 在分配时可以做出更好的选择

- Allocate：该接口用于向设备插件请求分配指定数量的设备资源。

- PreStartContainer： 该接口在容器启动之前调用，用于配置容器使用的设备资源





## 基于 K8S 的 GPU 虚拟化框架

GPU 虚拟化，除了 GPU 厂商能够在硬件和驱动层面对各种资源进行划分进而形成隔离的虚拟化方案之外，

GPU共享资源隔离方案

- gpu share。阿里GPU Share Device Plugin。不支持共享资源的隔离
- 截获CUDA库转发，如vCUDA。
- 截获驱动转发，如阿里云cGPU、腾讯云qGPU。
- 截获GPU硬件访问，如NVIDIA GRID vGPU


### 容器侧：CUDA 工具集
{{<figure src="./container_toolkit.png#center" width=800px >}}

工具: github.com/NVIDIA/nvidia-container-toolkit

一个典型的 GPU 应用软件栈如下图所示。
- 其中，最上层的是多个包含了业务应用在内的容器。每个容器都分别包含了业务应用、CUDA 工具集（CUDA Toolkit）和容器 RootFS；
- 中间层是容器引擎（docker）和安装了 CUDA 驱动程序的宿主机操作系统；
- 最底层是部署了多个 GPU 硬件显卡的服务器硬件。



## 如何利用容器运行GPU程序


- 直接使用深度学习的容器镜像 tensorflow : https://github.com/tensorflow/tensorflow/blob/v2.17.0/tensorflow/tools/ci_build/Dockerfile.gpu
- 基于cuda镜像基础构建




## 参考

- [Kubernetes容器平台下的 GPU 集群算力管控](https://mp.weixin.qq.com/s/KzyXgXAsGde_OeF-5TMd2A)
- https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/device-plugins/
- [自定义资源支持：K8s Device Plugin 从原理到实现](https://www.lixueduan.com/posts/kubernetes/21-device-plugin/)
- [GPU 环境搭建指南：如何在裸机、Docker、K8s 等环境中使用 GPU](https://www.lixueduan.com/posts/ai/01-how-to-use-gpu/)
- [CUDA简介](https://cloud.tencent.com/developer/article/2092885)
- [CUDA 编程手册系列第一章：CUDA 简介](https://developer.nvidia.com/zh-cn/blog/cuda-intro-cn/)