---
title: "Pod"
date: 2024-10-30T22:30:14+08:00
summary: pod 启动过程
categories:
  - kubernetes
tags:
  - k8s
  - pod
  - 源码
---


## 总体图
{{<figure src="./what-happens-when-k8s.svg#center" width=800px >}}

{{<figure src="./k8s-creation.gif#center" width=800px >}}

## pod 启动过程简写版本

1. 用户请求：

用户通过kubectl命令行工具或API接口提交一个Pod的定义，通常是通过YAML或JSON格式的配置文件来描述Pod的详细信息，包括容器镜像、环境变量、资源需求、卷挂载等。

2. API Server接收入口：

用户的请求首先到达Kubernetes API Server，API Server会对请求进行认证、授权和准入控制检查。

3. 持久化存储到etcd：

一旦API Server验证了请求的有效性，它会将Pod的定义信息写入etcd（分布式键值存储），以确保集群内的所有组件都能获取最新的集群状态。

4. 调度决策：

当Pod被创建并保存到etcd后，API Server会触发调度器（scheduler）对Pod进行调度。
调度器根据集群节点的资源状况、亲和性和反亲和性规则以及其他约束条件，选择一个最适合运行Pod的Node，并更新Pod的状态为“Scheduled”。

5. 绑定Pod至Node：

调度器将调度决定通知给API Server，由API Server将Pod与选定的Node进行绑定。

6. kubelet执行：

相应节点上的kubelet进程通过监听API Server的事件，得知需要在其上创建新的Pod。
kubelet从etcd中获取该Pod的详细信息，然后开始执行创建Pod的具体工作，这包括：
- 下载所需容器镜像
- 创建网络命名空间和网络策略
- 设置Pod的Volume（卷）
- 启动Pod中的各个容器

7. 容器启动：

容器运行时（如Docker或containerd）负责启动容器，并监控容器的生命周期事件，如健康检查、重启策略等。

8. Pod就绪和运行：

当Pod中的所有容器均成功启动并且通过了就绪探针（readiness probe）检测，则kubelet会将Pod的状态报告回API Server，标记Pod为“Running”状态，此时Pod可以接受来自Service的流量。

9. 持续监控与管理：

在Pod的整个生命周期内，kubelet和API Server将持续监视Pod的状态，并根据Pod的定义和系统策略进行相应的管理和维护操作。


## 参考

- [kubectl 创建 Pod 背后到底发生了什么](https://icloudnative.io/posts/what-happens-when-k8s)
- [Components and processes for creating a Kubernetes POD](https://community.veeam.com/kubernetes-korner-90/components-and-processes-for-creating-a-kubernetes-pod-6335)