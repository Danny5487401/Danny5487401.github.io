---
title: "VPA（Vertical Pod Autoscaler 垂直 Pod 自动缩放器）"
date: 2025-05-17T21:11:31+08:00
summary: vpa 介绍及未来扩展
draft: true
---


垂直自动伸缩（VPA，Vertical Pod Autoscaler） 是一个基于历史数据、集群可使用资源数量和实时的事件（如 OMM， 即 out of memory）来自动设置Pod所需资源并且能够在运行时自动调整资源基础服务。


## VPA一般需要具备以下三种关键能力

1、容器资源规格推荐。基于应用的真实负载，根据特定的算法计算出容器的合理资源规格。

2、对于新创建的Pod，需要基于k8s webhook，在创建Pod对象的过程中将资源规格修改为推荐值。

3、对于已经创建的Pod，需要定时动态调整容器的资源规格。


## VPA 组成

三部分
- admission-controller（准入控制器）
- recommender（推荐器）
- updater（更新器）


### 准入控制器（Admission Controller）

VPA Admission Controller 拦截 Pod 创建请求。如果 Pod 与 VPA 配置匹配且模式未设置为 off，则控制器通过将建议的资源应用于 Pod spec 来重写资源请求。


### 推荐器（Recommender）

Recommender 是 VPA 的主要组成部分。它负责计算推荐的资源。在启动时，Recommender 获取所有 Pod 的历史资源利用率（无论它们是否使用 VPA ）以及历史存储中的 Pod OOM 事件的历史记录。
它聚合这些数据并将其保存在内存中。


### 更新器（Updater）


VPA Updater 是一个负责将推荐资源应用于现有 Pod 的组件。它监视集群中的所有 VPA object 和 Pod ，通过调用 Recommender API 定期获取由 VPA 控制的 Pod 的建议。
当推荐的资源与实际配置的资源明显不同时，Updater 可能会决定更新 Pod。


## 更新策略（Update Policy）

mode 可以设置为三种：

Initial: VPA 只在创建 Pod 时分配资源，在 Pod 的其他生命周期不改变Pod的资源。

Auto(默认)：VPA 在 Pod 创建时分配资源，并且能够在 Pod 的其他生命周期更新它们，包括淘汰和重新调度 Pod。

Off：VPA 从不改变Pod资源。Recommender 而依旧会在VPA对象中生成推荐信息，他们可以被用在演习中。


## VPA的不足
VPA的成熟度还不足 : 更新正在运行的 Pod 资源配置是 VPA 的一项试验性功能，会导致 Pod 的重建和重启，而且有可能被调度到其他的节点上

多个 VPA 同时匹配同一个 Pod 会造成未定义的行为

## 参考
- https://github.com/kubernetes/autoscaler/tree/vertical-pod-autoscaler-1.3.1/cluster-autoscaler
- [Kubernetes 垂直自动伸缩走向何方](https://mp.weixin.qq.com/s/ykWgx1WJxBFSPidD1To53Q)
- [B站容器云平台VPA技术实践](https://mp.weixin.qq.com/s/LFytnn2m732aOwbHEtc1Mg)