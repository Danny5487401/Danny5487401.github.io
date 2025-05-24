---
title: "Koodinator"
date: 2025-05-18T09:54:34+08:00
draft: true
---



## 基本知识


### RDT

{{<figure src="./rdt.png#center" width=800px >}}

RDT技术全称 Resource Director Technology，RDT技术提供了LLC（Last Level Cache）以及MB（Memory Bandwidth）内存带宽的分配和监控能力.

RDT的主要功能有以下几个：

- CAT（Cache Allocation Technology）：分配和隔离LLC资源
- CMT（Cache Monitor Technology）：监控LLC的使用情况
- MBA（Memory Bandwidth Allocation）：内存带宽分配和隔离
- MBM（Memory Bandwidth Monitor）：内存带宽监控
- CDP（Code & Data Prioritization）：细化的Code-Cache和Data-Cache的分配

在混合部署场景下，cgroup提供了粗粒度的CPU、内存、IO等资源的隔离和分配，但是从软件层面无法对LLC(last level cache)缓存和内存带宽等共享资源进行隔离，离线业务可以通过争抢LLC和内存带宽来干扰在线业务。
RDT从硬件层面提供了细粒度的LLC资源的分配和监控能力，在混部场景运用广泛。



Resctrl文件系统是Linux内核在4.10提供的对RDT技术的支持，作为一个伪文件系统在使用方式上与cgroup是类似，通过提供一系列的文件为用户态提供查询和修改接口。


## 组成

{{<figure src="./parts.png#center" width=800px >}}

Koordinator 由两个控制面（Koordinator Scheduler/Koordinator Manager）和一个 DaemonSet 组件(Koordlet)组成。


### Koord-Scheduler
Koord-Scheduler 以 Deployment 的形式部署在集群中，用于增强 Kubernetes 在 QoS-aware，差异化 SLO 以及任务调度场景的资源调度能力


- QoS-aware 调度，包括负载感知调度让节点间负载更佳平衡，资源超卖的方式支持运行更多的低优先级工作负载。
- 差异化 SLO，包括 CPU 精细化编排，为不同的工作负载提供不同的 QoS 隔离策略（cfs，LLC，memory 带宽，网络带宽，磁盘io）。
- 任务调度，包括弹性额度管理，Gang 调度，异构资源调度等，以支持更好的运行大数据和 AI 工作负载。


### Koord-Descheduler
Koord-Decheduler 以 Deployment 的形式部署在集群中，它是 kubernetes 上游社区的增强版本，当前包含:

- 重调度框架, Koord-Decheduler 重新设计了全新重调度框架，在可扩展性、资源确定性以及安全性上增加了诸多的加强，更多的细节.
- 负载感知重调度，基于新框架实现的一个负载感知重调度插件，支持用户配置节点的安全水位，以驱动重调度器持续优化集群编排，从而规避集群中出现局部节点热点.


### Koord-Manager
Koord-Manager 以 Deployment 的形式部署，通常由两个实例组成，一个 leader 实例和一个 backup 实例。Koordinator Manager 由几个控制器和 webhooks 组成，用于协调混部场景下的工作负载，资源超卖(resource overcommitment)和 SLO 管理。

目前，提供了三个组件:

- Colocation Profile，用于支持混部而不需要修改工作负载。用户只需要在集群中做少量的配置，原来的工作负载就可以在混部模式下运行，了解更多关于Colocation Profile。
- SLO 控制器，用于资源超卖(resource overcommitment)管理，根据节点混部时的运行状态，动态调整集群的超发(overcommit)配置比例。该控制器的核心职责是管理混部时的 SLO，如智能识别出集群中的异常节点并降低其权重，动态调整混部时的水位和压力策略，从而保证集群中 pod 的稳定性和吞吐量。
- Recommender（即将推出），它使用 histograms 来统计和预测工作负载的资源使用细节，用来预估工作负载的峰值资源需求


### Koordlet
Koordlet 以 DaemonSet 的形式部署在 Kubernetes 集群中，用于支持混部场景下的资源超卖(resource overcommitment)、干扰检测、QoS 保证等。


在Koordlet内部，它主要包括以下模块:

- 资源 Profiling，估算 Pod 资源的实际使用情况，回收已分配但未使用的资源，用于低优先级 Pod 的 overcommit。
- 资源隔离，为不同类型的 Pod 设置资源隔离参数，避免低优先级的 Pod 影响高优先级 Pod 的稳定性和性能。
- 干扰检测，对于运行中的 Pod，动态检测资源争夺，包括 CPU 调度、内存分配延迟、网络、磁盘 IO 延迟等。
- QoS 管理器，根据资源剖析、干扰检测结果和 SLO 配置，动态调整混部节点的水位，抑制影响服务质量的 Pod。
- 资源调优，针对混部场景进行容器资源调优，优化容器的 CPU Throttle、OOM 等，提高服务运行质量。


### Koord-RuntimeProxy
Koord-RuntimeProxy 以 systemd service 的形式部署在 Kubernetes 集群的节点上，用于代理 Kubelet 与 containerd/docker 之间的 CRI 请求。这一个代理被设计来支持精细化的资源管理策略，比如为不同 QoS Pod 设置不同的 cgroup 参数，包括内核 cfs quota，resctl 等等技术特性，以改进 Pod 的运行时质量。。

## 参考

- https://koordinator.sh/zh-Hans/
- [Intel-RDT 技术浅析](https://www.cnblogs.com/wodemia/p/17745661.html)
- [Resctrl使用说明书](https://www.cnblogs.com/wodemia/p/17745666.html)