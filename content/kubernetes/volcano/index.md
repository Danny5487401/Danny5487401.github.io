---
title: "Volcano"
date: 2025-06-27T12:52:00+08:00
summary: "Volcano架构体系"
categories:
  - kubernetes
tags:
  - scheduler
  - k8s
---
Volcano 主要用于AI、大数据、基因、渲染等诸多高性能计算场景，对主流通用计算框架均有很好的支持。它提供高性能计算任务调度，异构设备管理，任务运行时管理等能力.


## 丰富的调度策略

- Gang Scheduling：确保作业的所有任务同时启动，适用于分布式训练、大数据等场景
- Binpack Scheduling：通过任务紧凑分配优化资源利用率
- Heterogeneous device scheduling：高效共享GPU异构资源，支持CUDA和MIG两种模式的GPU调度，支持NPU调度
- Proportion/Capacity Scheduling：基于队列配额进行资源的共享/抢占/回收
- NodeGroup Scheduling：支持节点分组亲和性调度，实现队列与节点组的绑定关系
- DRF Scheduling：支持多维度资源的公平调度
- SLA Scheduling：基于服务质量的调度保障
- Task-topology Scheduling：支持任务拓扑感知调度，优化通信密集型应用性能
- NUMA Aware Scheduling：支持NUMA架构的调度，优化任务在多核处理器上的资源分配，提升内存访问效率和计算性能


### Binpack Scheduling



## 云原生混部

云原生混部是指通过云原生的方式将在线业务和离线业务部署在同一个集群。
由于在线业务运行具有明显的波峰波谷特征，因此当在线业务运行在波谷时，离线业务可以利用这部分空闲的资源，当在线业务到达波峰时，通过在线作业优先级控制等手段压制离线作业的运行，保障在线作业的资源使用，从而提升集群的整体资源利用率，同时保障在线业务SLO。

## QOS


|            Qos等级            |            典型应用场景            | CPU优先级 | Memory优先级 |
| :---------------------------: | :---------------------------------: | :-------: | :----------: |
|     LC(Latency Critical)     | 时延敏感极高的核心在线业务，独占CPU |   独占   |      0      |
| HLS(Highly Latency Sensitive) |       时延敏感极高的在线业务       |     2     |      0      |
|     LS(Latency Sensitive)     |        时延敏感型的近线业务        |     1     |      0      |
|        BE(Best Effort)        |  离线的AI、大数据业务，可容忍驱逐  |    -1    |      0      |



Volcano提供了native、extend等超卖资源计算和上报模式，
native的模式会上报超卖资源至节点的allocatable字段，这样一来在线和离线作业的使用方式是一致的，提升了用户体验 ，
而extend模式支持将超卖资源以扩展方式上报至节点，做到和Kubernetes的解耦，



在离线作业通常会使用多种不同维度的资源，因此需要对各个维度的资源设置资源隔离措施，Volcano会通过内核态接口设置CPU、Memory、Network等维度的资源隔离，当在离线作业发生资源争用时，压制离线作业的资源使用，优先保障在线作业QoS。

- CPU: OS层面提供了5级CPU QoS等级，数值从-2到2，QoS等级越高则代表可以获得更多的CPU时间片并有更高的抢占优先级。通过设置cpu子系统的cgroup cpu.qos_level可以为不同业务设置不用的CPU QoS。

- Memory: Memory隔离体现在系统发生OOM时离线作业会被有限OOM Kill掉，通过设置memory子系统的cgroup memory.qos_level可以为不同业务设置不同的Memory QoS。

- Network: 网络隔离实现了对在线作业的出口网络带宽保障，它基于整机的带宽大小，并通过cgroup + tc + ebpf技术，实现在线作业对离线作业的出口网络带宽压制。





## 参考

- https://volcano.sh/zh/docs/v1-12-0/
