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




## 优先级

Koordinator 将不同类型的工作负载匹配到不同的优先级:
{{<figure src="./priority_class.png#center" width=800px >}}
- koord-prod，运行典型的延迟敏感型服务，一般是指需要 "实时 "响应的服务类型，比如通过点击移动APP中的按钮调用的典型服务。
- koord-mid，对应于长周期的可用资源，一般用于运行一些实时计算、人工智能训练任务/作业，如 tensorflow/pytorch 等。
- koord-batch，对应于的短周期可用资源，运行典型的离线批处理作业，一般指离线分析类作业，如日级大数据报告、非交互式 SQL 查询。
- koord-free，运行低优先级的离线批处理作业，一般指不做资源预算，利用闲置资源尽量完成，如开发人员为测试目提交的作业。

## QOS

{{<figure src="./qos_core.png#center" width=800px >}}

- LSE(Latency Sensitive Exclusive): 很少使用，常见于中间件类应用，一般在独立的资源池中使用
- LSR(Latency Sensitive Reserved): 类似于社区的 Guaranteed，CPU 核被绑定
- LS(Latency Sensitive): 微服务工作负载的典型QoS级别，实现更好的资源弹性和更灵活的资源调整能力
- BE(Best Effort): 批量作业的典型 QoS 水平，在一定时期内稳定的计算吞吐量，低成本资源





## 负载感知调度（Load Aware Scheduling）

{{<figure src="./load_aware.png#center" width=800px >}}


### 节点指标
```shell
[root@master-01 ~]# kubectl get nodemetrics.slo.koordinator.sh master-01 -o yaml
apiVersion: slo.koordinator.sh/v1alpha1
kind: NodeMetric
metadata:
  creationTimestamp: "2025-05-24T11:31:54Z"
  generation: 1
  name: master-01
  resourceVersion: "15281512"
  uid: 21d81aaf-0338-4e94-bccc-07540fec3575
spec:
  metricCollectPolicy:
    aggregateDurationSeconds: 300
    nodeAggregatePolicy:
      durations:
      - 5m0s
      - 10m0s
      - 30m0s
    nodeMemoryCollectPolicy: usageWithoutPageCache
    reportIntervalSeconds: 60
status:
  nodeMetric:
    aggregatedNodeUsages:
    - duration: 5m0s
      usage:
        p50:
          resources:
            cpu: 429m
            memory: 5712464Ki
        p90:
          resources:
            cpu: 886m
            memory: 5750116Ki
        p95:
          resources:
            cpu: 1097m
            memory: 5833412Ki
        p99:
          resources:
            cpu: 1366m
            memory: 5938812Ki
    - duration: 10m0s
      usage:
        p50:
          resources:
            cpu: 429m
            memory: 5716284Ki
        p90:
          resources:
            cpu: 887m
            memory: 5763284Ki
        p95:
          resources:
            cpu: 1127m
            memory: 5842656Ki
        p99:
          resources:
            cpu: 1537m
            memory: 5934088Ki
    - duration: 30m0s
      usage:
        p50:
          resources:
            cpu: 429m
            memory: 5723620Ki
        p90:
          resources:
            cpu: 858m
            memory: 5823232Ki
        p95:
          resources:
            cpu: 1113m
            memory: 5867972Ki
        p99:
          resources:
            cpu: 1467m
            memory: 5977372Ki
    aggregatedSystemUsages:
    - duration: 5m0s
      usage:
        p50:
          resources:
            cpu: 153m
            memory: 3078852Ki
        p90:
          resources:
            cpu: 407m
            memory: 3085764Ki
        p95:
          resources:
            cpu: 539m
            memory: 3088652Ki
        p99:
          resources:
            cpu: 795m
            memory: 3106312Ki
    - duration: 10m0s
      usage:
        p50:
          resources:
            cpu: 155m
            memory: 3080256Ki
        p90:
          resources:
            cpu: 422m
            memory: 3089936Ki
        p95:
          resources:
            cpu: 551m
            memory: 3094736Ki
        p99:
          resources:
            cpu: 803m
            memory: 3123404Ki
    - duration: 30m0s
      usage:
        p50:
          resources:
            cpu: 156m
            memory: 3082092Ki
        p90:
          resources:
            cpu: 424m
            memory: 3179492Ki
        p95:
          resources:
            cpu: 569m
            memory: 3184832Ki
        p99:
          resources:
            cpu: 853m
            memory: 3203756Ki
    nodeUsage:
      resources:
        cpu: 515m
        memory: "5862330450"
    systemUsage:
      resources:
        cpu: 196m
        memory: "3150994008"
  podsMetric:
  - name: my-clickhouse-zookeeper-0
    namespace: clickhouse
    podUsage:
      resources:
        cpu: 26m
        memory: "396051912"
    priority: koord-prod
    qos: LS
  - name: prometheus-prometheus-node-exporter-wgsq8
    namespace: monitor
    podUsage:
      resources:
        cpu: 2m
        memory: "15283891"
    priority: koord-batch
    qos: BE
  - name: node-local-dns-wb5tm
    namespace: kube-system
    podUsage:
      resources:
        cpu: 5m
        memory: "15037204"
    priority: koord-prod
    qos: LS
  - name: my-clickhouse-shard0-0
    namespace: clickhouse
    podUsage:
      resources:
        cpu: 183m
        memory: "681455546"
    priority: koord-prod
    qos: LS
  - name: koordlet-fzt68
    namespace: koordinator-system
    podUsage:
      resources:
        cpu: 41m
        memory: "64553043"
    priority: koord-prod
    qos: LS
  - name: koord-manager-7dcfb8f8bf-7s25k
    namespace: koordinator-system
    podUsage:
      resources:
        cpu: 8m
        memory: "28991571"
    priority: koord-prod
    qos: LS
  - name: mysql-7474b86d4f-52p5n
    namespace: mysql
    podUsage:
      resources:
        cpu: 21m
        memory: "393941019"
    priority: koord-prod
    qos: LSR
  - name: kube-flannel-ds-h27xn
    namespace: kube-system
    podUsage:
      resources:
        cpu: 11m
        memory: "13854899"
    priority: koord-prod
    qos: LS
  - name: my-kafka-controller-0
    namespace: kafka
    podUsage:
      resources:
        cpu: 57m
        memory: "1101719261"
    priority: koord-prod
    qos: LS
  prodReclaimableMetric:
    resource:
      resources:
        cpu: 2380m
        memory: "0"
  updateTime: "2025-05-25T03:36:38Z"
```


## 参考

- https://koordinator.sh/zh-Hans/
- [Intel-RDT 技术浅析](https://www.cnblogs.com/wodemia/p/17745661.html)
- [Resctrl使用说明书](https://www.cnblogs.com/wodemia/p/17745666.html)