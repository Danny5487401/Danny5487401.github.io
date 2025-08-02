---
title: "Calico"
date: 2025-06-21T22:35:34+08:00
summary: Calico 实现原理及源码分析
categories:
  - kubernetes
  - cni
tags:
  - cni
---


## 基本知识

### tcpdump 


```shell
$ tcpdump -nn udp port 53 or host 35.190.27.188
```
-nn ，表示不解析抓包中的域名（即不反向解析）、协议以及端口号。

* udp : 协议过滤,只显示 UDP协议
* port 53 : 端口过滤额, 端口号（包括源端口和目的端口）为53的包。

* host 35.190.27.188: 主机过滤, 表示只显示 IP 地址（包括源地址和目的地址）为35.190.27.188的包。

* or: 逻辑表达式, 这两个过滤条件中间的 “or”，表示或的关系，也就是说，只要满足上面两个条件中的任一个，就可以展示出来。

* net 192.168.0.0 网络地址过滤





输出格式
```shell
时间戳 协议 源地址.源端口 > 目的地址.目的端口 网络包详细信息
```

保存到 ping.pcap 文件
```shell
$ tcpdump -nn udp port 53 or host 35.190.27.188 -w ping.pcap
```


### BGP (外网路由协议（Border Gateway Protocol)

求最短路径常用的有两种方法，一种是Bellman-Ford算法，一种是Dijkstra算法。


动态路由算法
- 第一大类的算法称为距离矢量路由（distance vector routing）。它是基于Bellman-Ford算法的
- 第二大类算法是链路状态路由（link state routing），基于Dijkstra算法。


BGP又分为两类，eBGP(External Border Gateway Protocol )和iBGP (Internal Border Gateway Protocol)。

iGGP: 负责在同一AS内的BGP路由器间传播路由,通过递归方式进行路径选择.
eBGP: 用于在不同AS间传播BGP路由,它基于hop-by-hop 机制进行路由选择.


BGP协议使用的算法是路径矢量路由协议（path-vector protocol）。它是距离矢量路由协议的升级版。


自治系统（Autonomous System, AS） 是指一组相互信任、使用相同路由策略的网络或子网，通过BGP（边界网关协议）进行通信。


自治系统编号（Autonomous System Number，ASN） 是一个唯一标识自治系统的32位整数，用于在BGP（边界网关协议）中标识不同的网络或网络提供商。
```shell
root@node1:/etc/cni/net.d# calicoctl get nodes --output=wide
NAME    ASN       IPV4             IPV6
node1   (64512)   172.16.7.30/16
node2   (64512)   172.16.7.31/16
node3   (64512)   172.16.7.32/16
node4   (64512)   172.16.7.33/16
node5   (64512)   172.16.7.34/16
```


### Proxy ARP
能就是使那些在同一网段却不在同一物理网络上的计算机或路由器能够相互通信。

```shell
# 查看 ens32 是否开启
root@node1:~# cat /proc/sys/net/ipv4/conf/ens32/proxy_arp
0
root@node1:~# cat /proc/sys/net/ipv4/conf/calid7b92ca9b15/proxy_arp
1
```


### eXpress Data Path (XDP) 

XDP（eXpress Data Path）提供了一个内核态、高性能、可编程 BPF 包处理框架。
{{<figure src="./xdp-process.png#center" width=800px >}}


XDP的三种工作模式
- Native XDP，即运行在网卡驱动实现的的 poll() 函数中，需要网卡驱动的支持；
- Generic XDP，即上面提到的如果网卡驱动不支持XDP，则可以运行在 receive_skb() 函数中；
- Offloaded XDP，这种模式是指将XDP程序offload到网卡中，这需要网卡硬件的支持，JIT编译器将BPF代码翻译成网卡原生指令并在网卡上运行


### eBPF
eBPF 是嵌入在 Linux 内核中的虚拟机。它允许将小程序加载到内核中，并附加到钩子上，当某些事件发生时会触发这些钩子。这允许（有时大量）定制内核的行为。

{{<figure src="./ebpf_structure.png#center" width=800px >}}

eBPF 的执行需要三步：

1. 从用户跟踪程序生成 BPF 字节码；

2. 加载到内核中运行；

3. 向用户空间输出结果。


#### 动态追踪的事件源
动态追踪所使用的事件源，可以分为静态探针、动态探针以及硬件事件等三类

{{<figure src="./perf_event.png#center" width=800px >}}
- 硬件事件通常由性能监控计数器 PMC（Performance Monitoring Counter）产生，包括了各种硬件的性能情况，比如 CPU 的缓存、指令周期、分支预测等等。
- 静态探针，是指事先在代码中定义好，并编译到应用程序或者内核中的探针。这些探针只有在开启探测功能时，才会被执行到；未开启时并不会执行。常见的静态探针包括内核中的跟踪点（tracepoints）和 USDT（Userland Statically Defined Tracing）探针。
- 动态探针，则是指没有事先在代码中定义，但却可以在运行时动态添加的探针，比如函数的调用和返回等。动态探针支持按需在内核或者应用程序中添加探测点，具有更高的灵活性。常见的动态探针有两种，即用于内核态的 kprobes 和用于用户态的 uprobes。

## Calico组网模式


### IPIP 模式(不同网段)

{{<figure src="./ip-in-ip.png#center" width=800px >}}
Calico默认网络架构，IPIP 可理解为IPinIP，属于overlay的网络架构。不依赖于外部交换机设备，即可实现网络组网。缺点是报文的封装和解封装对网络效率有影响，节点规模有限制。

{{<figure src="./ip-in-ip-communication.png#center" width=800px >}}

### VXLAN (不同网段)

### BGP 模式 (相同网段)
两种模式

1. 全互联模式(node-to-node mesh)

全互联模式 每一个BGP Speaker都需要和其他BGP Speaker建立BGP连接，这样BGP连接总数就是N^2，如果数量过大会消耗大量连接。如果集群数量超过100台官方不建议使用此种模式。
```shell
(⎈|kubeasz-test:metallb)➜  git_download kubectl get bgpconfigurations.crd.projectcalico.org default -o yaml
apiVersion: crd.projectcalico.org/v1
kind: BGPConfiguration
metadata:
  name: default
spec:
  asNumber: 64512
  listenPort: 179
  logSeverityScreen: Info
  nodeToNodeMeshEnabled: true
```



2. 路由反射模式Router Reflection（RR）

RR模式 中会指定一个或多个BGP Speaker为RouterReflection，它与网络中其他Speaker建立连接，每个Speaker只要与Router Reflection建立BGP就可以获得全网的路由信息。
在calico中可以通过Global Peer实现RR模式。



Calico 项目提供的 BGP 网络解决方案，与 Flannel 的 host-gw 模式几乎一样。也就是说，Calico也是基于路由表实现容器数据包转发，但不同于Flannel使用flanneld进程来维护路由信息的做法，而Calico项目使用BGP协议来自动维护整个集群的路由信息


#### 不适合 BGP 模式

- 节点跨网段
- 阻止 BGP 报文的网路环境
- 对入站数据包进行强制源地址和目的地址校验


## IPAM 地址管理
```shell
(⎈|kubeasz-test:metallb)➜  ~ kubectl get cm -n kube-system calico-config -o yaml
apiVersion: v1
data:
  calico_backend: vxlan
  cluster_type: kubespray
  cni_network_config: |-
    {
      "name": "k8s-pod-network",
      "cniVersion":"0.3.1",
      "plugins":[
        {
            "datastore_type": "kubernetes",
            "nodename": "__KUBERNETES_NODE_NAME__",
            "type": "calico",
            "log_level": "info",
            "log_file_path": "/var/log/calico/cni/cni.log",
            "ipam": {
              "type": "calico-ipam",
              "assign_ipv4": "true"
            },
            "policy": {
              "type": "k8s"
            },
            "kubernetes": {
              "kubeconfig": "__KUBECONFIG_FILEPATH__"
            }
        },
        {
          "type":"portmap",
          "capabilities": {
            "portMappings": true
          }
        },
        {
          "type":"bandwidth",
          "capabilities": {
            "bandwidth": true
          }
        }
      ]
    }
kind: ConfigMap
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"v1","data":{"calico_backend":"vxlan","cluster_type":"kubespray","cni_network_config":"{\n  \"name\": \"k8s-pod-network\",\n  \"cniVersion\":\"0.3.1\",\n  \"plugins\":[\n    {\n                  \"datastore_type\": \"kubernetes\",\n        \"nodename\": \"__KUBERNETES_NODE_NAME__\",\n                  \"type\": \"calico\",\n        \"log_level\": \"info\",\n                  \"log_file_path\": \"/var/log/calico/cni/cni.log\",\n                                      \"ipam\": {\n          \"type\": \"calico-ipam\",\n                        \"assign_ipv4\": \"true\"\n        },\n                                                \"policy\": {\n          \"type\": \"k8s\"\n        },\n                            \"kubernetes\": {\n          \"kubeconfig\": \"__KUBECONFIG_FILEPATH__\"\n        }\n    },\n    {\n      \"type\":\"portmap\",\n      \"capabilities\": {\n        \"portMappings\": true\n      }\n    },\n    {\n      \"type\":\"bandwidth\",\n      \"capabilities\": {\n        \"bandwidth\": true\n      }\n    }\n  ]\n}"},"kind":"ConfigMap","metadata":{"annotations":{},"name":"calico-config","namespace":"kube-system"}}
  creationTimestamp: "2025-06-23T05:13:15Z"
  name: calico-config
  namespace: kube-system
  resourceVersion: "1602"
  uid: 5ddb6570-a0a3-4566-81a7-2457186da8fd
```
确保 ipam 使用 calico-ipam 

Calico通过IPPool进行IPAM管理，IPPool定义了地址池名字、地址段、blockSize等字段。
```shell
# 查看默认 ipPool
(⎈|kubeasz-test:metallb)➜  ~ kubectl get ippools.crd.projectcalico.org default-pool -o yaml
apiVersion: crd.projectcalico.org/v1
kind: IPPool
metadata:
  annotations:
    projectcalico.org/metadata: '{"creationTimestamp":"2025-06-23T05:13:00Z"}'
  creationTimestamp: "2025-06-23T05:13:00Z"
  generation: 1
  name: default-pool
  resourceVersion: "1560"
  uid: 94fcf297-08e1-48e6-8508-81430ca903c4
spec:
  allowedUses:
  - Workload
  - Tunnel
  blockSize: 26
  cidr: 10.233.64.0/18 # 填写创建集群时规划的cidr地址段    
  ipipMode: Never  # Never不使用IPIP模式,Always时代表使用IPIP模式,CrossSubnet代表混合模式,跨网段则ipip,不跨网段BGP       
  natOutgoing: true  #nat转发 
  nodeSelector: all()
  vxlanMode: Always  # vxlanMode 可以为Always,CrossSubnet, 
  
  
root@node1:/opt/calico# calicoctl ipam show
+----------+----------------+-----------+------------+--------------+
| GROUPING |      CIDR      | IPS TOTAL | IPS IN USE |   IPS FREE   |
+----------+----------------+-----------+------------+--------------+
| IP Pool  | 10.233.64.0/18 |     16384 | 61 (0%)    | 16323 (100%) |
+----------+----------------+-----------+------------+--------------+
```

字段解释:

- block/blockSize: block主要功能是路由聚合，减少对外宣告路由条目。
block在POD所在节点自动创建，如在worker01节点创建1.1.1.1的POD时，blocksize为29，则该节点自动创建1.1.1.0/29的block，对外宣告1.1.1.0/29的BGP路由，并且节点下发1.1.1.0/29的黑洞路由和1.1.1.1/32的明细路由。
在IBGP模式下，黑洞路由可避免环路。如果blockSize设置为32，则不下发黑洞路由也不会造成环路，缺点是路由没有聚合，路由表项会比较多，需要考虑交换机路由器的容量。


Calico创建block时，会出现借用IP的情况。
如在 worker01节点存在1.1.1.0/29的block，由于worker01节点负载很高，地址为1.1.1.2的POD被调度到worker02节点，这种现象为IP借用。
woker02节点会对外宣告1.1.1.2/32的明细路由，在IBGP模式下，交换机需要开启RR模式，将路由反射给worker01上，否则在不同worker节点的同一个block的POD，由于黑洞路由的存在，导致POD之间网络不通。
可通过ipamconfigs来管理是否允许借用IP(strictAffinity)、每个节点上最多允许创建block的数量(maxBlocksPerHost)等。



- nodeselector: 可以根据拓扑分配不同段的IP地址

```yaml
# 创建了两个 IP 池，它只为标签为zone=west和zone=west2的节点分配 IP 地址
kind: IPPool                                                                                                                                                                  
metadata:                                                                                                                                                                     
   name: zone-west-ippool1                                                                                                                                                    
spec:                                                                                                                                                                         
   cidr: 172.122.1.0/24                                                                                                                                                       
   ipipMode: Always                                                                                                                                                           
   natOutgoing: true                                                                                                                                                          
   nodeSelector: zone == "west"                                                                                                                                               
                                                                                                                                                                                
---                                                                                                                                                                           
                                                                                                                                                                                
apiVersion: projectcalico.org/v3                                                                                                                                              
kind: IPPool                                                                                                                                                                  
metadata:                                                                                                                                                                     
   name: zone-west-ippool2                                                                                                                                                    
spec:                                                                                                                                                                         
   cidr: 172.122.2.0/24                                                                                                                                                       
   ipipMode: Always                                                                                                                                                           
   natOutgoing: true                                                                                                                                                          
   nodeSelector: zone == "west2"
```


- ipipMode
  * ipip always模式（纯ipip模式）
  * ipip cross-subnet模式（ipip-bgp混合模式），指同子网内路由采用bgp，跨子网路由采用ipip

## 组件

- Felix：运行在每一台 Host 的 agent 进程，主要负责网络接口管理和监听、路由、ARP 管理、ACL 管理和同步、状态上报等。
- etcd：分布式键值存储，主要负责网络元数据一致性，确保Calico网络状态的准确性，可以与kubernetes共用；
- BGP Client（BIRD）：Calico 为每一台 Host 部署一个 BGP Client，使用 BIRD 实现，BIRD 是一个单独的持续发展的项目，实现了众多动态路由协议比如 BGP、OSPF、RIP 等。在 Calico 的角色是监听 Host 上由 Felix 注入的路由信息，然后通过 BGP 协议广播告诉剩余 Host 节点，从而实现网络互通。
- calico-controller:  实现网络策略功能,支持 calico 相关的 CRD 资源.
- BGP Route Reflector（RR 路由反射）：在大型网络规模中，如果仅仅使用 BGP client 形成 mesh 全网互联的方案就会导致规模限制，因为所有节点之间俩俩互联，需要 N^2 个连接，为了解决这个规模问题，可以采用 BGP 的 Router Reflector 的方法，使所有 BGP Client 仅与特定 RR 节点互联并做路由同步，从而大大减少连接数。
- typha:  各个 calico-node 同 calico datastore 通讯的中间层,减轻大规模集群 calico datastore 的负载,具有缓存功能. 50 节点以上,建议使用.
- Whisker: v3.30 图形工具.


## calico 数据面

### 传统标准数据面


{{<figure src="./standard_process.png#center" width=800px >}}

1. 网卡收到一个包（通过 DMA 放到 ring-buffer）。
1. 包经过 XDP hook 点。
1. 内核给包分配内存创建skb（包的内核结构体表示），然后送到内核协议栈。
1. 包经过 GRO 处理，对分片包进行重组。
1. 包进入 tc（traffic control）的 ingress hook。接下来，所有橙色的框都是 Netfilter 处理点。
1. Netfilter：在 PREROUTING hook 点处理 raw table 里的 iptables 规则。
1. 包经过内核的连接跟踪（conntrack）模块。
1. Netfilter：在 PREROUTING hook 点处理 mangle table 的 iptables 规则。
1. Netfilter：在 PREROUTING hook 点处理 nat table 的 iptables 规则。
1. 进行路由判断（FIB：Forwarding Information Base，路由条目的内核表示） 。接下来又是四个 Netfilter 处理点。
1. Netfilter：在 FORWARD hook 点处理 mangle table 里的 iptables 规则。
1. Netfilter：在 FORWARD hook 点处理 filter table 里的 iptables 规则。
1. Netfilter：在 POSTROUTING hook 点处理 mangle table 里的 iptables 规则。
1. Netfilter：在 POSTROUTING hook 点处理 nat table 里的 iptables 规则。
1. 包到达 TC egress hook 点，会进行出方向（egress）的判断，例如判断这个包是到本 地设备，还是到主机外。
1. 对大包进行分片。根据 step 15 判断的结果，这个包接下来可能会：
1. 发送到一个本机 veth 设备，或者一个本机 service endpoint，
1. 或者，如果目的 IP 是主机外，就通过网卡发出去



### eBPF
{{<figure src="./ebpf_process.png#center" width=800px >}}

对比可以看出，Calico eBPF datapath 做了短路处理：从 tc ingress 直接到 tc egress，节省了 9 个中间步骤（总共 17 个）。
更重要的是：这个 datapath 绕过了 整个 Netfilter 框架（橘黄色的框们），Netfilter 在大流量情况下性能是很差的。



```shell
# 检查 BPF 文件系统
root@node1:~# mount | grep "/sys/fs/bpf"
bpf on /sys/fs/bpf type bpf (rw,nosuid,nodev,noexec,relatime,mode=700)
```
Calico 的 eBPF 数据平面是标准 Linux 数据平面（基于 iptables）的替代方案。
标准数据平面侧重于通过与 kube-proxy 和 iptables 规则进行交互来实现兼容性，而 eBPF 数据平面则侧重于性能、延迟和改善用户体验，并提供标准数据平面中无法实现的功能。
作为其中的一部分，eBPF 数据平面将 kube-proxy 替换为 eBPF 实现。主要的“用户体验”功能是在流量到达 NodePort 时保留来自集群外部的流量源 IP；这使服务器端日志和网络策略在该路径上更加有用。


新的数据平面与 Calico 的标准Linux网络数据平面相比

* 它可以扩展到更高的吞吐量。

* 它每 GBit 使用更少的 CPU。

* 它原生支持 Kubernetes 服务（不需要 kube-proxy）：

  - 减少数据包到服务的第一个数据包延迟。
  - 将外部客户端源 IP 地址一直保留到 pod。
  - 支持 DSR（Direct Server Return），实现更高效的服务路由。
  - 使用比 kube-proxy 更少的 CPU 来保持数据平面同步。



## 参考

- [k8s网络原理之Calico ](https://www.cnblogs.com/zhangpeiyao/p/18328708)
- [calico原理视频1-pod同主机和跨主机通讯](https://www.bilibili.com/video/BV1nfz3Y6EhJ/)
- [calico原理视频2-vxlan,bgp,ipip 抓包分析](https://www.bilibili.com/video/BV1jKiZYQEzf)
- [Calico的ip池对象ipPool](https://www.jianshu.com/p/dcad6d74e526)
- [Calico eBPF数据平面](https://luckymrwang.github.io/2022/05/12/Calico-eBPF%E6%95%B0%E6%8D%AE%E5%B9%B3%E9%9D%A2/)

