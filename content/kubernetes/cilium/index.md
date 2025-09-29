---
title: "Cilium"
date: 2025-08-29T23:04:45+08:00
summary: "ebpf 在 cilium 中的使用"
categories:
  - cni
  - cilium
tags:
  - cilium
---


## 基本知识

### bpftool

BPFTOOL 是linux内核自带的用于对eBPF程序和eBPF map进行检查与操作的工具软件。


#### bpftool的常用功能
sudo bpftool prog list：
显示所有已经被load到系统里的eBPF程序的信息列表，除了显示功能外，还支持dump等功能，可以通过man bpftool prog来查看具体支持的功能。

bpftool net list
显示内核网络子系统里的eBPF程序，除了显示功能外，还支持其它功能，可以通过man bpftool net来查看具体支持的功能。

bpftool link list
显示所有激活的链接，除了显示功能外，还支持其它功能，可以通过man bpftool link来查看具体支持的功能。

bpftool perf list
显示系统里所有raw_tracepoint, tracepoint, kprobe attachments ，除了显示功能外，还支持其它功能，可以通过man bpftool perf来查看具体支持的功能。

bpftool btf list
显示所有BPF Type Format (BTF)数据 ，除了显示功能外，还支持其它功能，可以通过man bpftool btf来查看具体支持的功能。

bpftool map list
显示系统内已经载入的所有bpf map数据，除了显示功能外，还支持其它功能，可以通过man bpftool map来查看具体支持的功能。



bpftool feature probe dev eth0: 查看eth0支持的eBPF特性


```shell
root@node5:~# bpftool feature probe | grep map_type
eBPF map_type hash is available
eBPF map_type array is available
eBPF map_type prog_array is available
eBPF map_type perf_event_array is available
eBPF map_type percpu_hash is available
eBPF map_type percpu_array is available
eBPF map_type stack_trace is available
eBPF map_type cgroup_array is available
eBPF map_type lru_hash is available
eBPF map_type lru_percpu_hash is available
eBPF map_type lpm_trie is available
eBPF map_type array_of_maps is available
eBPF map_type hash_of_maps is available
eBPF map_type devmap is available
eBPF map_type sockmap is available
eBPF map_type cpumap is available
eBPF map_type xskmap is available
eBPF map_type sockhash is available
eBPF map_type cgroup_storage is available
eBPF map_type reuseport_sockarray is available
eBPF map_type percpu_cgroup_storage is available
eBPF map_type queue is available
eBPF map_type stack is available
eBPF map_type sk_storage is available
eBPF map_type devmap_hash is available
eBPF map_type struct_ops is available
eBPF map_type ringbuf is available
eBPF map_type inode_storage is available
eBPF map_type task_storage is available
eBPF map_type bloom_filter is available
eBPF map_type user_ringbuf is available
eBPF map_type cgrp_storage is available
```


### 容器的网络发展路线

基于 Linux bridge 以及基于 ovs 实现的 overlay 的网络。

基于 bgp/hostgw 等基于路由能力的网络。

基于 macvlan，ipvlan 等偏物理网络的 underlay 的网络。

基于 Kernel 的 eBPF 的技术实现的网络。

基于 dpdk/sriov/vpp/virtio-user/offload/af-xdp 实现的用户态的网络

### BTF（BPF Type Format）
BTF（BPF Type Format）是内嵌在BPF（Berkeley Packet Filter）程序中的数据结构描述信息.

BTF是为了实现更复杂的eBPF程序而设计的。其提供了一种机制，通过它可以将编程时使用的数据结构（如C语言中的结构体、联合体、枚举等）的信息嵌入到eBPF程序中。这样做的主要目的是为了让eBPF程序在运行时能够具有类型安全（Type Safety），同时也便于内核和用户空间的程序理解和操作这些数据结构。
在eBPF程序开发过程中，用户通常会在用户空间编写C代码，然后使用特定的编译器（如clang）编译这些代码为eBPF字节码。
由于C程序中定义的复杂数据结构信息在编译为eBPF字节码过程中会丢失，因此BTF被设计来保留这些信息。
当eBPF程序加载到内核时，BTF信息可以被内核使用，以确保程序操作的数据结构与内核预期的一致，从而保证程序的正确运行。


BTF 规范包含两个部分：

- BTF 内核 API
- BTF ELF 文件格式

内核 API 是用户空间和内核之间的约定。内核在使用之前使用 BTF 信息对其进行验证。ELF 文件格式是一个用户空间 ELF 文件和 libbpf 加载器之间的约定。

### eBPF（extended BPF）
eBPF 是嵌入在 Linux 内核中的虚拟机。它允许将小程序加载到内核中，并附加到钩子上，当某些事件发生时会触发这些钩子。这允许（有时大量）定制内核的行为。

{{<figure src="./ebpf_structure.png#center" width=800px >}}

eBPF 的执行需要三步：

1. 从用户跟踪程序生成 BPF 字节码；

2. 加载到内核中运行；

3. 向用户空间输出结果。

#### eBPF 应用
- bcc（https://github.com/iovisor/bcc）: 提供一套开发工具和脚本。


#### eBPF 的实现原理

{{<figure src="./ebpf_principle.png#center" width=800px >}}

1、BPF Verifier（验证器）

确保 eBPF 程序的安全。验证器会将待执行的指令创建为一个有向无环图（DAG），确保程序中不包含不可达指令


2、BPF JIT

将 eBPF 字节码编译成本地机器指令，以便更高效地在内核中执行


3、多个 64 位寄存器、一个程序计数器和一个 512 字节的栈组成的存储模块

用于控制eBPF程序的运行，保存栈数据，入参与出参


4、BPF Helpers（辅助函数）

提供了一系列用于 eBPF 程序与内核其他模块进行交互的函数。这些函数并不是任意一个 eBPF 程序都可以调用的，具体可用的函数集由 BPF 程序类型决定。


5、BPF Map & context

用于提供大块的存储，这些存储可被用户空间程序用来进行访问，进而控制 eBPF 程序的运行状态。

#### eBPF 程序分类和使用场景
eBPF 程序类型决定了一个 eBPF 程序可以挂载的事件类型和事件参数，这也就意味着，内核中不同事件会触发不同类型的 eBPF 程序。

根据内核头文件 include/uapi/linux/bpf.h 中 bpf_prog_type 的定义，Linux 内核 v5.13 已经支持 30 种不同类型的 eBPF 程序（
```shell
# 查询当前系统支持的程序类型
root@node5:~# bpftool feature probe | grep program_type
eBPF program_type socket_filter is available
eBPF program_type kprobe is available
eBPF program_type sched_cls is available
eBPF program_type sched_act is available
eBPF program_type tracepoint is available
eBPF program_type xdp is available
eBPF program_type perf_event is available
eBPF program_type cgroup_skb is available
eBPF program_type cgroup_sock is available
eBPF program_type lwt_in is available
eBPF program_type lwt_out is available
eBPF program_type lwt_xmit is available
eBPF program_type sock_ops is available
eBPF program_type sk_skb is available
eBPF program_type cgroup_device is available
eBPF program_type sk_msg is available
eBPF program_type raw_tracepoint is available
eBPF program_type cgroup_sock_addr is available
eBPF program_type lwt_seg6local is available
eBPF program_type lirc_mode2 is NOT available
eBPF program_type sk_reuseport is available
eBPF program_type flow_dissector is available
eBPF program_type cgroup_sysctl is available
eBPF program_type raw_tracepoint_writable is available
eBPF program_type cgroup_sockopt is available
eBPF program_type tracing is available
eBPF program_type struct_ops is available
eBPF program_type ext is available
eBPF program_type lsm is available
eBPF program_type sk_lookup is available
eBPF program_type syscall is available
eBPF program_type netfilter is available
```


主要是分为3大使用场景：

1. 跟踪

tracepoint, kprobe, perf_event等，主要用于从系统中提取跟踪信息，进而为监控、排错、性能优化等提供数据支撑。

2. 网络

xdp, sock_ops, cgroup_sock_addr , sk_msg等，主要用于对网络数据包进行过滤和处理，进而实现网络的观测、过滤、流量控制以及性能优化等各种丰富的功能，这里可以丢包，重定向。

根据事件触发位置的不同，网络类 eBPF 程序又可以分为 XDP（eXpress Data Path，高速数据路径）程序、TC（Traffic Control，流量控制）程序、套接字程序以及 cgroup 程序，

3. 安全和其他

lsm，用于安全.

##### kprobe

kprobe 允许在内核函数的入口处插入一个断点。
当 CPU 执行到这个位置时，会触发一个陷入（trap），CPU 切换到你预先定义的处理函数（probe handler）执行。
这个处理函数可以访问和修改内核的状态，包括 CPU 寄存器、内核栈、全局变量等。执行完处理函数后，CPU 会返回到断点处，继续执行原来的内核代码.


kretprobe 允许在内核函数返回时插入探测点。这对于追踪函数的返回值或者函数的执行时间非常有用。
kretprobe 的工作原理是在函数的返回地址前插入一个断点。当函数返回时，CPU 会先跳转到你的处理函数，然后再返回到原来的地址。


也不是所有的函数都是支持kprobe机制，可以通过cat /sys/kernel/debug/tracing/available_filter_functions查看当前系统支持的函数


##### tracepoint
tracepoints 是 Linux 内核中的一种机制，它们是在内核源代码中预定义的钩子点，用于插入用于跟踪和调试的代码

tracepoints 是在内核源代码中预定义的，提供了稳定的 ABI。即使内核版本升级，tracepoint 的名称和参数也不会改变，这使得开发者可以编写依赖于特定 tracepoint 的代码，而不用担心在未来的内核版本中这些 tracepoint 会改变。

tracepoints 对性能的影响非常小。只有当 tracepoint 被激活，并且有一个或多个回调函数（也称为探针）附加到它时，它才会消耗 CPU 时间。这使得 tracepoints 非常适合在生产环境中使用

##### socket

socket 就是和网络包相关的事件，常见的网络包处理函数有sock_filter和sockops。


其中和socket相关的事件有：

* BPF_PROG_TYPE_SOCKET_FILTER: 这种类型的 eBPF 程序设计用于处理网络数据包
* BPF_PROG_TYPE_SOCK_OPS 和 BPF_PROG_TYPE_SK_SKB: 这两种类型的 eBPF 程序设计用于处理 socket 操作和 socket 缓冲区中的数据包
* BPF_PROG_TYPE_SK_MSG：用于处理 socket 消息

##### tc (traffic control 流量控制)

Linux 流量控制通过网卡队列、排队规则、分类器、过滤器以及执行器等，实现了对网络流量的整形调度和带宽控制。

子系统包括 qdisc（queueing discipline 队列规则）、class、classifier（filter）、action等概念，eBPF程序可以作为classifier被挂载

TC 模块实现流量控制功能使用的排队规则分为两类：无分类排队规则、分类排队规则。无分类排队规则相对简单，而分类排队规则则引出了分类和过滤器等概念，使其流量控制功能增强


##### xdp（eXpress Data Path）
XDP机制的主要目标是在接收数据包时尽早处理它们，以提高网络性能和降低延迟。它通过将eBPF程序附加到网络设备的接收路径上来实现这一目标。


##### uprobe(User Probe)

利用了Linux内核中的ftrace（function trace）框架来实现。通过uprobe，可以在用户空间程序的指定函数入口或出口处插入探测点，当该函数被调用或返回时，可以触发事先定义的处理逻辑。


#### 动态追踪的事件源
动态追踪所使用的事件源，可以分为静态探针、动态探针以及硬件事件等三类

{{<figure src="./perf_event.png#center" width=800px >}}
- 硬件事件通常由性能监控计数器 PMC（Performance Monitoring Counter）产生，包括了各种硬件的性能情况，比如 CPU 的缓存、指令周期、分支预测等等。
- 静态探针，是指事先在代码中定义好，并编译到应用程序或者内核中的探针。这些探针只有在开启探测功能时，才会被执行到；未开启时并不会执行。常见的静态探针包括内核中的跟踪点（tracepoints）和 USDT（Userland Statically Defined Tracing）探针。
- 动态探针，则是指没有事先在代码中定义，但却可以在运行时动态添加的探针，比如函数的调用和返回等。动态探针支持按需在内核或者应用程序中添加探测点，具有更高的灵活性。常见的动态探针有两种，即用于内核态的 kprobes 和用于用户态的 uprobes。


## 安装要求
https://docs.cilium.io/en/v1.8/operations/system_requirements/#features-kernel-matrix




## 组件
https://docs.cilium.io/en/v1.8/concepts/overview/


{{<figure src="./cilium-component.png#center" width=800px >}}


### 整体架构：控制平面与数据平面


数据平面 (Data Plane)：数据平面的核心职责是高效处理实际的网络流量。在 Cilium 中，数据平面主要由运行在每个 Kubernetes 节点（宿主机）Linux 内核中的 eBPF 程序构成。
这些 eBPF 程序负责处理 L3/L4 层的网络连接、执行网络策略、进行负载均衡等。对于 L7 层的策略执行（例如 HTTP、Kafka 策略），Cilium 的数据平面还会集成一个 Envoy 代理。数


控制平面 (Control Plane)：控制平面的主要职责是管理和配置数据平面组件。Cilium 的控制平面主要由运行在每个 Kubernetes 节点上的 cilium-agent 守护进程实现。
每个 cilium-agent 都是一个独立的控制平面实例，它连接到 Kubernetes API 服务器，监视集群状态和配置变化（例如 Pod 的创建与删除、网络策略的更新等），并将这些高级配置翻译成具体的 eBPF 程序和规则，下发到其所在节点的数据平面执行。
此外，cilium-agent 还会将其节点上创建的端点（Endpoints）或身份（Identities）等信息以 Kubernetes 自定义资源（CRD）的形式写回 Kubernetes API。


### cilium operator


### Cilium Agent
Cilium Agent 以 daemonset 的形式运行，因此 Kubernetes 集群的每个节点上都有一个 Cilium agent pod 在运行。该 agent 执行与 Cilium 相关的大部分工作：

- 与 Kubernetes API 服务器交互，同步集群状态
- 与 Linux kernel 交互--加载 eBPF 程序并更新 eBPF map
- 通过文件系统 socket 与 Cilium CNI 插件可执行文件交互，以获得新调度工作负载的通知
- 根据要求的网络策略，按需创建 DNS 和 Envoy Proxy 服务器
- 启用 Hubble 时创建 Hubble gRPC 服务

### Cilium CNI Plugin
由 Kubelet 调用在 Pod 的网络命名空间中完成容器网络的管理，包括容器网卡的创建，网关的设置，路由的设置等，
因为依赖 eBPF 的网络能力，这里还会调用 Cilium Agent 的接口，完成 Pod 所需要的 eBPF 程序的编译，挂载，配置，以及和 Pod 相关的 eBPF Maps 的创建和管理。


### Hubble Server
主要负责完成 Cilium 网络方案中的观测数据的服务。在 Cilium 运行的数据路径中，会对数据包的处理过程进行记录，最后统一由 Hubble Server 来完成输出，同时提供了 API 来访问这些观测数据

### Hubble UI
用于展示 Hubble Server 收集的观测数据，这里会直接连接到 Relay 去查询数据。


### Cilium CLI (cilium 和 cilium-dbg)

cilium CLI：这是一个用于快速安装、管理和故障排除运行 Cilium 的 Kubernetes 集群的命令行工具。用户可以使用它来安装 Cilium、检查 Cilium 安装状态、启用/禁用特性（如 ClusterMesh、Hubble）等。
```shell
root@node1:~# cilium --help
CLI to install, manage, & troubleshooting Cilium clusters running Kubernetes.

#  ...

Usage:
  cilium [flags]
  cilium [command]

Available Commands:
  bgp          Access to BGP control plane
  clustermesh  Multi Cluster Management
  completion   Generate the autocompletion script for the specified shell
  config       Manage Configuration
  connectivity Connectivity troubleshooting
  context      Display the configuration context
  encryption   Cilium encryption
  help         Help about any command
  hubble       Hubble observability
  install      Install Cilium in a Kubernetes cluster using Helm
  status       Display status
  sysdump      Collects information required to troubleshoot issues with Cilium and Hubble
  uninstall    Uninstall Cilium using Helm
  upgrade      Upgrade a Cilium installation a Kubernetes cluster using Helm
  version      Display detailed version information
```

cilium-dbg (Debug Client)：这是一个与 Cilium Agent 一同安装在每个节点上的命令行工具。它通过与同一节点上运行的 Cilium Agent 的 REST API 交互，允许检查本地 Agent 的状态和各种内部信息。此外，它还提供了直接访问 eBPF 映射以验证其状态的工具。需要注意的是，这个内嵌于 Agent 的 cilium-dbg 与用于集群管理的 cilium CLI 是不同的工具。

```shell
root@node2:/home/cilium# cilium-dbg --help
CLI for interacting with the local Cilium Agent

Usage:
  cilium-dbg [command]

Available Commands:
  bgp          Access to BGP control plane
  bpf          Direct access to local BPF maps
  build-config Resolve all of the configuration sources that apply to this node
  cgroups      Cgroup metadata
  cleanup      Remove system state installed by Cilium at runtime
  completion   Output shell completion code
  config       Cilium configuration options
  debuginfo    Request available debugging information from agent
  encrypt      Manage transparent encryption
  endpoint     Manage endpoints
  envoy        Manage Envoy Proxy
  fqdn         Manage fqdn proxy
  help         Help about any command
  identity     Manage security identities
  ip           Manage IP addresses and associated information
  kvstore      Direct access to the kvstore
  lrp          Manage local redirect policies
  map          Access userspace cached content of BPF maps
  metrics      Access metric status
  monitor      Display BPF program events
  node         Manage cluster nodes
  nodeid       List node IDs and associated information
  policy       Manage security policies
  prefilter    Manage XDP CIDR filters
  preflight    Cilium upgrade helper
  recorder     Introspect or mangle pcap recorder
  service      Manage services & loadbalancers
  statedb      Inspect StateDB
  status       Display status of daemon
  troubleshoot Run troubleshooting utilities to check control-plane connectivity
  version      Print version information
```

## 目录结构说明

bpf : eBPF datapath收发包路径相关代码，eBPF源码存放目录。

daemon : 各node节点上运行的cilium-agent代码，也是跟内核做交互，处理eBPF相关的核心代码。

pkg : 项目依赖的各种包。
    * pkg/bpf ： eBPF运行时交互的抽象层
    * pkg/datapath datapath交互的抽象层
    * pkg/maps eBPF map的描述定义目录
    * pkg/monitor eBPF datapath 监控器抽


```shell
root@node1:/opt/cilium# tree -L 1  bpf/
bpf/
├── bpf_alignchecker.c # C与Go的消息结构体格式校验
├── bpf_host.c  # 物理层的网卡tc ingress\egress相关过滤器
├── bpf_lxc.c # 容器上的网络环境、网络流量管控等
├── bpf_network.c # 网络控制相关
├── bpf_overlay.c # overlay 控制代码
├── bpf_sock.c # sock控制相关，包含流量大小控制、TCP状态变化控制
├── bpf_xdp.c # DP层控制相关
├── complexity-tests
├── COPYING
├── custom
├── ep_config.h
├── filter_config.h
├── include
├── lib
├── LICENSE.BSD-2-Clause
├── LICENSE.GPL-2.0
├── Makefile
├── Makefile.bpf
├── netdev_config.h
├── node_config.h
├── source_names_to_ids.h
└── tests
```


## ipam
https://docs.cilium.io/en/v1.8/concepts/networking/ipam/


### cluster-pool 模式( 默认)
https://docs.cilium.io/en/v1.8/concepts/networking/ipam/cluster-pool/

cluster-pool 模式：为每一个 node 分配 pod cidr 交给部署的 cilium-operator 来做.

这个 PodCIDRs 的分配与 Flannel 中的 PodCIDRs 分配 的不同：后者使用 v1.Node 上由 Kubernetes 分配的 podCIDR，这个与 Cilium 的 Kubernetes Host Scope 类似；
而 Cilium 的 cluster-scope 使用的 PodCIDRs 则是由 Cilium operator 来分配和管理的，operator 将分配的 PodCIDR 附加在 v2.CiliumNode 上

```shell
(⎈|kubeasz-test:nfs)➜  ~ kubectl get ciliumnode
NAME    CILIUMINTERNALIP   INTERNALIP    AGE
node1   10.233.66.89       172.16.7.30   24d
node2   10.233.64.85       172.16.7.31   24d
node3   10.233.65.143      172.16.7.32   24d
node4   10.233.68.229      172.16.7.33   24d
node5   10.233.67.96       172.16.7.34   24d
node6   10.233.69.139      172.16.7.35   23d

(⎈|kubeasz-test:monitoring)➜  ~ kubectl get cn node1 -o yaml
apiVersion: cilium.io/v2
kind: CiliumNode
metadata:
  creationTimestamp: "2025-08-20T07:05:10Z"
  generation: 33
  labels:
    beta.kubernetes.io/arch: amd64
    beta.kubernetes.io/os: linux
    kubernetes.io/arch: amd64
    kubernetes.io/hostname: node1
    kubernetes.io/os: linux
    node-role.kubernetes.io/control-plane: ""
    node.kubernetes.io/exclude-from-external-load-balancers: ""
    openebs.io/nodename: node1
  name: node1
  ownerReferences:
  - apiVersion: v1
    kind: Node
    name: node1
    uid: add1b2b6-5a4d-4882-9c52-be844c221253
  resourceVersion: "13826717"
  uid: 34624aac-196e-4e8a-a9d7-c8f0d3813f0e
spec:
  addresses:
  - ip: 172.16.7.30
    type: InternalIP
  - ip: 10.233.66.89
    type: CiliumInternalIP
  alibaba-cloud: {}
  azure: {}
  bootid: 5c26c664-8df0-4385-90f6-ace4c9cc9e80
  encryption: {}
  eni: {}
  health:
    ipv4: 10.233.66.85
  ingress: {}
  ipam:
    podCIDRs:
    - 10.233.66.0/24
    pools: {}
status:
  alibaba-cloud: {}
  azure: {}
  eni: {}
  ipam:
    operator-status: {}
```


### crd

https://docs.cilium.io/en/v1.8/concepts/networking/ipam/crd/


## 参考
- [深入浅出eBPF｜你要了解的7个核心问题](https://mp.weixin.qq.com/s/Xr8ECrS_fR3aCT1vKJ9yIg)
- [BPF BTF 详解](https://www.cnblogs.com/linhaostudy/p/18060055)
- [eBPF中常见的事件类型](https://blog.spoock.com/2023/08/19/eBPF-Hook/)
- [Cilium datapath梳理](https://rexrock.github.io/post/cilium2/)
- [eBPF 开源项目 Cilium 深入分析](https://blog.csdn.net/weixin_39145568/article/details/147960141)