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

#### eBPF应用
- bcc（https://github.com/iovisor/bcc）: 提供一套开发工具和脚本。


#### eBPF的实现原理

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
```shell
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

3. 安全和其他

lsm，用于安全.



#### 动态追踪的事件源
动态追踪所使用的事件源，可以分为静态探针、动态探针以及硬件事件等三类

{{<figure src="./perf_event.png#center" width=800px >}}
- 硬件事件通常由性能监控计数器 PMC（Performance Monitoring Counter）产生，包括了各种硬件的性能情况，比如 CPU 的缓存、指令周期、分支预测等等。
- 静态探针，是指事先在代码中定义好，并编译到应用程序或者内核中的探针。这些探针只有在开启探测功能时，才会被执行到；未开启时并不会执行。常见的静态探针包括内核中的跟踪点（tracepoints）和 USDT（Userland Statically Defined Tracing）探针。
- 动态探针，则是指没有事先在代码中定义，但却可以在运行时动态添加的探针，比如函数的调用和返回等。动态探针支持按需在内核或者应用程序中添加探测点，具有更高的灵活性。常见的动态探针有两种，即用于内核态的 kprobes 和用于用户态的 uprobes。


## 组件
https://docs.cilium.io/en/v1.8/concepts/overview/


{{<figure src="./cilium-component.png#center" width=800px >}}


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

Cluster Scope 模式
```shell
(⎈|kubeasz-test:nfs)➜  ~ kubectl get ciliumnode
NAME    CILIUMINTERNALIP   INTERNALIP    AGE
node1   10.233.66.89       172.16.7.30   24d
node2   10.233.64.85       172.16.7.31   24d
node3   10.233.65.143      172.16.7.32   24d
node4   10.233.68.229      172.16.7.33   24d
node5   10.233.67.96       172.16.7.34   24d
node6   10.233.69.139      172.16.7.35   23d
```


## 参考
- [深入浅出eBPF｜你要了解的7个核心问题](https://mp.weixin.qq.com/s/Xr8ECrS_fR3aCT1vKJ9yIg)
- [BPF BTF 详解](https://www.cnblogs.com/linhaostudy/p/18060055)