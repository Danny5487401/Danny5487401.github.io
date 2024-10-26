---
title: "Linux cgroups"
date: 2024-10-23T22:24:23+08:00
summary: " Cgroup（control group 控制组群）是内核提供的一种资源隔离的机制，可以实现对进程所使用的cpu、内存物理资源、及网络带宽等进行限制。还可以通过分配的CPU时间片数量及磁盘IO宽带大小控制任务运行的优先"
---

cgroups（Control Groups）最初叫 Process Container，由 Google 工程师（Paul Menage 和 Rohit Seth）于 2006 年提出，后来因为 Container 有多重含义容易引起误解，就在 2007 年更名为 Control Groups，并被整合进 Linux 内核。顾名思义就是把进程放到一个组里面统一加以控制


## 基本概念
- 任务（task）： 在cgroup中，任务相当于是一个进程，可以属于不同的cgroup组，但是所属的cgroup不能同属一层级
- 任务/控制组： 资源控制是以控制组的方式实现的，进程可以加入到指定的控制组中，类似于Linux中user和group的关系。控制组为树状结构的上下父子关系，子节点控制组会继承父节点控制组的属性，如资源配额等
- 层级（hierarchy）： 一个大的控制组群树，归属于一个层级中，不同的控制组以层级区分开
- 子系统（subsystem）： 一个的资源控制器，比如cpu子系统可以控制进程的cpu使用率，子系统需要附加（attach）到某个层级，然后该层级的所有控制组，均受到该子系统的控制

### 常见的子系统（subsystem）
```shell
ubuntu@VM-16-12-ubuntu:/sys/fs/cgroup$ ls
blkio  cpu  cpuacct  cpu,cpuacct  cpuset  devices  freezer  hugetlb  memory  net_cls  net_cls,net_prio  net_prio  perf_event  pids  rdma  systemd  unified
```
- cpu 子系统： 主要限制进程的 cpu 使用率。
- cpuacct 子系统： 可以统计 cgroups 中的进程的 cpu 使用报告。
- cpuset 子系统： 为cgroups中的进程分配单独的cpu节点或者内存节点。
- memory 子系统： 可以限制进程的 memory 使用量。
- blkio 子系统： 可以限制进程的块设备 io。比如物理驱动设备（包括磁盘、固态硬盘、USB 等）
- devices 子系统： 可以控制进程能够访问某些设备。
- net_cls 子系统： 可以标记cgroups 中进程的网络数据包，然后可以使用 tc 模块（traffic control）对数据包进行控制。
- freezer 子系统： 可以挂起或者恢复 cgroups 中的进程。
- ns 子系统： 可以使不同 cgroups 下面的进程使用不同的 namespace。
- freezer subsystem: 可以挂起或恢复 cgroup 中的 task
- perf_event subsystem :使用后使得 cgroup 中的 task 可以进行统一的性能测试


## 四大功能


1)资源限制：cgroups可以对进程组使用的资源总额进行限制。如设定应用运行时使用内存的上限，一旦超过这个配额就发出OOM（Out of Memory）。

cgroup 主要限制的资源是：

- CPU
- 内存
- 网络
- 磁盘 I/O

2)优先级分配：通过分配的CPU时间片数量及硬盘IO带宽大小，实际上就相当于控制了进程运行的优先级。

3)资源统计：cgroups可以统计系统的资源使用量，如CPU使用时长、内存用量等等，这个功能非常适用于计费。

4)进程控制：cgroups可以对进程组执行挂起、恢复等操作


## 组成


cgroup 主要有两个组成部分：

- core - 负责分层组织过程；
- controller - 通常负责沿层次结构分配特定类型的系统资源。

## cgroup 子资源参数详解

### blkio：限制设备 IO 访问
限制磁盘 IO 有两种方式：权重（weight）和上限（limit）。权重是给不同的应用（或者 cgroup）一个权重值，各个应用按照百分比来使用 IO 资源；上限是直接写死应用读写速率的最大值。

1. 设置 cgroup 访问设备的权重
2. 设置 cgroup 访问设备的限制


### cpu：限制进程组 CPU 使用

任务使用 CPU 资源有两种调度方式：完全公平调度（CFS，Completely Fair Scheduler）和 实时调度（RT，Real-Time Scheduler）。前者可以根据权重为任务分配响应的 CPU 时间片，后者能够限制使用 CPU 的核数。


#### CFS 调优参数

设置 CPU 数字的单位都是微秒（microsecond），用 us 表示
- cpu.cfs_quota_us：每个周期 cgroup 中所有任务能使用的 CPU 时间，默认为 -1，表示不限制 CPU 使用。需要配合 cpu.cfs_period_us 一起使用，一般设置为 100000（docker 中设置的值）
- cpu.cfs_period_us：每个周期中 cgroup 任务可以使用的时间周期，如果想要限制 cgroup 任务每秒钟使用 0.5 秒 CPU，可以在 cpu.cfs_quota_us 为 100000 的情况下把它设置为 50000。如果它的值比 cfs_quota_us 大，表明进程可以使用多个核 CPU，比如 200000 表示进程能够使用 2.0 核
- cpu.stat：CPU 使用的统计数据，nr_periods 表示已经过去的时间周期；nr_throttled 表示 cgroup 中任务被限制使用 CPU 的次数（因为超过了规定的上限）；throttled_time 表示被限制的总时间
- cpu.shares：cgroup 使用 CPU 时间的权重值。如果两个 cgroup 的权重都设置为 100，那么它们里面的任务同时运行时，使用 CPU 的时间应该是一样的；如果把其中一个权重改为 200，那么它能使用的 CPU 时间将是对方的两倍


#### RT 调度模式下的参数

- cpu.rt_period_us：设置一个周期时间，表示多久 cgroup 能够重新分配 CPU 资源
- cpu.rt_runtime_us：设置运行时间，表示在周期时间内 cgroup 中任务能访问 CPU 的时间。这个限制是针对单个 CPU 核数的，如果是多核，需要乘以对应的核数



### memory：限制内存使用

- memory.limit_in_bytes：cgroup 能使用的内存上限值，默认为字节；也可以添加 k/K、m/M 和 g/G 单位后缀。往文件中写入 -1 来移除设置的上限，表示不对内存做限制
- memory.memsw.limit_in_bytes：cgroup 能使用的内存加 swap 上限，用法和上面一样。写入 -1 来移除上限
- memory.failcnt：任务使用内存量达到 limit_in_bytes 上限的次数
- memory.memsw.failcnt：任务使用内存加 swap 量达到 memsw.limit_in_bytes 上限的次数
- memory.soft_limit_in_bytes：设置内存软上限。如果内存充足， cgroup 中的任务可以用到 memory.limit_in_bytes 设定的内存上限；当时当内存资源不足时，内核会让任务使用的内存不超过 soft_limit_in_bytes 中的值。文件内容的格式和 limit_in_bytes 一样
- memory.swappiness：设置内核 swap out 进程内存（而不是从 page cache 中回收页） 的倾向。默认值为 60，低于 60 表示降低倾向，高于 60 表示增加倾向；如果值高于 100，表示允许内核 swap out 进程地址空间的页。如果值为 0 表示倾向很低，而不是禁止该行为

### net_cls：为网络报文分类
net_cls 子资源能够给网络报文打上一个标记（classid），这样内核的 tc（traffic control）模块就能根据这个标记做流量控制。

net_cls.classid：包含一个整数值。从文件中读取是的十进制，写入的时候需要是十六进制。比如，0x100001 写入到文件中，读取的将是 1048577， ip 命令操作的形式为 10:1。

这个值的格式为 0xAAAABBBB，一共 32 位，分成前后两个部分，前置的 0 可以忽略，因此 0x10001 和 0x00010001 一样，表示为 1:1

## 容器中映射关系
### docker 中资源的表示
```shell
➜  ~ docker run --rm -d  --cpus=2 --memory=2g --name=2c2g redis:alpine 
e420a97835d9692df5b90b47e7951bc3fad48269eb2c8b1fa782527e0ae91c8e
➜  ~ cat /sys/fs/cgroup/system.slice/docker-`docker ps -lq --no-trunc`.scope/cpu.max
200000 100000
➜  ~ cat /sys/fs/cgroup/system.slice/docker-`docker ps -lq --no-trunc`.scope/memory.max
2147483648
➜  ~ 
➜  ~ docker run --rm -d  --cpus=0.5 --memory=0.5g --name=0.5c0.5g redis:alpine
8b82790fe0da9d00ab07aac7d6e4ef2f5871d5f3d7d06a5cdb56daaf9f5bc48e
➜  ~ cat /sys/fs/cgroup/system.slice/docker-`docker ps -lq --no-trunc`.scope/cpu.max       
50000 100000
➜  ~ cat /sys/fs/cgroup/system.slice/docker-`docker ps -lq --no-trunc`.scope/memory.max
536870912
```


### kubernetes 资源的表示
对于CPU
- resource.requests 经过转换之后会写入 cpu.share， 表示这个 cgroups最少可以使用的 CPU,在Kubernetes中一个CPU线程相当于1024 share
- resource.limits 则通过 cpu.cfs_quota_us和cpu.cfs_period_us 两个文件来控制，表示cgroups最多可以使用的 CPU。如果 cgroups 中任务在每 1 秒内有 0.2 秒，可对单独 CPU 进行存取，可以将 cpu.cfs_quota_us 设定为 200000，cpu.cfs_period_us 设定为 1000000。



对于内存

```shell
$ ls -l /sys/fs/cgroup/memory/kubepods/burstable/podfbc202d3-da21-11e8-ab5e-42010a80014b/0a1b22ec1361a97c3511db37a4bae932d41b22264e5b97611748f8b662312574
...
-rw-r--r-- 1 root root 0 Oct 27 19:53 memory.limit_in_bytes
-rw-r--r-- 1 root root 0 Oct 27 19:53 memory.soft_limit_in_bytes
```



## cgroup v1 与 cgroup v2

最初 cgroups 的版本被称为 v1，这个版本的 cgroups 设计并不友好，理解起来非常困难。后续的开发工作由 Tejun Heo 接管，他重新设计并重写了 cgroups，新版本被称为 v2，并首次出现在 kernel 4.5 版本。


```shell
# 查看 cgroup 版本

# v1 版本
ubuntu@VM-16-12-ubuntu:/sys/fs/cgroup$ mount |grep cgroup
tmpfs on /sys/fs/cgroup type tmpfs (ro,nosuid,nodev,noexec,mode=755)
cgroup2 on /sys/fs/cgroup/unified type cgroup2 (rw,nosuid,nodev,noexec,relatime,nsdelegate)
cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
cgroup on /sys/fs/cgroup/hugetlb type cgroup (rw,nosuid,nodev,noexec,relatime,hugetlb)
cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,perf_event)
cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (rw,nosuid,nodev,noexec,relatime,cpu,cpuacct)
cgroup on /sys/fs/cgroup/pids type cgroup (rw,nosuid,nodev,noexec,relatime,pids)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,net_cls,net_prio)
cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,blkio)
cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,freezer)
cgroup on /sys/fs/cgroup/memory type cgroup (rw,nosuid,nodev,noexec,relatime,memory)
cgroup on /sys/fs/cgroup/rdma type cgroup (rw,nosuid,nodev,noexec,relatime,rdma)

# v2 版本
$ mount|grep cgroup
cgroup2 on /sys/fs/cgroup type cgroup2 (rw,nosuid,nodev,noexec,relatime,nsdelegate)

```



Kubernetes 自 v1.25 起 cgroup2 特性正式 stable



## 工具

```shell
$ sudo apt-get install cgroup-tools
```
- 查看所有的 cgroup：lscgroup
- 查看所有支持的子系统：lssubsys -a
- 查看所有子系统挂载的位置： lssubsys –m
- 查看单个子系统（如 memory）挂载位置：lssubsys –m memory


## 参考

- [一篇搞懂容器技术的基石： cgroup](https://zhuanlan.zhihu.com/p/434731896)
- [docker 容器基础技术：linux cgroup 简介](https://cizixs.com/2017/08/25/linux-cgroup/)
- [详解Cgroup V2](https://zorrozou.github.io/docs/%E8%AF%A6%E8%A7%A3Cgroup%20V2.html)