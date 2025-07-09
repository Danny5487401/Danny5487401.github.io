---
title: "Virtualization 虚拟化"
date: 2025-06-22T16:18:55+08:00
draft: true
---



简而言之，虚拟化是指对计算机资源的抽象。


计算机系统包括五个抽象层：硬件抽象层，指令集架构层，操作系统层，库函数层和应用程序层


## 基本概念


ring0是指CPU的运行级别，ring0是最高级别，ring1次之，ring2更次之.
操作系统（内核）的代码运行在最高运行级别ring0上，可以使用特权指令，控制中断、修改页表、访问设备等等


### QEMU（Quick Emulator）

{{<figure src="./qemu_structure.png#center" width=800px >}}

QEMU（Quick Emulator）:一种通用的开源计算机仿真器和虚拟器.

QEMU的优点在于其实纯软件实现的虚拟化模拟器，几乎可以模拟任何硬件设备，但是也正因为QEMU是纯软件实现的，因此所有指令都需要QEMU转手，因此会严重的降低性能。而可行的办法是通过配合KVM或者Xen来进行加速，目前肯定是以KVM为主。KVM 是硬件辅助的虚拟化技术，主要负责 比较繁琐的 CPU 和内存虚拟化，而 QEMU 则负责 I/O 虚拟化，两者合作各自发挥自身的优势，相得益彰。


#### QEMU虚拟机网络
虚拟机网络一般有三种模式如下，目前主要用的就是Bridge模式，所以这里主要是看看网桥的通讯过程。
- Host-Only： 这种模式下，VM只能与Host之间进行网络通讯，与网段内其它的机器处于隔离的状态
- Nat： 显然这种模式下，虚拟机要与网段内其它的机器或者外网的机器通讯时，必须要走nat
- Bridge：这种模式下，虚拟机相当于网段内一台独立的主机了，是目前应用最广泛的模式


## 虚拟机监视器（VMM）模型



### 裸机虚拟化模型（Hypervisor Model）

{{<figure src="./HypervisorModel.png#center" width=800px >}}

裸机虚拟化模型，也称为Type-I型虚拟化模型、


采用该模型的虚拟化平台有Wind River的Hypervisor 2.0和Helix Virtual Platform， VMware ESXi， Xen等。





### 宿主机虚拟化模型（Host-based Model）

{{<figure src="./Host-basedModel.png#center" width=800px >}}

宿主机虚拟化模型，也称为Type-II型虚拟化模型。

采用该模型的虚拟化平台有VMware Workstation和Xen等。



## 常用虚拟化技术


1. 硬件仿真技术
2. 全虚拟化技术（Full Virtualization）: 客户机操作系统运行在 hypervisor 之上，而 hypervisor 运行在裸机之上。客户机不知道它是在虚拟机还是物理机中运行，在全虚拟化中客户机不需要修改操作系统就可以直接运行。
3. 半虚拟化技术（Paravirtualization）: 客户机操作系统不仅需要感知其运行于 hypervisor 之上，还必须包含与 hypervisor 进行交互能够带来更高效率的代码
4. 硬件辅助虚拟化技术（Hardware-Assisted Virtualization)



### 半虚拟化

虚拟机内部设备驱动完全不知道自己处在虚拟化环境中，所以I/O操作会完整的走 虚拟机内核栈->QEMU->宿主机内核栈，产生很多VM Exit和VM Entry，导致性能很差。

virtio 并不是半虚拟化领域的唯一形式，Xen 也提供了类似的半虚拟化设备驱动，VMware 也提供了名为 Guest Tools 的半虚拟化架构。

Virtio方案旨在提高I/O性能。在改方案中虚拟机能够感知到自己处于虚拟化环境中，并且会加载相应的virtio总线驱动和virtio设备驱动，执行自己定义的 协议进行数据传输，减少VM Exit和VM Entry操作。


Virtio是一种前后端架构，包括前端驱动（Guest内部）、后端设备（QEMU设备）、传输协议（vring）。


## kvm(kernel base virtual machine基于内核的虚拟机)




## 参考
- [x86 体系结构的虚拟化](https://www.cnblogs.com/jmilkfan-fanguiju/p/11825029.html)