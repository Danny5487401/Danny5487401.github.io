---
title: "Virtualization 虚拟化"
date: 2025-06-22T16:18:55+08:00
summary: 常用虚拟化技术,I/O 虚拟化
categories:
  - virtualization

---


虚拟化是指对计算机资源的抽象。


计算机系统包括五个抽象层：硬件抽象层，指令集架构层，操作系统层，库函数层和应用程序层


## 基本概念


ring0是指CPU的运行级别，ring0是最高级别，ring1次之，ring2更次之.
操作系统（内核）的代码运行在最高运行级别ring0上，可以使用特权指令，控制中断、修改页表、访问设备等等


### VT-d(intel Virtualization Technology for Direct I/O 直接I/O虚拟化技术)

{{<figure src="./vt-d.png#center" width=800px >}}

实现主要是通过在硬件上引入重定向单元，该硬件重定向单元用于对I/O子系统的DMA操作和中断传递进行重定向，从而辅助VMM（Virtual Machine Monitor）实现I/O子系统的虚拟化。




### QEMU（Quick Emulator）

{{<figure src="./qemu_structure.png#center" width=800px >}}

[QEMU](https://www.qemu.org/docs/master/about/index.html) :一种通用的开源计算机仿真器和虚拟器.

QEMU的优点在于其实纯软件实现的虚拟化模拟器，几乎可以模拟任何硬件设备，但是也正因为QEMU是纯软件实现的，因此所有指令都需要QEMU转手，因此会严重的降低性能。
而可行的办法是通过配合KVM或者Xen来进行加速，目前肯定是以KVM为主。
KVM 是硬件辅助的虚拟化技术，主要负责 比较繁琐的 CPU 和内存虚拟化，而 QEMU 则负责 I/O 虚拟化，两者合作各自发挥自身的优势，相得益彰。
由于qemu模拟io设备效率不高的原因，现在常常采用半虚拟化的virtio方式来虚拟IO设备。


#### QEMU 虚拟机网络
虚拟机网络一般有三种模式如下，目前主要用的就是Bridge模式，所以这里主要是看看网桥的通讯过程。
- Host-Only： 这种模式下，VM只能与Host之间进行网络通讯，与网段内其它的机器处于隔离的状态
- Nat： 显然这种模式下，虚拟机要与网段内其它的机器或者外网的机器通讯时，必须要走nat
- Bridge：这种模式下，虚拟机相当于网段内一台独立的主机了，是目前应用最广泛的模式


## VMM（ Virtual Machine Monitor 虚拟机监视器）

Hypervisor: 一种运行在基础物理服务器和操作系统之间的中间软件层,可允许多个操作系统和应用共享硬件。
也可叫做VMM（ virtual machine monitor ），即虚拟机监视器。


### 裸机虚拟化模型（Hypervisor Model）

{{<figure src="./HypervisorModel.png#center" width=800px >}}

裸机虚拟化模型，也称为Type-I型虚拟化模型.

采用该模型的虚拟化平台有Wind River的Hypervisor 2.0和Helix Virtual Platform， VMware ESXi， Xen等。




### 宿主机虚拟化模型（Host-based Model）

{{<figure src="./Host-basedModel.png#center" width=800px >}}

宿主机虚拟化模型，也称为Type-II型虚拟化模型。

采用该模型的虚拟化平台有VMware Workstation和Xen等。



## 常用虚拟化技术


1. 硬件仿真技术
2. 全虚拟化技术（Full Virtualization）: 客户机操作系统运行在 hypervisor 之上，而 hypervisor 运行在裸机之上。客户机不知道它是在虚拟机还是物理机中运行，在全虚拟化中客户机不需要修改操作系统就可以直接运行。
3. 半虚拟化技术（Para Virtualization）: 客户机操作系统不仅需要感知其运行于 hypervisor 之上，还必须包含与 hypervisor 进行交互能够带来更高效率的代码
4. 硬件辅助虚拟化技术（Hardware-Assisted Virtualization)



### 半虚拟化

虚拟机内部设备驱动完全不知道自己处在虚拟化环境中，所以I/O操作会完整的走 虚拟机内核栈->QEMU->宿主机内核栈，产生很多VM Exit和VM Entry，导致性能很差。

virtio 并不是半虚拟化领域的唯一形式，Xen 也提供了类似的半虚拟化设备驱动，VMware 也提供了名为 Guest Tools 的半虚拟化架构。





## kvm(kernel base virtual machine基于内核的虚拟机)
Kernel-Based Virtual Machine 基于内核的虚拟机，是Linux内核的一个可加载模块，通过调用Linux本身内核功能，实现对CPU的底层虚拟化和内存的虚拟化，使Linux内核成为虚拟化层，需要x86架构的，支持虚拟化功能的硬件支持（比如Intel-VT，AMD-V），是一种全虚拟化架构。


KVM是linux内核的模块，它需要CPU的支持，采用硬件辅助虚拟化技术Intel-VT，AMD-V，内存的相关如Intel的EPT和AMD的RVI技术，Guest OS的CPU指令不用再经过Qemu转译，直接运行，大大提高了速度，KVM通过/dev/kvm暴露接口，用户态程序可以通过ioctl函数来访问这个接口。


## I/O 虚拟化

网络包的接收与发送，都是典型的生产者-消费者模型，简单来说，CPU会在内存中维护两个ring-buffer，分别代表RX和TX，ring-buffer中存放的是描述符，描述符里包含了一个网络包的信息，包括了网络包地址、长度、状态等信息；
ring-buffer有头尾两个指针，
- 发送端为：TDH(Transmit Descriptor Head)和TDT(Transmit Descriptor Tail)，
- 接收端为：RDH(Receive Descriptor Head)和RDT(Receive Descriptor Tail)，


双倍数据率同步动态随机存储器( Double Data Rate Synchronous Dynamic Random Access Memory，简称DDR SDRAM或DDR), 一种高级类型的SDRAM，允许每个时钟周期传输两倍的内存。

{{<figure src="./io_evolution.png#center" width=800px >}}

I/O 虚拟化经历了从 I/O 全虚拟化、I/O 半虚拟化、硬件直通再到 vDPA 加速 Vhost-user 技术的演进。

### 全虚拟化方案

通过软件来模拟网卡，Qemu+KVM的方案如下图.
{{<figure src="./full-virtualization-process.png#center" width=800px >}}
```shell
root@node4:~# lspci -vv -s 02:00.0
02:00.0 Ethernet controller: Intel Corporation 82545EM Gigabit Ethernet Controller (Copper) (rev 01)
	DeviceName: Ethernet0
	Subsystem: VMware PRO/1000 MT Single Port Adapter
	Physical Slot: 32
	Control: I/O+ Mem+ BusMaster+ SpecCycle- MemWINV+ VGASnoop- ParErr- Stepping- SERR+ FastB2B- DisINTx-
	Status: Cap+ 66MHz+ UDF- FastB2B- ParErr- DEVSEL=medium >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
	Latency: 0 (63750ns min), Cache Line Size: 64 bytes
	Interrupt: pin A routed to IRQ 18
	Region 0: Memory at fd5c0000 (64-bit, non-prefetchable) [size=128K]
	Region 2: Memory at fdff0000 (64-bit, non-prefetchable) [size=64K]
	Region 4: I/O ports at 2000 [size=64]
	Expansion ROM at fd500000 [virtual] [disabled] [size=64K]
	Capabilities: [dc] Power Management version 2
		Flags: PMEClk- DSI+ D1- D2- AuxCurrent=0mA PME(D0+,D1-,D2-,D3hot+,D3cold+)
		Status: D0 NoSoftRst- PME-Enable- DSel=0 DScale=1 PME-
	Capabilities: [e4] PCI-X non-bridge device
		Command: DPERE- ERO+ RBC=512 OST=1
		Status: Dev=ff:1f.0 64bit+ 133MHz+ SCD- USC- DC=simple DMMRBC=2048 DMOST=1 DMCRS=16 RSCEM- 266MHz- 533MHz-
	Kernel driver in use: e1000
	Kernel modules: e1000
```
Qemu中，设备的模拟称为前端，比如e1000，前端与后端通信，后端再与底层通信，我们来分别看看发送和接收处理的流程.

发送：

- Guest OS在准备好网络包数据以及描述符资源后，通过写TDT寄存器，触发VM的异常退出，由KVM模块接管；
- KVM模块返回到Qemu后，Qemu会检查VM退出的原因，比如检查到e1000寄存器访问出错，因而触发e1000前端工作；
- Qemu能访问Guest OS中的地址内容，因而e1000前端能获取到Guest OS内存中的网络包数据，发送给后端，后端再将网络包数据发送给TUN/TAP驱动，其中TUN/TAP为虚拟网络设备；
- 数据发送完成后，除了更新ring-buffer的指针及描述符状态信息外，KVM模块会模拟TX中断；
- 当再次进入VM时，Guest OS看到的是数据已经发送完毕，同时还需要进行中断处理；
- Guest OS跑在vCPU线程中，发送数据时相当于会打算它的执行，直到处理完后再恢复回来，也就是一个严格的同步处理过程


接收：

- 当TUN/TAP有网络包数据时，可以通过读取TAP文件描述符来获取；
- Qemu中的I/O线程会被唤醒并触发后端处理，并将数据发送给e1000前端；
- e1000前端将数据拷贝到Guest OS的物理内存中，并模拟RX中断，触发VM的退出，并由KVM模块接管；
- KVM模块返回到Qemu中进行处理后，并最终重新进入Guest OS的执行中断处理；
- 由于有I/O线程来处理接收，能与vCPU线程做到并行处理，这一点与发送不太一样

### 网卡半虚拟化

Virtio 目前被用作虚拟机（VM）访问块设备（virtio-blk）和网络设备（virtio-net）的标准开放接口。

Virtio是一种前后端架构，包括前端驱动（Guest内部）、后端设备（QEMU设备）、传输协议（vring）。

将 Virtio-net 分为两个平面： 数据面需要尽可能快的转发数据包，控制面则需要做到尽可能的灵活

* 控制面 - 用于在 Host 与 Guest 之间进行能力协商，同时用于建立和终止数据面。
* 数据面 - 用于 Host 与 Guset 之间传输数据包。

{{<figure src="./virtio-optimization.png#center" width=800px >}}
第一行是针对网卡的实现，第二行更进一步的抽象，第三行是通用的解决方案了，对I/O操作的虚拟化通用支持；



{{<figure src="./featured.png#center" width=800px >}}
* Virtio Driver：前端部分，处理用户请求，并将I/O请求转移到后端；
* Virtio Device：后端部分，由Qemu来实现，接收前端的I/O请求，并通过物理设备进行I/O操作；
* Virtqueue：中间层部分，用于数据的传输；
* Notification：交互方式，用于异步事件的通知；


virtio网络的发展

- 控制平面由最原始的virtio到vhost-net协议，再到vhost-user协议，逐步得到了完善与扩充;
- 数据平面上，从原先集成在QEMU中或内核模块的中，到集成了DPDK数据平面优化技术的vhost-user，最终到使用硬件加速数据平面。在保留virtio这种标准接口的前提下，达到了SR-IOV设备直通的网络性能。



## 参考
- [x86 体系结构的虚拟化](https://www.cnblogs.com/jmilkfan-fanguiju/p/11825029.html)
- [Linux虚拟化KVM-Qemu分析（八）之virtio初探](https://rtoax.blog.csdn.net/article/details/113819423)
- [virtio 网络的演化：原始virtio ＞ vhost-net(内核态) ＞ vhost-user(DPDK) ＞ vDPA](https://blog.csdn.net/Rong_Toa/article/details/113819506)