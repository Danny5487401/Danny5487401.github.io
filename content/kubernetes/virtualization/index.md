---
title: "Virtualization"
date: 2025-06-22T16:18:55+08:00
draft: true
---



简而言之，虚拟化是指对计算机资源的抽象。


计算机系统包括五个抽象层：硬件抽象层，指令集架构层，操作系统层，库函数层和应用程序层


## 基本概念


ring0是指CPU的运行级别，ring0是最高级别，ring1次之，ring2更次之.
操作系统（内核）的代码运行在最高运行级别ring0上，可以使用特权指令，控制中断、修改页表、访问设备等等



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
2. 全虚拟化技术（Full Virtualization）
3. 半虚拟化技术（Paravirtualization）
4. 硬件辅助虚拟化技术（Hardware-Assisted Virtualization)


## kvm(kernel base virtual machine基于内核的虚拟机)




## 参考
- [x86 体系结构的虚拟化](https://www.cnblogs.com/jmilkfan-fanguiju/p/11825029.html)