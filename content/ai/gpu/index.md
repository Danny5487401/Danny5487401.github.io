---
title: "Gpu"
date: 2025-07-09T21:10:30+08:00
draft: true
---



## DMA( Direct Memory Access 直接内存访问)


允许不同速度的硬件装置来沟通，而不需要依于 CPU 的大量中断负载。


### DMA传输过程

{{<figure src="./dma-process.png#center" width=800px >}}
1、DMA请求

CPU对DMA控制器初始化，并向I/O接口发出操作命令，I/O接口提出DMA请求。


2、DMA响应

DMA控制器对DMA请求判别优先级及屏蔽，向总线裁决逻辑提出总线请求。

当CPU执行完当前总线周期即可释放总线控制权。此时，总线裁决逻辑输出总线应答，表示DMA已经响应，通过DMA控制器通知I/O接口开始DMA传输。


3、DMA传输

DMA控制器获得总线控制权后，CPU即刻挂起或只执行内部操作，由DMA控制器输出读写命令，直接控制RAM与I/O接口进行DMA传输。
在DMA控制器的控制下，在存储器和外部设备之间直接进行数据传送，在传送过程中不需要中央处理器的参与。开始时需提供要传送的数据的起始位置和数据长度。


4、DMA结束

当完成规定的成批数据传送后，DMA控制器即释放总线控制权，并向I/O接口发出结束信号。

当I/O接口收到结束信号后，一方面停 止I/O设备的工作，另一方面向CPU提出中断请求，使CPU从不介入的状态解脱，并执行一段检查本次DMA传输操作正确性的代码。



## 内存的架构

{{<figure src="./memory_structure.png#center" width=800px >}}


系统存储：

* L1/L2/L3：多级缓存，其位置一般在CPU芯片内部；
* System DRAM：片外内存，内存条；
* Disk/Buffer：外部存储，如磁盘或者固态硬盘。


GPU设备存储：

* L1/L2 cache：多级缓存，其位置在GPU芯片内部；
* GPU DRAM：通常所指的显存


传输通道：

* PCIE BUS：PCIE标准的数据通道，数据就是通过该通道从显卡到达主机；
* BUS： 总线。计算机内部各个存储之间交互数据的通道；
* PCIE-to-PCIE：显卡之间通过PCIE直接传输数据；
* NVLINK：显卡之间的一种专用的数据传输通道，由NVIDIA公司推出


## 存储（内存）之间的操作

### 数据从磁盘/系统内存到GPU



## GPU 内存管理


{{<figure src="./gpu_memory_management.png#center" width=800px >}}

对GPU内存的使用经历了三个阶段，

第一个阶段是分离内存管理，GPU上运行的Kernel代码不能直接访问CPU内存，在载入Kernel之前或Kernel执行结束之后必须进行显式的拷贝操作；

第二个阶段是半分离内存管理，Kernel代码能够直接用指针寻址到整个系统中的内存资源；

第三个阶段是分离内存管理，CPU还是GPU上的代码都可以使用指针直接访问到系统中的任意内存资源。


### 分离内存管理

1. 页锁定内存（Page-locked Memory），或称固定内存（Pinned Memory）和零拷贝内存.


将数据在系统内存中锁住，避免数据在系统环境切换（如线程更换）时，数据从内存转移到硬盘。



2. 所谓零拷贝，就是GPU寄存器堆直接与主机内存交互。从代码里可以看到，将主机内存指针进行映射后，Kernel就可以直接使用指针来访问主机内存了，读取的数据会直接写入寄存器中.
具体的做法是，直接申请pinned memory，然后将指针传递给运算的kernel：




### UVA (Unified Virtual Address 半分离内存管理)



### UM (Unified Memory 统一内存管理)




## 参考
- [nvidia 官方架构](https://www.nvidia.cn/technologies/)
- [浅谈GPU通信和PCIe P2P DMA](https://zhuanlan.zhihu.com/p/430101220)