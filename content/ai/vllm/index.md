---
title: "vLLM"
date: 2025-08-29T11:29:48+08:00
summary: "PagedAttention 实现"
draft: true
---


vLLM 主要用于快速 LLM 推理和服务，其核心是 PagedAttention.

## 基本概念

### 计算强度 (arithmetic intensity)

算法对于内存带宽的需求通常使用 计算强度 (arithmetic intensity) 来表示，单位是 OPs/byte。意思是在算法中平均每读入单位数据，能支持多少次运算操作。


算力 ：也称为计算平台的性能上限，指的是一个计算平台倾尽全力每秒钟所能完成的浮点运算数。floating point operations per second.单位是 FLOPS or FLOP/s。

带宽 ：也即计算平台的带宽上限，指的是一个计算平台倾尽全力每秒所能完成的内存交换量。单位是Byte/s。

计算强度上限 ：两个指标相除即可得到计算平台的计算强度上限。它描述的是在这个计算平台上，单位内存交换最多用来进行多少次计算。单位是FLOPs/Byte


### MAC（Memory Access Cost，存储访问开销)

MAC的开销主要来自两方面。一是从存储中读取数据；二是向存储中写数据。与CPU的情况类似，在GPU中，当需要计算时，需将数据从显存中读取并由计算单元进行计算操作。在计算完毕后，再写回到显存中。




## 大模型推理框架



## 序列建模的演进之路

### RNN（ Recurrent Neural Networks)：序列处理的开拓者

局限性：然而，由于梯度消失问题，普通RNN很难学习长距离依赖。随着序列长度增加，早期输入的信息会迅速衰减或爆炸。

### 自注意力(Self-Attention)机制: 长依赖问题的解决方案

也称为内部注意力(Intra-Attention).

注意力机制(attention mechanism)最早是在序列到序列模型中提出的，用于解决机器翻译任务。

自注意力模型采用查询-键-值(Query-Key-Value,QKV)模式


#### 为什么Self-Attention解决了长依赖问题？
并行计算：不像RNN需要顺序处理，Self-Attention可以并行计算所有位置
路径长度恒定：任意两个位置之间的信息传递只需一步操作
加权求和：通过自适应权重聚合所有位置的信息



## FlashAttention 基本原理



## 参考
- [第1.1讲：Transformers 的崛起：从RNN到Self-Attention](https://www.cnblogs.com/1314520xh/p/18845484)