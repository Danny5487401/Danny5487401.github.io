---
title: "vLLM"
date: 2025-08-29T11:29:48+08:00
summary: "PagedAttention 实现"
categories:
  - ai
---

vLLM是伯克利大学LMSYS组织开源的大语言模型高速推理框架.

vLLM 主要用于快速 LLM 推理和服务，通过一种名为PagedAttention的技术，动态地为请求分配KV cache显存，提升显存利用率。

## 基本概念

FLOPS：等同于FLOP/s，表示Floating Point Operations Per Second，即每秒执行的浮点数操作次数，用于衡量硬件计算性能。

FLOPs：表示Floating Point Operations，表示某个算法的总计算量（即总浮点运算次数），用于衡量一个算法的复杂度。

### 计算强度 (arithmetic intensity)

算法对于内存带宽的需求通常使用 计算强度 (arithmetic intensity) 来表示，单位是 OPs/byte。意思是在算法中平均每读入单位数据，能支持多少次运算操作。


算力 ：也称为计算平台的性能上限，指的是一个计算平台倾尽全力每秒钟所能完成的浮点运算数。floating point operations per second.单位是 FLOPS or FLOP/s。

带宽 ：也即计算平台的带宽上限，指的是一个计算平台倾尽全力每秒所能完成的内存交换量。单位是Byte/s。

计算强度上限 ：两个指标相除即可得到计算平台的计算强度上限。它描述的是在这个计算平台上，单位内存交换最多用来进行多少次计算。单位是FLOPs/Byte


### MAC（Memory Access Cost，存储访问开销)

MAC的开销主要来自两方面。一是从存储中读取数据；二是向存储中写数据。与CPU的情况类似，在GPU中，当需要计算时，需将数据从显存中读取并由计算单元进行计算操作。在计算完毕后，再写回到显存中。



## 大模型推理

一个常规的LLM推理过程通常分为两个阶段：预填充阶段( prefill ) 和 生成response的阶段( decode)。通常会使用KV cache技术加速推理。

{{<figure src="./prefill_n_decode.png#center" width=800px >}}






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



## FlashAttention(Fast and Memory Efficient Exact Attention with IO-Awareness）)

(1）Fast（with IO-Awareness），计算快。计算慢的卡点不在运算能力，而是在读写速度上。所以它通过降低对显存（HBM）的访问次数来加快整体运算速度，这种方法又被称为O-Awareness。

（2）Memory Efficient，节省显存。

（3）Exact Attention，精准注意力。


## PagedAttention


PagedAttention的设计灵感来自操作系统的虚拟内存分页管理技术。


### 场景
PagedAttention在Parallel Sampling和Beam Search场景上的优势

#### Parallel Sampling


{{<figure src="./ParallelSampling.png.png#center" width=800px >}}

Parallel Sampling：我给模型发送一个请求，希望它对prompt做续写，并给出三种不同的回答。我们管这个场景叫parallel sampling. 


#### Beam Search
Beam Search：束搜索，这是LLM常用的decode策略之一，即在每个decode阶段，我不是只产生1个token，而是产生top k个token（这里k也被称为束宽）。top k个token必然对应着此刻的top k个序列。
我把这top k个序列喂给模型，假设词表的大小为|V|，那么在下一时刻，我就要在k*|V|个候选者中再选出top k.

{{<figure src="./BeamSearch.png.png#center" width=800px >}}


## 参考
- https://docs.vllm.ai/en/latest/
- [第1.1讲：Transformers 的崛起：从RNN到Self-Attention](https://www.cnblogs.com/1314520xh/p/18845484)
- [图解大模型计算加速系列之：vLLM核心技术PagedAttention原理](https://mp.weixin.qq.com/s/-5EniAmFf1v9RdxI5-CwiQ)
- [图解大模型计算加速系列：FlashAttention V1，从硬件到计算逻辑](https://zhuanlan.zhihu.com/p/669926191)