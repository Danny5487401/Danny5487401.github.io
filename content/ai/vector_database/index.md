---
title: "向量数据库"
date: 2025-07-31T11:06:36+08:00
draft: true
---


向量数据库是一种专为高效存储和检索高维向量数据而设计的数据库系统。

这些向量通常来源于机器学习和深度学习模型对非结构化数据（如文本、图像、音频、视频）的编码处理。通过将原始数据转化为密集的数值向量（生产使用一般向量维度会大于512），向量数据库能够支持诸如相似性搜索、推荐系统、图像检索、语音识别等多种应用场景。

## 基本概念

### 向量Embeddings
向量Embeddings是自然语言处理（NLP）中的一个基本概念，是单词、句子、文档、图像、音频或视频数据等对象的数字表示。

- 生成句子Embeddings的常用方法包括Doc2Vec (Document-to-vector)
- 卷积神经网络(cnn)和视觉几何组(VGG)用于生成图像Embeddings


## 常见向量数据库

1. [Milvus](https://github.com/milvus-io/milvus) - 开源，由Zilliz开发，专为大规模向量相似性搜索设计，支持多种索引类型，适用于图像检索、推荐系统等场景。

2. [Faiss](https://github.com/facebookresearch/faiss) - 开源库，由Facebook AI Research (FAIR)开发，针对相似性搜索进行了优化，特别是对于GPU加速的场景非常有效。

3. [qdrant](https://github.com/qdrant/qdrant)- 开源

4. [pgvector](https://github.com/pgvector/pgvector)- 开源 pg 插件


### milvus

Milvus部署依赖许多外部组件，如存储元信息的ETCD、存储使用的MinIO、消息存储Pulasr 等等


### qdrant
Qdrant完全独立开发，支持集群部署，不需要借助ETCD、Pulsar等组件


## 向量数据库技术原理

1. 数据向量化：这是向量数据库工作的起点，涉及将非结构化数据（如文本、图像、音频）通过机器学习或深度学习模型转化为高维数值向量的过程。这个过程被称为嵌入（Embedding），目的是捕捉原始数据的语义特征。例如，文本可以通过词嵌入模型（如Word2Vec、BERT）转换为向量，图像则可能通过卷积神经网络（CNN）提取特征向量。

2. 向量存储：将转换后的向量存储在数据库中。由于向量通常是高维的，存储方案需高效且可扩展，以支持海量数据。这通常涉及多维索引结构，以便快速定位和检索向量。

3. 相似度计算：向量数据库的核心功能之一是快速计算向量间的相似度。常用的距离度量方法包括欧氏距离、余弦相似度等，这些度量方法帮助评估两个向量的接近程度，从而找到最相似的向量。

4. 近似最近邻搜索（Approximate Nearest Neighbor, ANN）：为了提高大规模数据集上的查询效率，向量数据库采用ANN算法。这些算法通过预先构建索引，牺牲极小的精确度换取大幅度的查询速度提升。常见的ANN索引方法包括基于树的方法（如KD树、Ball Tree）、基于哈希的方法（如LSH、PQ）、基于图的方法（如HNSW）、以及乘积量化方法等。

5. 索引构建与更新：构建高效索引是向量数据库的基础，这一步骤通常在数据写入时完成。随着数据的增加和更新，索引也需要动态调整和优化，以维持查询性能。

6. 分布式与并行处理：面对大规模数据集，向量数据库往往采用分布式架构，通过并行处理和数据分片技术来分散存储和计算压力，保证系统的扩展性和高性能。


## 索引

在向量数据库领域，HNSW（Hierarchical Navigable Small-World）和 DiskANN 正逐渐成为主流索引方案。
其中NHSW主要以内存搜索为主，DiskANN主要以磁盘搜索为主。

### HNSW（Hierarchical Navigable Small-World 层次导航小世界图
它是跳表和小世界图（SWG）结构的扩展，可以有效地找到近似的最近邻。

### DiskANN (DISK Approximate Nearest Neighbors)

ANN计算每个候选点与查询点之间的实际距离(如欧几里得距离、余弦相似度)。然后根据与查询点的距离/相似度对候选项进行排名。排名靠前的候选人作为近似近邻返回。


## 参考
- [得物向量数据库落地实践](https://mp.weixin.qq.com/s/SmBNmaD-EWGcImks_g5_hg)
- [向量数据库技术原理及常见向量数据库介绍](https://cloud.tencent.com/developer/article/2424753)