---
title: "Ai Agent"
date: 2025-11-10T16:44:01+08:00
summary: ai agent 组成
---


AI Agent（也称人工智能代理）是一种能够感知环境、进行决策和执行动作的智能实体。

一个基于大模型的 AI Agent 系统可以拆分为大模型、规划、记忆与工具使用四个组件部分


## 常见推理模式


### CoT（Chain of Thoughts 思维链）

用了思维链后，大模型把任务做了拆分并展示了每一步思考的过程

### ReAct（Reason+Act）

包含 Reason 与 Act 两个部分，其中 Reason 就是大模型推理的过程，其推理运用了 CoT 的思想；Act 是与外界环境交互的动作。


### Reflection && Reflexion
{{<figure src="./Reflection_n_Reflexion.png#center" width=800px >}}

两个大模型的协作过程为：
1. Generate 大模型收到用户的请求后，生成初始 response，并交给 Reflect 大模型。
2. Reflect 会给出评估后，将评语等反馈返给 Generate 大模型。
3. Generate 大模型根据评估做调整后，重新生成 response。
4. 反复循环，直到达到用户设定的循环次数后，将最终的 response 返给用户


### ReWOO（Reason WithOut Observation 无观察推理）
通过一次性规划所有步骤，减少多轮对话的成本和 token 消耗。


## ai gent 项目

- https://github.com/microsoft/autogen 微软推出的 Agent 编程框架
- https://github.com/Significant-Gravitas/AutoGPT
 

## Agent Memory：智能体运行时记忆（动态）
传统软件很少纠结“会不会忘”。进程崩了有数据库兜底，请求断了有 session 和 checkpoint，服务重启之后照着状态恢复就行。




### 为什么需要 Agent Memory
- LLM 原生上下文窗口有限，长对话、多轮交互、跨会话任务易丢失信息；LLM Memory：模型预训练知识（静态）
- Memory 让 Agent 实现知识累积、迭代推理、持续进化，支撑复杂长程任务；
- 区别于 RAG：Memory 聚焦交互态、会话内 / 跨会话动态信息，RAG 聚焦外部知识库





Agent 的记忆其实需要解决三个传统软件用不同机制分别处理过的问题。
- 第一是状态持久化。Agent 被打断之后，要记得自己刚才在干什么。这对应传统软件里的数据库状态、session 和 checkpoint。
- 第二是知识检索。Agent 要访问的信息，远超上下文窗口能装下的量，所以要有地方存，也要有办法取。这对应数据库、搜索索引和文档系统。
- 第三是经验累积。Agent 应该从过去的执行里学到东西，下次少踩坑。这一点，传统软件里没有完全等价的机制。最接近的是测试套件和事故复盘：它们都在把过去踩过的坑固化下来，让系统以后不要重犯





### 记忆模式组
四种模式：分层保留（Hierarchical Retention）、检索增强（RAG）、进度追踪（Progress Tracking）、失败日记（Failure Journals）



- 工作记忆 working memory，主要由分层保留来管理。
- 语义记忆 semantic memory，主要由 RAG 和其他检索机制来取回。
- 情节记忆 episodic memory，主要由进度追踪来沉淀。
- 失败记忆 failure memory，可以看作 episodic memory 里最值得主动召回的一类，由失败日记来管理。
- 程序性记忆 procedural memory，程序性记忆”把会做的活儿固化成可复用流程，也就是技能包（Skill Package）模式，是经验沉淀的高级形态。

### 基准测试算法

#### LoCoMo——Long-Context Conversations with Memory

它评估 AI 系统在长篇自然对话中回忆和推理信息的能力。LoCoMo 中的对话跨越数百个回合，模拟用户和 AI 助手之间的真实多会话交互



### 第三方实现



- https://github.com/mem0ai/mem0: Mem0是轻量级语义检索记忆框架，同时提供托管服务与开源版本，Pro版额外集成知识图谱能力。
- https://github.com/TencentCloud/TencentDB-Agent-Memory
- https://github.com/rohitg00/agentmemory: Agent 执行工具调用时，它通过 Hook 机制自动静默捕获所有操作

## 参考

- [Agent 设计模式之美 11｜记忆模块导论](https://time.geekbang.org/column/article/987077)



