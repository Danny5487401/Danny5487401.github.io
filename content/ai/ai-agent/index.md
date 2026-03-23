---
title: "Ai Agent"
date: 2025-11-10T16:44:01+08:00
summary: ai agent 常见推理模式
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
 



## 参考



