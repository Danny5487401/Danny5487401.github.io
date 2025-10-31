---
title: "A2A( Agent-to-Agent Protocol 协议 )"
date: 2025-10-18T16:41:54+08:00
---
Agent to Agent Protocol (A2A) 是由 Google 推出的开源协议，旨在实现不透明 Agent 智能体应用程序之间的通信和互操作性。

A2A是负责 Agent 智能体之间的通信、协作和能力发现.

## 要解决什么问题
https://a2a-protocol.org/latest/topics/what-is-a2a/#problems-that-a2a-solves

不同供应商或框架构建的 AI Agents 之间缺乏有效的通信和协作方式。这限制了它们在复杂、多步骤任务中的应用潜力。


## 原理

A2A 协议的核心是通过以下步骤实现 Agents 间的通信：

- 发现机制 agent discovery：允许 Agents 通过标准化的方式发现其他 Agents 的存在，类似于网络中的 DNS 发现设备。每个 Agents 有一个公开的 Agent Card 文件（位于 /.well-known/agent.json），包含能力、技能和通信端点，每个 Agent 可以公布自己的技能，例如“搜索信息”、“总结文本”或“处理图像”，便于其他 Agents 根据任务需求选择合作伙伴。。
- 任务管理：任务是工作的核心单元，有唯一 ID，状态包括提交、处理中、需要输入、完成、失败或取消。确保协作流程顺畅。
- 消息和内容：通信通过消息进行，消息包含文本、文件或结构化数据（Parts），角色标记为“用户”或“Agents”。
- 流式传输和推送：支持长时间任务的流式更新（通过 Server-Sent Events）和推送通知（通过 Webhook URL）。

## 基本概念
https://a2a-protocol.org/latest/topics/key-concepts/

### 参与者（Actors）
A2A 协议包含三个核心参与者：

- 用户（User）： 使用智能体系统完成任务的终端用户（可以是人类，也可以是服务）。
- 客户端（Client）： 代表用户向一个“黑盒”智能体发起任务请求的实体（可以是服务、Agents 或应用）。
- 远程 智能体 / 服务器（Remote Agent / Server）： 黑盒智能体，即 A2A 协议的服务端。


### Agent Card（智能体卡片）

支持 A2A 协议的远程智能体必须以 JSON 格式 发布一份 Agent Card（智能体卡片） ，用于描述该智能体的能力（capabilities/skills）以及身份认证机制。

客户端会使用 Agent Card 中的信息来：

- 判断该智能体是否具备完成某项任务的能力；
- 获取所需的身份认证方式；
- 并基于 A2A 协议与该远程智能体建立通信。

### 制品（Artifact）
任务生成的输出，也包含 Parts。


### 消息（Message）
消息包含任何不是制品的内容。它可以包括 Agent 的思维、用户上下文、指令、错误、状态或元数据等内容。


### Part
客户端和远程 Agent 交换的完全形成的内容，作为消息或制品的一部分。每个部分都有自己的内容类型和元数据。



## 参考

- https://github.com/a2aproject/A2A/tree/main
- https://a2a-protocol.org/latest/
- [Agent to Agent（A2A）一文全了解](https://juejin.cn/post/7491231635868090394)