---
title: "Codex"
date: 2026-04-06T20:00:00+08:00
summary: OpenAI 推出的本地 AI 编程代理
categories:
  - codex
tags:
  - ai
  - codex
draft: false
---

“Codex”是指一系列软件智能体产品，包括 Codex CLI、Codex Cloud 和 Codex VS Code 扩展。


## 项目文档记忆：AGENTS.md

- https://github.com/agentsmd/agents.md
- https://agents.md/#examples

openai/codex 遵循这个规范.


如果每个项目都需要为不同的 Agent 维护一套不同的“私约”，那么我们刚刚从“复制粘贴上下文”的泥潭中挣扎出来，又将陷入“维护多套 AI Agent 配置”的新泥潭。这种碎片化，极大地阻碍了 AI 原生开发方法论的沉淀和迁移。
- Claude Code 有自己的 CLAUDE.md。
- Gemini CLI 有 GEMINI.md。
- CRUSH 有 CRUSH.md。


正是在这样的背景下，AGENTS.md 应运而生。它不再是某一家公司的“私有协议”，而是由 OpenAI、Google 等多家 AI 巨头和社区共同倡议的一个开放标准.

建议在你的项目根目录下创建一个名为 AGENTS.md 的文件，专门存放那些写给 AI Agent 看的、结构化的核心指令。




## skill
https://learn.chatgpt.com/docs/build-skills



扫描路径: 使用 ~/.agents/skills/ 作为中央 canonical 目录

分发: 打包成 plugin


### Agent Skill 开放标准
Agent Skill 标准通常包括技能的定义格式、调用协议、响应格式等关键要素。技能可以通过 MCP（Model Context Protocol）或其他通信机制与 AI 模型进行交互，为模型提供超出其内置能力的功能，如数据库查询、API 调用、文件操作等。


Agent Skill 标准在 AI 应用开发中具有重要意义：

- 能力扩展：AI 模型无需掌握所有领域知识，可通过调用相应的技能来完成特定任务。
- 安全性：通过预定义的技能接口，可以控制 AI 对系统资源的访问权限，提高系统的安全性。
- 可维护性：技能作为独立的组件，可以单独开发、测试和更新，而不影响 AI 模型本身。
- 可复用性：同一技能可以被多个 AI 模型或应用共享使用，提高开发效率。
- 实时性：AI 可以获取实时数据和执行实时操作，而不仅仅依赖于训练时的数据



遵从 Agent Skill 开放标准列表: https://agentskills.io/clients
- openclaw
- hermes
- trae
- claude code
- chatgpt

### 第三方应用
- 线上监控诊断产品 arthas: https://github.com/alibaba/arthas/blob/master/AGENTS.md






## 参考
- [深入解析 Codex 智能体循环](https://openai.com/zh-Hans-CN/index/unrolling-the-codex-agent-loop/)
- [OpenAI Codex 深入剖析：下一代 AI 编程助手的架构与原理](https://juejin.cn/post/7592921639464108074)