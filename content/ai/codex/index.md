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


### 第三方应用
- 线上监控诊断产品 arthas: https://github.com/alibaba/arthas/blob/master/AGENTS.md




## 参考
- [深入解析 Codex 智能体循环](https://openai.com/zh-Hans-CN/index/unrolling-the-codex-agent-loop/)
- [OpenAI Codex 深入剖析：下一代 AI 编程助手的架构与原理](https://juejin.cn/post/7592921639464108074)