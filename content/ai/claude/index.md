---
title: "Claude"
date: 2026-02-11T11:58:17+08:00
summary: "一个可编程、可扩展、可组合的 AI Agent 框架。"
categories:
  - ai
---



## 底层技术全景图

{{<figure src="./structure.png#center" width=800px >}}


### 基础层：Memory（记忆系统）

基础层也可以称为是 Claude Code 的长期记忆系统，它的核心文件是 CLAUDE.md

### 四大核心组件
{{<figure src="./four_components.png#center" width=800px >}}

Commands（斜杠命令）、Skills（技能）、SubAgents（子代理）、Hooks（钩子）四个核心组件.



Tools 是行动原语。它回答的是能做什么。读文件、改代码、执行 Bash 命令……这些是操作层面的能力，类似人的双手。

SubAgents 是执行分工。它回答的是谁来做。当任务复杂到需要独立上下文时，子代理承担专职职责，类似团队中的同事。

Hooks 是流程规则。它回答的是什么时候检查。它们在关键节点自动触发质量校验或合规约束，类似企业中的质检流程。

而 Skills 回答的，是另外一个非常关键的问题：“怎么做，以及何时做”，它不是工具，也不是分工机制。它是一种可操作知识结构

#### Skills（技能）

Skills 是一种可被语义触发的能力包，它包含领域知识、执行步骤、输出规范与约束条件，并在需要时渐进式加载到主 Agent 的认知空间中。


从工程角度，Skill 内容分为两类，参考型和任务型。参考型 Skill 影响“怎么做”，任务型 Skill 决定“做什么”。前者是语义环境，后者是具体行动。


从团队协作的视角来看，这里是一些最佳实践。
- 任务型 Skill 放在项目级  .claude/skills/（git 追踪，团队共享）
- 个人习惯性命令放在  ~/.claude/skills/（跨项目可用）
- 为每个 Skill 写清晰的  description  和  argument-hint

```shell
> /help
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 Claude Code v2.0.76  general   commands   custom-commands  (tab to cycle)

 Claude understands your codebase, makes edits with your permission, and executes commands — right from your terminal.

 Shortcuts
 ! for bash mode   double tap esc to clear input     ctrl + _ to undo
 / for commands    shift + tab to auto-accept edits  ctrl + z to suspend
 @ for file paths  ctrl + o for verbose output       ctrl + v to paste images
 & for background  ctrl + t to show todos            opt + p to switch model
                   shift + ⏎ for newline             ctrl + s to stash prompt
```



##### Skill 设计的四种模式

###### 1 模板驱动模式
模板驱动模式核心是用模板强约束输出结构，让结果稳定、可对比、可自动解析。适用于报告生成、文档输出等需要格式一致性的场景。

###### 2 脚本增强模式
脚本增强模式的核心是把计算、匹配、数据转换等确定性逻辑交给脚本执行，而不是让 Claude 推理完成。适用于公式计算、正则匹配、指标统计等场景。


###### 3 知识分层模式
是按使用频率组织知识，高频内联，中低频按需加载。适用于规则多、领域复杂的 Skill


###### 4 分层策略

```html
总是加载（SKILL.md 内联） 
← 80% 的请求只需要这些 
← 控制在 500 行以内

触发时加载（Quick Reference） 
← 用户问到特定方向时加载 
← 契约式引用："When user asks about X → load Y"

按需加载（reference/ + examples/） 
← Claude 判断需要时才读取 
← 文件名要有描述性
```

#### Sub-Agents（子代理）

Sub-Agents（子代理）的核心思想是：一个复杂任务可以拆解给多个专职角色。
创建子代理是有成本的——需要设计、维护、调试。

不该创建子代理的场景一次性任务：直接在主对话中完成即可。简单的 prompt 模板：直接用 Skill 文件，不需要独立上下文和工具隔离。自动化触发动作：用 Hook，不需要 AI 分析判断



#### hooks 
Hooks 是 AI 助手的中间件——拦截、监控、增强每一次交互。

```shell
# 17 种 Hook 事件
 /hooks

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  Hooks
  5 hooks

  ❯ 1.  PreToolUse - Before tool execution
    2.  PostToolUse - After tool execution
    3.  PostToolUseFailure - After tool execution fails
    4.  Notification - When notifications are sent
  ↓ 5.  UserPromptSubmit - When the user submits a prompt
```

分为三大阵营。

- 控制点——能阻止的事件（PreToolUse、UserPromptSubmit、Stop、SubagentStop）：你可以通过它们改变 Claude 的执行路径——拦截危险操作、拒绝不合理的输入、强制 Claude 继续修复。它们是 Hooks 系统的肌肉。

- 接管点——替代默认行为的事件（PermissionRequest）：它不是简单地阻止，而是接管了原本由用户手动处理的权限弹窗——你的脚本可以自动批准或拒绝权限请求，替代人类的决策。它是 Hooks 系统的自动驾驶。

- 观察点——不能阻止的事件（SessionStart、PostToolUse、PostToolUseFailure、Notification、SubagentStart、PreCompact、SessionEnd）：你只能在这些时刻做记录、做反馈、做后处理，但不能改变已经发生的事情。它们是 Hooks 系统的眼睛。




```shell
hooks                            ← 第一层：顶层容器
├── PreToolUse                   ← 第二层：事件类型（什么时候触发）
│   └── [第一组规则]
│       ├── matcher: "Bash"      ← 第三层：匹配器（针对哪个工具）
│       └── hooks: [...]         ← 第三层：Hook 列表（执行什么）
│           └── type: "command"
│           └── command: "..."
└── PostToolUse
    └── [第二组规则]
        ├── matcher: "Write"
        └── hooks: [...]
```

第一层选择“什么时候”——在工具执行前还是执行后？第二层选择“针对谁”——是所有工具还是特定工具？第三层选择“做什么”——执行脚本、调用 LLM、还是启动子代理


四种 Hook 执行类型

- Command 类型——执行 Shell 脚本
- Prompt 类型——LLM 评估
- Agent 类型——子代理评估
- HTTP 类型——它不在本地执行逻辑，而是把事件数据以 POST 请求发送到远程 HTTP 端点


### 集成层：连接外部世界上面这四大核心组件之上，是集成层，负责链接外部世界。

集成层包含 Headless（无头模式）和 MCP（Model Context Protocol）两大技术。


### Plugins：打包容器
当你开发了一套好用的 Commands、Skills、Hooks 组合，想要分享给团队或社区时，就需要 Plugins

## 模型选择

|   模型   | 行为 | 备注 |
|:------:|:--:|:--:|
| sonnet |  使用最新的 Sonnet 模型（当前为 Sonnet 4.5）用于日常编码任务  | 内容 |
|  opus  | 使用最新的 Opus 模型（当前为 Opus 4.6）用于复杂推理任务 | 内容 |
| haiku  | 使用快速高效的 Haiku 模型用于简单任务 | 内容 |


### 场景一: 代码审查
sonnet 代码审查需要较强的分析能力 ✅

haiku  可能漏掉细微的安全问题 ❌

opus  对于审查任务来说成本太高 ❌



## 常见工作流

https://code.claude.com/docs/en/common-workflows

### 1. 图片处理

mac 使用 ctrl+v 粘贴 (不是 cmd+v)


### 2. 引用文件或则目录
```shell
@文件路径
```

### 3. 恢复会话

```shell
> /resume
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Resume Session
╭─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ ⌕ Search…                                                                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

❯ 我这个图片是在干嘛
  22 minutes ago · 2 messages · -

  @/tmp/nacos.yaml 读取配置
  1 week ago · 14 messages · -
```


### 4. mcp 

```json
{
  "mcpServers": {
    "github": {
      "type": "http",
      "url": "https://api.githubcopilot.com/mcp/",
      "headers": {
        "Authorization": "Bearer ${GITHUB_TOKEN}"
      }
    },
    "kubernetes": {
      "command": "npx",
      "args": [
        "-y",
        "kubernetes-mcp-server@v0.0.57"
      ]
    }
  }
}
```

```shell
> /mcp
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 Manage MCP servers
 5 servers

 ❯ 1. argocd-mcp            ✔ connected · Enter to view details
   2. gitlab                ✔ connected · Enter to view details
   3. kubernetes            ✔ connected · Enter to view details
   4. mcp-server-nacos      ◯ disabled · Enter to view details
   5. plugin:gitlab:gitlab  ◯ disabled · Enter to view details
   
   
│ Kubernetes MCP Server                                                                                                                                           │
│                                                                                                                                                                 │
│ Status: ✔ connected                                                                                                                                             │
│ Command: npx                                                                                                                                                    │
│ Args: -y kubernetes-mcp-server@v0.0.57                                                                                                                          │
│ Config location: /Users/python/.claude.json                                                                                                                     │
│ Capabilities: tools · prompts                                                                                                                                   │
│ Tools: 23 tools                                                                                                                                                 │
│                                                                                                                                                                 │
│ ❯ 1. View tools                                                                                                                                                 │
│   2. Reconnect                                                                                                                                                  │
│   3. Disable
```


### 5 Headless模式
将AI能力集成到脚本与CI

```shell
# 场景：快速根据获取一个Git Commit Message建议
claude -p "Stage我的修改，然后生成一条符合Conventional Commit规范的Message" --allowedTools "Bash,Read" --permission-mode acceptEdits


# 使用cat将文件内容通过管道传递给claude
cat nginx-error.log | claude -p "请分析这份Nginx错误日志，总结出最主要的错误类型和可能的原因。"


# 实时观察AI的思考过程
claude -p "使用go-code-security-reviewer subagent 审查@internal/converter/converter.go，检查是否有安全漏洞" --output-format stream-json --verbose
```


### 6 WebFetch
默认集成了 WebFetch 命令，就是指定 URL 读取网页内容，这个理论上就是一个本地执行的 curl 命令，没有云端成本，不需要云端协作。
但是有个问题：（一）CC 在访问地址之前，会先调用 anthropic.com 的一个风控接口，判断这个网络地址是否有安全风险。
（二）政策原因，anthropic.com 会拒绝所有来自中国大陆、香港的请求，风控接口返回 404 或者其他。
（三）风控不通过，WebFetch 失败。

```shell
❯ 帮我查看 https://mp.weixin.qq.com/s/x9wUAM6QI1Ogv2B0biawbg 这个链接的内容

⏺ Fetch(https://mp.weixin.qq.com/s/x9wUAM6QI1Ogv2B0biawbg)
  ⎿  Error: Unable to verify if domain mp.weixin.qq.com is safe to fetch. This may be due to network restrictions or enterprise security policies blocking claude.ai.
```

在 ~/.claude/settings.json 中添加如下配置，禁用 WebFetch 工具前置的风控检查
```json
{
  "skipWebFetchPreflight":true,
}
```

详见解决方式: https://linux.do/t/topic/1148954


## 规范驱动开发（Spec-Driven Development, SDD）


{{<figure src="./sdd.png#center" width=800px >}}

核心产物—— spec.md、plan.md 和 tasks.md

AI Agent 扮演了多个“编译器”的角色：
- 需求编译器：将你用自然语言描述的模糊想法，“编译”成一份结构化的、无歧义的需求规范（spec.md）。
- 方案编译器：将需求规范与你的技术约束（如使用 Go 语言）相结合，“编译”成一份详尽的技术实现蓝图（plan.md）。
- 任务编译器：将技术蓝图，“编译”成一份带依赖关系的、原子化的任务指令集（tasks.md）。
- 代码编译器（生成器）：最终，它根据任务指令集，生成最终的可执行代码。

{{<figure src="./sdd-process.png#center" width=800px >}}


## 参考
- [极客时间: Claude Code 工程化实践](https://time.geekbang.org/column/article/942438)
- [极客时间: AI 原生开发工作流实战](https://time.geekbang.org/column/article/924983)

