---
title: "Openclaw"
date: 2026-03-11T18:23:43+08:00
draft: true
summary: "个人 AI AGENT"
---



## 架构
{{<figure src="./structure.png#center" width=800px >}}


OpenClaw 的外围就是各种 IM 软件。除了 IM 软件，还有两个项目本身提供的东西：一个是 Client 端，也就是命令行的控制端；
另一个是 WebChat，它提供了一个小网页，大家可以通过网页端对话使用。这些都是外围的东西。
整体上，OpenClaw 的所有东西都放在一个叫 Gateway 的进程里，这个进程是一个 Node 服务。


## OpenClaw 的核心技术

### 1. 上下文工程

（1）system prompt 动态加载

（2）上下文的剪裁和压缩

（3）长记忆搜索


### 2. 后台任务：双调度机制


#### Cron Tab

OpenClaw 自己维护一个 cron.json 文件，记录需要精确调度的任务


#### Heartbeat 机制
heartbeat 每 30 分钟无脑唤醒一次，让 agent 做点事情。


### 3. 工具调用与 Skills 渐进式披露



## 参考
- [爆火全网的OpenClaw强在哪儿](https://time.geekbang.org/column/article/946360)