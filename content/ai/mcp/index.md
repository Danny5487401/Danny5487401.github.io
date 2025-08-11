---
title: "MCP（ 模型上下文协议 Model Context Protocol)"
date: 2025-05-12T22:34:01+08:00
summary: 模型上下文协议实现原理
categories:
  - mcp
---


模型上下文协议（Model Context Protocol，简称MCP）是一种创新的开放标准协议，旨在解决大语言模型（LLM）与外部数据和工具之间的连接问题。
它为AI应用提供了一种统一、标准化的方式来访问和处理实时数据，使模型不再局限于训练时获得的静态知识。


MCP由Anthropic首次提出并开源，通过定义标准化接口，允许大语言模型以一致的方式与各类外部系统互动，包括数据库、API和企业内部工具等。
这一协议的核心价值在于打破了AI模型的"信息孤岛"限制，极大扩展了大模型的应用场景.




MCP 由三个核心组件构成：Host、Client 和 Server。

假设你正在使用 Claude Desktop (Host) 询问："我桌面上有哪些文档？"

- Host：Claude Desktop 作为 Host，负责接收你的提问并与 Claude 模型交互。
- Client：当 Claude 模型决定需要访问你的文件系统时，Host 中内置的 MCP Client 会被激活。这个 Client 负责与适当的 MCP Server 建立连接。
- Server：在这个例子中，文件系统 MCP Server 会被调用。它负责执行实际的文件扫描操作，访问你的桌面目录，并返回找到的文档列表。



## 流程

{{<figure src="./mcp_process.png#center" width=800px >}}

{{<figure src="./mcp_process_example.png#center" width=800px >}}

## 案例 
客户端: https://github.com/modelcontextprotocol/python-sdk/tree/main/examples/clients/simple-chatbot/mcp_simple_chatbot


 

## 手动开发 MCP 开发



## 参考
- https://github.com/punkpeye/awesome-mcp-clients
- https://mcpservers.org/
- https://github.com/modelcontextprotocol/servers
- [MCP（Model Context Protocol）初体验：企业数据与大模型融合初探](https://www.cnblogs.com/CareySon/p/18805011/mcp_for_crm_demo)
- [MCP (Model Context Protocol)，一篇就够了](https://zhuanlan.zhihu.com/p/29001189476)