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


## 基本概念

MCP 由三个核心组件构成：Host、Client 和 Server。

假设你正在使用 Claude Desktop (Host) 询问："我桌面上有哪些文档？"
{{<figure src="./mcp_structure.png#center" width=800px >}}

- Host：Claude Desktop 作为 Host，负责接收你的提问并与 Claude 模型交互。
- Client：当 Claude 模型决定需要访问你的文件系统时，Host 中内置的 MCP Client 会被激活。这个 Client 负责与适当的 MCP Server 建立连接。
- Server：文件系统 MCP Server 会被调用。它负责执行实际的文件扫描操作，访问你的桌面目录，并返回找到的文档列表。


## 流程

{{<figure src="./mcp_process.png#center" width=800px >}}

{{<figure src="./mcp_process_example.png#center" width=800px >}}


## Primitives 原语

### Tools 工具

Tools（工具） 是 MCP 协议中的一项关键原语，服务器可通过它向客户端暴露可执行功能，供 LLM 使用（通常需要用户批准，确保人类参与决策）


### Resources 资源

Resources（资源）是 MCP 协议中的核心原语之一，服务器通过它可以向客户端提供可读的数据或内容，用作 LLM 交互的上下文信息。


### Prompts 提示词

提示词 允许服务器定义可复用的提示词模板和工作流，客户端可以轻松将这些模板呈现给用户或 LLM。

## 案例 

客户端: https://github.com/modelcontextprotocol/python-sdk/tree/main/examples/clients/simple-chatbot/mcp_simple_chatbot



## 手动开发 MCP 开发


```go
// hello-mcp-server.go
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
)

// 定义通用的请求和响应结构体，以匹配MCP的JSON-RPC格式
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type Response struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Result  any    `json:"result,omitempty"`
	Error   *Error `json:"error,omitempty"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func main() {
	// MCP服务器通过标准输入/输出进行通信，所以我们需要一个扫描器来读取stdin
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Bytes()

		// 读取每一行（通常是一个JSON-RPC请求），并尝试解析
		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			log.Printf("Error unmarshaling request: %v", err)
			continue
		}

		// 根据请求的Method字段，路由到不同的处理函数
		switch req.Method {
		case "initialize":
			handleInitialize(req)
		case "tools/list":
			handleToolsList(req)
		case "tools/call":
			handleToolCall(req)
		case "notifications/initialized":
			// 客户端发送的初始化完成通知，无需响应
			continue
		default:
			sendError(req.ID, -32601, "Method not found")
		}
	}
}

// handleInitialize负责向Claude Code"自我介绍"
func handleInitialize(req Request) {
	// 符合MCP协议的initialize响应
	initializeResult := map[string]any{
		"protocolVersion": "2024-11-05", // MCP协议版本
		"capabilities": map[string]any{
			"tools": map[string]any{}, // 声明支持工具能力
		},
		"serverInfo": map[string]any{
			"name":    "hello-server",
			"version": "1.0.0",
		},
	}
	sendResult(req.ID, initializeResult)
}

// handleToolsList返回可用工具列表
func handleToolsList(req Request) {
	toolsListResult := map[string]any{
		"tools": []map[string]any{
			{
				"name":        "greet",
				"description": "A simple tool that returns a greeting.",
				"inputSchema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"name": map[string]any{
							"type":        "string",
							"description": "The name of the person to greet.",
						},
					},
					"required": []string{"name"},
				},
			},
		},
	}
	sendResult(req.ID, toolsListResult)
}

// handleToolCall负责处理工具的实际调用
func handleToolCall(req Request) {
	var params map[string]any
	if err := json.Unmarshal(req.Params, &params); err != nil {
		sendError(req.ID, -32602, "Invalid params")
		return
	}

	toolName, _ := params["name"].(string)
	if toolName != "greet" {
		sendError(req.ID, -32601, "Tool not found")
		return
	}

	toolArguments, _ := params["arguments"].(map[string]any)
	name, _ := toolArguments["name"].(string)

	// 这是我们工具的核心逻辑
	greeting := fmt.Sprintf("Hello, %s! Welcome to the world of MCP in Go.", name)

	// MCP期望的响应格式
	toolResult := map[string]any{
		"content": []map[string]any{
			{
				"type": "text",
				"text": greeting,
			},
		},
	}
	sendResult(req.ID, toolResult)
}

// sendResult和sendError是辅助函数，用于向stdout发送格式化的JSON-RPC响应
func sendResult(id any, result any) {
	resp := Response{JSONRPC: "2.0", ID: id, Result: result}
	sendJSON(resp)
}

func sendError(id any, code int, message string) {
	resp := Response{JSONRPC: "2.0", ID: id, Error: &Error{Code: code, Message: message}}
	sendJSON(resp)
}

func sendJSON(v any) {
	encoded, err := json.Marshal(v)
	if err != nil {
		log.Printf("Error marshaling response: %v", err)
		return
	}
	// MCP协议要求每个JSON对象后都有一个换行符
	fmt.Println(string(encoded))
}

```

```shell
$ claude mcp add --transport stdio hello -- go run hello-mcp-server.go

# 工具的完整名称是 mcp__hello__greet
> 我想调用 mcp__hello__greet 工具，名字是 Danny xia                                                                                                                    
                                                                                                                                                                       
⏺ 我来帮你调用 mcp__hello__greet 工具，使用名字 "Danny xia"。                                                                                                          
                                                                                                                                                                       
⏺ hello - greet (MCP)(name: "Danny xia")                                                                                                                               
  ⎿  Hello, Danny xia! Welcome to the world of MCP in Go.                                                                                                              
                                                                                                                                                                       
⏺ 工具返回了问候语：Hello, Danny xia! Welcome to the world of MCP in Go.
```

## 参考
- https://modelcontextprotocol.io/docs/getting-started/intro
- https://github.com/modelcontextprotocol
- https://github.com/punkpeye/awesome-mcp-clients
- https://github.com/modelcontextprotocol/servers
- https://mcpservers.org/
- [MCP（Model Context Protocol）初体验：企业数据与大模型融合初探](https://www.cnblogs.com/CareySon/p/18805011/mcp_for_crm_demo)
- [MCP (Model Context Protocol)，一篇就够了](https://zhuanlan.zhihu.com/p/29001189476)
- [一文掌握 MCP 上下文协议：从理论到实践](https://zhuanlan.zhihu.com/p/1891139164952584541)