---
title: "Netbird"
date: 2026-05-17T15:48:59+08:00
draft: true
summary: 一款开源的零信任网络平台，它利用 WireGuard 技术，在电脑、服务器或云实例等设备之间建立快速、加密的点对点（P2P）覆盖网络，无需复杂的手动配置、打开防火墙端口或设置集中式 VPN 网关，团队可以直观地管理网络访问权限和用户
---



NetBird 是一个由一系列组件组成的开源平台，负责处理点对点连接、隧道、身份验证和网络管理（IP、密钥、ACL 等）。

NetBird 依赖四个组件：客户端（或代理）、Management 管理、Signal 信号 和 Relay 中继 服务。只有经过身份验证的用户（或机器）才能访问被授权的资源。
对等体 Peer 指连接到网络的任何设备：云/本地 Linux 服务器、笔记本、手机或树莓派。



## 基本概念

### NAT

经典的 NAT（NAPT）可分为 full cone 完全圆锥型、restricted cone 受限圆锥型、port restricted cone  端口受限圆锥型和 symmetric 对称型四种.



### P2P（Peer-to-Peer 点对点)
{{<figure src="./p2p.png#center" width=800px >}}

如果连接双方都是公网地址，则可以直接访问到对方，从而建立连接。但大部分情况下其中一方或者双方都不是公网地址，而是隐藏在 NAT（Network Address Translation，网络地址转换）之后的内网地址，此时要建立连接，就得使用某种能绕过 NAT 的 hole punching 打洞技术。


- A 与 S 建立连接（Session A-S），向 S 注册自己的内网地址 10.0.0.1:4321 ；S 会同时记录 A 在公网的地址 155.99.25.11:62000 。B 与 S 建立连接（Session B-S），向 S 注册自己的内网地址 10.1.1.3:4321 ；S 会同时记录 B 在公网的地址 138.76.29.7:31000 。
- A 向 S 发送请求，获取 B 的地址（Request Connection to B）；S 会同时把 A 的地址转发给 B（Forward A’s Endpoints to B）。然后 A 和 B 都开始尝试相互向对方发送数据包。
- 当 A 向 B 第一次发送数据包时（Send to B at）会在 NAT_A 中产生映射 (10.0.0.1:4321, 138.76.29.7:31000) ；此时 NAT_B 并没有 A 和 B 的映射记录，数据包仍然会被丢弃。
- 当 B 向 A 第一次发送数据包时（Send to A at）会在 NAT_B 中产生映射 (10.1.1.3:4321, 155.99.25.11:62000) ；因为之前 NAT_A 已经创建了 A 和 B 的映射，所以 B 请求成功。
- 当 A 向 B 第二次发送数据包时，因为 NAT_B 也有了 A 和 B 的映射记录，所以 A 也请求成功。于是打洞完成，A 和 B 可以直接建立点对点连接（Session A-B）。


### STUN（Session Traversal Utilities for NAT)
https://datatracker.ietf.org/doc/html/rfc8489

STUN（Session Traversal Utilities for NAT，NAT 会话穿越应用程序）是一种允许位于 NAT 之后的客户端找出自己的公网地址，并判断出 NAT 限制其直连的方法的协议.

STUN技术需要一个位于公网的STUN server，它实现了一个基于client-server的协议（该协议见RFC5389），由客户端主动发起连接，STUN server会通知STUN client它的公网IP以及公网端口.

STUN在大多数的NAT网络中（完全圆锥型NAT、受限圆锥型NAT和端口受限圆锥型NAT）是没有问题，但是在对称型NAT中不能使用。

{{<figure src="./stun_process.png#center" width=800px >}}
STUN服务器收到客户端发送的binding request包，会从IP协议拿到外网的IP，从传输协议拿到PORT，最后将IP与PORT做异或处理放到binding response的XOR-MAPPED-ADDRESS中返回，客户端拿到后回调给上层。


### TURN（Traversal Using Relays around NAT）
TURN（Traversal Using Relays around NAT，NAT 中继遍历程序）.
当两个客户端由于对称型NAT原因不能建立连接可以使用一个TURN作为中继，两个客户端分别和TURN server建立连接，TURN server返回它自己的IP和端口给两个客户端，TURN server作为中继，使用UDP协议给两个客户端直接转发报文。




### ICE（Interactive Connectivity Establishment，交互式连接建立)
https://datatracker.ietf.org/doc/html/rfc5245

是一种端到端交互的技术，可以让两个终端相互知道对方的公网IP，可以不借助一个公网server完成端到端（Peer to peer，P2P）的通信。
它结合了STUN和TURN的优势，去掉了两者的不足。

ICE会同时使用STUN和TURN，它通过这两个技术获得IP地址和端口（被称为candidate），candidate会存在多个，在SIP消息中可以携带多个candidate。接收端收到SIP消息后，会对这些candidate分别做连接检查



## 组件

### Management service

功能:
- 注册和认证新 peer.
- 存储网路图谱.
- 管理私有 ip .
- 同步网络修改给peers
- 管理连接规则
- 管理 dns
- 管理 users


### Signal service
功能: 通知


### Relay service
一个 TURN 服务器.

传输协议:
- QUIC: 优先
- WebSocket:  UDP 不允许才使用.

## 管理


### team


### 用户角色
五种角色: Owner, Admin, Network Admin, Auditor and User



## 参考
- [P2P 打洞原理](https://webrtc.mthli.com/basic/p2p-hole-punching/)
