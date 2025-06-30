---
title: "Calico"
date: 2025-06-21T22:35:34+08:00
draft: true
---



## BGP (外网路由协议（Border Gateway Protocol )

求最短路径常用的有两种方法，一种是Bellman-Ford算法，一种是Dijkstra算法。


动态路由算法
- 第一大类的算法称为距离矢量路由（distance vector routing）。它是基于Bellman-Ford算法的
- 第二大类算法是链路状态路由（link state routing），基于Dijkstra算法。


BGP又分为两类，eBGP和iBGP。自治系统间，边界路由器之间使用eBGP广播路由。
内部网络也需要访问其他的自治系统。边界路由器如何将BGP学习到的路由导入到内部网络呢？就是通过运行iBGP，使得内部的路由器能够找到到达外网目的地的最好的边界路由器。


BGP协议使用的算法是路径矢量路由协议（path-vector protocol）。它是距离矢量路由协议的升级版。


自治系统（Autonomous System, AS） 是指一组相互信任、使用相同路由策略的网络或子网，通过BGP（边界网关协议）进行通信。


自治系统编号（Autonomous System Number，ASN） 是一个唯一标识自治系统的32位整数，用于在BGP（边界网关协议）中标识不同的网络或网络提供商。
```shell
root@node1:/etc/cni/net.d# calicoctl get nodes --output=wide
NAME    ASN       IPV4             IPV6
node1   (64512)   172.16.7.30/16
node2   (64512)   172.16.7.31/16
node3   (64512)   172.16.7.32/16
node4   (64512)   172.16.7.33/16
node5   (64512)   172.16.7.34/16
```

### BGP两种模式
1. 全互联模式(node-to-node mesh)

全互联模式 每一个BGP Speaker都需要和其他BGP Speaker建立BGP连接，这样BGP连接总数就是N^2，如果数量过大会消耗大量连接。如果集群数量超过100台官方不建议使用此种模式。

2. 路由反射模式Router Reflection（RR）

RR模式 中会指定一个或多个BGP Speaker为RouterReflection，它与网络中其他Speaker建立连接，每个Speaker只要与Router Reflection建立BGP就可以获得全网的路由信息。在calico中可以通过Global Peer实现RR模式。



## 组件


- Felix：运行在每一台 Host 的 agent 进程，主要负责网络接口管理和监听、路由、ARP 管理、ACL 管理和同步、状态上报等。
- etcd：分布式键值存储，主要负责网络元数据一致性，确保Calico网络状态的准确性，可以与kubernetes共用；
- BGP Client（BIRD）：Calico 为每一台 Host 部署一个 BGP Client，使用 BIRD 实现，BIRD 是一个单独的持续发展的项目，实现了众多动态路由协议比如 BGP、OSPF、RIP 等。在 Calico 的角色是监听 Host 上由 Felix 注入的路由信息，然后通过 BGP 协议广播告诉剩余 Host 节点，从而实现网络互通。
- BGP Route Reflector（RR）（路由反射）：在大型网络规模中，如果仅仅使用 BGP client 形成 mesh 全网互联的方案就会导致规模限制，因为所有节点之间俩俩互联，需要 N^2 个连接，为了解决这个规模问题，可以采用 BGP 的 Router Reflector 的方法，使所有 BGP Client 仅与特定 RR 节点互联并做路由同步，从而大大减少连接数。


### Felix


