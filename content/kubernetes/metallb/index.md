---
title: "Metallb 负载均衡器"
date: 2025-07-20T16:27:23+08:00
summary: "Metallb 实现原理"
draft: true
---


有两个共同提供此服务的工作负载（workload）：地址分配（address allocation）和外部公告（external announcement）；对应的就是在k8s中部署的controller和speaker。


地址分配（address allocation），首先我们需要给MetalLB分配一段IP，接着它会根据k8s的service中的相关配置来给LoadBalancer的服务分配IP，

外部公告（external announcement）的主要功能就是要把服务类型为LoadBalancer的服务的EXTERNAL-IP公布到网络中去，确保客户端能够正常访问到这个IP。
MetalLB对此的实现方式主要有三种：ARP/NDP和BGP；其中ARP/NDP分别对应IPv4/IPv6协议的Layer2模式，BGP路由协议则是对应BGP模式。
外部公告（external announcement）主要就是由作为daemonset部署的speaker来实现，它负责在网络中发布ARP/NDP报文或者是和BGP路由器建立连接并发布BGP报文



## LB (LoadBalancer 负载均衡器)

调度后方的多台机器，以统一的接口对外提供服务，承担此职责的技术组件。

总体来说负载均衡只有两种：

- 四层负载均衡
- 七层负载均衡

四层负载均衡的优势是性能高，七层负载均衡的优势是功能强。


“四层”的来历：“四层负载均衡”其实是多种均衡器工作模式的统称，“四层”的意思是说这些工作模式的共同特点是维持着同一个 TCP 连接，而不是说它只工作在第四层，如
- 通过改写 MAC 实现的负载均衡（又叫数据链路层负载）工作在二层
- 通过改写 IP 实现的负载均衡（又叫网络层负载均衡）工作在三层

### 四层负载均衡


#### 经典 SNAT 模式
{{<figure src="./lb_snat_process.png#center" width=800px >}}
- 客户端向负载均衡器提供的虚拟 IP 地址 （Virtual IP Address，VIP） 发送请求 （CIP → VIP）
- 负载均衡器从提前配置的多个子网 IP 地址中选择一个(SNAT IP)，替代客户端请求的源 IP，并依据负载均衡算法，选择一个服务器 IP 作为目的 IP，发送请求 (SNIP → SIP) ；
- 服务器处理后将响应结果发回负载均衡器 （SIP →  SNIP） ；
- 负载均衡器将最终结果返回给客户端 （VIP → CIP） 。


缺点:

由于信息量的因素，网络请求的回包往往会比请求包大很多。一般达到 10 倍， 20 Mbps 的请求，其回包可能达到 200 Mbps 。
这样一来，由于回包也是经过 LB，就会大量增加 LB 的带宽使用，减小 LB 的有效处理容量。


基础架构的服务(DNS,MAIL,LDAP 等）工作在 TCP/UDP 传输层之上，所以无法像其它工作在 HTTP 协议以上的应用那样，用 HTTP header 里边的 X-Forwarded-For 字段来保存客户端真实 IP。 
这些基础架构服务的请求包在被 LB 进行 SNAT 之后，客户端的真正 IP 被替换为 LB 的 SNAT IP。



#### DSR (Direct Server Return,服务器直接返回) 技术
{{<figure src="./dsr_process.png#center" width=800px >}}

只有请求经过负载均衡器，而服务的响应无须从负载均衡器原路返回的工作模式，整个请求、转发、响应的链路形成一个“三角关系”，所以这种负载均衡模式也常被很形象地称为 “三角传输模式”（Direct Server Return，DSR），
也有叫“单臂模式”（Single Legged Mode）或者“直接路由”（Direct Routing）。

在 Layer 2 实现时叫 Direct Routing，F5 称之为 nPath.

让后端服务器绕开 LB 直接回包给客户端，从而实现节省 LB 带宽和获取客户端真实 IP 的目标。

在 DSR 模式下，当网络请求包到达 LB 时，LB 并不做 SNAT，而是把包的源 IP 地址原封不动地转发给后端服务器。
当后端服务器拿到请求包以后，由于包里边携带了客户端的源 IP 地址，它就可以直接将回包通过网络路由给这个源 IP 地址，到达客户端手中。


{{<figure src="./dsr_process_2.png#center" width=800px >}}

二层负载均衡器直接改写目标 MAC 地址的工作原理决定了它与真实的服务器的通信必须是二层可达的，通俗地说就是必须位于同一个子网当中，无法跨 VLAN。


#### IP 隧道
保持原来的数据包不变，新创建一个数据包，把原来数据包的 Headers 和 Payload 整体作为另一个新的数据包的 Payload，在这个新数据包的 Headers 中写入真实服务器的 IP 作为目标地址，然后把它发送出去


### 七层负载均衡


{{<figure src="./application_lb.png#center" width=800px >}}

工作在四层之后的负载均衡模式就无法再进行转发了，只能进行代理，此时真实服务器、负载均衡器、客户端三者之间由两条独立的 TCP 通道来维持通信。

代理根据“哪一方能感知到”的原则，可以分为“正向代理”、“反向代理”和“透明代理”三类.


七层代理可以实现的功能：

- CDN 可以做的缓存方面的工作，如：静态资源缓存、协议升级、安全防护、访问控制
- 智能路由
- 抵御安全攻击
- 微服务链路治理

## metallb 两种模式

### Layer2 模式


部署Layer2模式需要把k8s集群中的ipvs配置打开strictARP，开启之后k8s集群中的kube-proxy会停止响应kube-ipvs0网卡之外的其他网卡的arp请求，而由MetalLB接手处理。







## BGP 模式


## 参考
- https://metallb.io/
- [eBay 流量管理之 DSR 在基础架构中的运用及优化](https://www.infoq.cn/article/rwbisriaej2rpcpbdsgc)
- [负载均衡方案介绍](https://jiapan.me/2022/load-balancing/)