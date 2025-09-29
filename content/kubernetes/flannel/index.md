---
title: "Flannel"
date: 2025-02-27T20:51:18+08:00
summary: "flannel 源码 v0.26.0 实现: 子网租约管理,三种数据包实现方式"
categories:
  - kubernetes
authors:
  - Danny
tags:
  - k8s
  - cni
  - 源码
---

Flannel是CoreOS开源的，Overlay模式的CNI网络插件，Flannel在每个集群节点上运行一个flanneld的代理守护服务，为每个集群节点（HOST）分配一个子网（SUBNET），同时为节点上的容器组（POD）分配IP，在整个集群节点间构建一个虚拟的网络，实现集群内部跨节点通信。

## 基本知识

### VLAN（Virtual Local Area Network 虚拟局域网）
{{<figure src="./vlan_before_n_after.png#center" width=800px >}}
解决广播问题和安全问题的两种方式
- 物理隔离: 配置单独的子网.
- 虚拟隔离: VLAN

我们可以设置交换机每个口所属的VLAN。如果某个口坐的是程序员，他们属于VLAN 10；如果某个口坐的是人事，他们属于VLAN 20；如果某个口坐的是财务，他们属于VLAN 30。
这样，财务发的包，交换机只会转发到VLAN 30的口上。程序员啊，你就监听VLAN 10吧，里面除了代码，啥都没有。

而且对于交换机来讲，每个VLAN的口都是可以重新设置的。一个财务走了，把他所在座位的口从VLAN 30移除掉，来了一个程序员，坐在财务的位置上，就把这个口设置为VLAN 10，十分灵活。

VLAN具备以下优点：

- 限制广播域：广播域被限制在一个VLAN内，节省了带宽，提高了网络处理能力。
- 增强局域网的安全性：不同VLAN内的报文在传输时相互隔离，即一个VLAN内的用户不能和其它VLAN内的用户直接通信。
- 提高了网络的健壮性：故障被限制在一个VLAN内，本VLAN内的故障不会影响其他VLAN的正常工作。
- 灵活构建虚拟工作组：用VLAN可以划分不同的用户到不同的工作组，同一工作组的用户也不必局限于某一固定的物理范围，网络构建和维护更方便灵活。

| 表头 |                Vlan                |             子网              |
|:--:|:----------------------------------:|:---------------------------:|
| 区别 | 1. 划分二层网络 2. 可划分4094个vlan,设备数量不受限制 | 1. 划分三层网络 2. 划分网段数量影响子网设备数量 |
| 联系 |         同一 vlan 可以划分一或多个网段         |      同一子网可以划分一或多个vlan       |



{{<figure src="./vlan_structure.png#center" width=800px >}}


#### VLAN的使用场景
VLAN的常见使用场景包括：VLAN间用户的二层隔离，VLAN间用户的三层互访

VLAN间用户的二层隔离 
{{<figure src="./vlan_department.png#center" width=800px >}}

1. 为了保证部门内员工的位置调整后，访问网络资源的权限不变，可在公司的交换机Switch_1上配置基于IP子网划分VLAN。这样，服务器的不同网段就划分到不同的VLAN，访问服务器不同应用服务的数据流就会隔离，提高了安全性。

{{<figure src="./vlan_company.png#center" width=800px >}}
2. 某商务楼内有多家公司，为了降低成本，多家公司共用网络资源，各公司分别连接到一台二层交换机的不同接口，并通过统一的出口访问Internet。


VLAN间用户的三层互访

{{<figure src="./vlan_access_route.png#center" width=800px >}}
某小型公司的两个部门分别通过二层交换机接入到一台三层交换机Switch_3，所属VLAN分别为VLAN2和VLAN3，部门1和部门2的用户互通时，需要经过三层交换机。
可在Switch_1和Switch_2上划分VLAN并将VLAN透传到Switch_3上，然后在Switch_3上为每个VLAN配置一个VLANIF接口，实现VLAN2和VLAN3间的路由。


#### VLAN帧格式
IEEE802.1Q，俗称“Dot One Q”，是经过IEEE认证的对数据帧附加VLAN识别信息的协议。
{{<figure src="./vlan_frame.png#center" width=800px >}}

- TPID: Tag Protocol Identifier
- PRI: Priority，表示数据帧的802.1Q优先级, 取值范围为0～7，值越大优先级越高。当网络阻塞时，设备优先发送优先级高的数据帧。
- CFI: Canonical Format Indicator（标准格式指示位）, CFI取值为0表示MAC地址以标准格式进行封装，为1表示以非标准格式封装。在以太网中，CFI的值为0。
- VID: VLAN ID , VLAN ID取值范围是0～4095。由于0和4095为协议保留取值，所以VLAN ID的有效取值范围是1～4094。

在一个VLAN交换网络中，以太网帧主要有以下两种格式：

- 有标记帧（Tagged帧）：加入了4字节VLAN标签的帧。
- 无标记帧（Untagged帧）：原始的、未加入4字节VLAN标签的帧。
  缺省 VLAN 又称 PVID（Port Default VLAN ID）.

常用设备中：

- 用户主机、服务器、Hub只能收发Untagged帧。
- 交换机、路由器和AC既能收发Tagged帧，也能收发Untagged帧。
- 语音终端、AP等设备可以同时收发一个Tagged帧和一个Untagged帧。

#### 接口类型
根据接口连接对象以及对收发数据帧处理的不同，以太网接口分为：
- Access接口一般用于和不能识别Tag的用户终端（如用户主机、服务器等）相连，或者不需要区分不同VLAN成员时使用。
- Trunk接口一般用于连接交换机、路由器、AP以及可同时收发Tagged帧和Untagged帧的语音终端。
- Hybrid接口既可以用于连接不能识别Tag的用户终端（如用户主机、服务器等）和网络设备（如Hub），也可以用于连接交换机、路由器以及可同时收发Tagged帧和Untagged帧的语音终端、AP。

### Vxlan(Virtual Extensible LAN 虚拟可扩展局域网）
在vlan的基础之上进行的扩展, 可以划分的vlan个数扩大到16M个. VXLAN采用MAC in UDP（User Datagram Protocol）封装方式，是NVO3（Network Virtualization over Layer 3）中的一种网络虚拟化技术。

在常用的vxlan模式中，涉及到封包和拆包，这也是Flannel网络传输效率相对低的原因。

VTEP（VXLAN Tunnel Endpoints VXLAN隧道端点）:可以是个物理设备，也可以是虚拟设备，flannel创建的flannel.1就是vtep设备,flannel中vxlan所说的封包解包就是由这个设备完成

vtep设置即有ip地址，也有mac地址.

```shell
[root@master-01 opt]# ip --details link show flannel.1
8: flannel.1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UNKNOWN mode DEFAULT group default
    link/ether 0a:08:b0:d6:65:bc brd ff:ff:ff:ff:ff:ff promiscuity 0
    vxlan id 1 local 172.16.7.30 dev ens32 srcport 0 0 dstport 8472 nolearning ageing 300 noudpcsum noudp6zerocsumtx noudp6zerocsumrx addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
```



VNI（VXLAN Network Identifier，VXLAN 网络标识符）: 是一种类似于VLAN ID的用户标识，一个VNI代表了一个租户. 在flannel中，vni默认都是1, 所以这就是为什么flannel创建的vtep设备的名称叫做flannel.1的原因


```shell
[root@master-01 opt]# ip --details link show docker0
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT group default
    link/ether 02:42:54:41:3c:e4 brd ff:ff:ff:ff:ff:ff promiscuity 0
    bridge forward_delay 1500 hello_time 200 max_age 2000 ageing_time 30000 stp_state 0 priority 32768 vlan_filtering 0 vlan_protocol 802.1Q bridge_id 8000.2:42:54:41:3c:e4 designated_root 8000.2:42:54:41:3c:e4 root_port 0 root_path_cost 0 topology_change 0 topology_change_detected 0 hello_timer    0.00 tcn_timer    0.00 topology_change_timer    0.00 gc_timer   21.99 vlan_default_pvid 1 vlan_stats_enabled 0 group_fwd_mask 0 group_address 01:80:c2:00:00:00 mcast_snooping 1 mcast_router 1 mcast_query_use_ifaddr 0 mcast_querier 0 mcast_hash_elasticity 4 mcast_hash_max 512 mcast_last_member_count 2 mcast_startup_query_count 2 mcast_last_member_interval 100 mcast_membership_interval 26000 mcast_querier_interval 25500 mcast_query_interval 12500 mcast_query_response_interval 1000 mcast_startup_query_interval 3125 mcast_stats_enabled 0 mcast_igmp_version 2 mcast_mld_version 1 nf_call_iptables 0 nf_call_ip6tables 0 nf_call_arptables 0 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
```

#### 报文解析
{{<figure src="./vxlan_info.png#center" width=800px >}}

右边的为原始报文 Original Ethernet Frame，左边的即为vxlan封装报文. 

Original Ethernet Frame是原始的报文:  pod1访问pod2的报文，因为是个正常网络报文，包含IP header、Ethernet header、及 payload。
- payload 就是数据
- IP header 很自然也就是pod1及pod2的ip地址信息
- Ethernet header: 不是pod1及pod2的MAC地址，而应该是两端flannel.1的MAC地址

vxlan封装报文:
- Vxlan header这里只需要关注一个字段，那就是VNI
- udp header: 中包含有源端口，目的端口.Src.port为node1上的flannel.1的端口,Dst.port(上面也显示为VxlanPort)为node2上flannel.1的端口，Linux内核中默认为VXLAN分配的UDP监听端口为8472
- Outer IP header: 在ip报文中,含有源ip及目的ip，源ip即为flannel.1所绑定的物理ip,即node1节点的eth0 ip,目标ip，那肯定是node2的eth0 ip了, 这个ip是需要根据目标flannel.1的mac地址获得，这部分信息同样维护在flanneld中的.

flanneld中维护了这两部分信息:

- flannel.1的ip与mac地址对应关系，通过flannel.1的ip可以查询到flannel.1 的mac地址
- flannel.1的mac地址及其所在nfde ip对应关系，通过flannel.1的mac地址可以查询到node ip


抓包方式
```shell
# 抓取外层包 udp 协议
tcpdump -i eth0 -nn port 8472
```


### ARP（Address Resolution Protocol地址解析协议）
将IP地址解析为MAC地址的协议

```shell
k8s-172-16-7-30:/etc/kubeasz# ansible -i clusters/test/hosts kube_node  -m shell -a 'ip --detail addr show flannel.1'
172.16.7.32 | CHANGED | rc=0 >>
20: flannel.1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UNKNOWN group default
    link/ether c6:73:f2:93:70:0a brd ff:ff:ff:ff:ff:ff promiscuity 0
    vxlan id 1 local 172.16.7.32 dev ens32 srcport 0 0 dstport 8472 nolearning ageing 300 noudpcsum noudp6zerocsumtx noudp6zerocsumrx numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
    inet 192.168.2.0/32 scope global flannel.1
       valid_lft forever preferred_lft forever
    inet6 fe80::c473:f2ff:fe93:700a/64 scope link
       valid_lft forever preferred_lft forever
172.16.7.31 | CHANGED | rc=0 >>
54: flannel.1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UNKNOWN group default
    link/ether da:9c:34:59:c0:cd brd ff:ff:ff:ff:ff:ff promiscuity 0
    vxlan id 1 local 172.16.7.31 dev ens32 srcport 0 0 dstport 8472 nolearning ageing 300 noudpcsum noudp6zerocsumtx noudp6zerocsumrx numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
    inet 192.168.1.0/32 scope global flannel.1
       valid_lft forever preferred_lft forever
    inet6 fe80::d89c:34ff:fe59:c0cd/64 scope link
       valid_lft forever preferred_lft forever
```

```shell
[root@master-01 net.d]# ip neigh show dev flannel.1
192.168.2.0 lladdr c6:73:f2:93:70:0a PERMANENT
192.168.1.0 lladdr da:9c:34:59:c0:cd PERMANENT
```

#### arping命令
arping命令 是用于发送arp请求到一个相邻主机的工具，arping使用arp数据包，通过ping命令检查设备上的硬件地址。能够测试一个ip地址是否是在网络上已经被使用，并能够获取更多设备信息。

据观察Redhat\CentOS使用的是Linux iputils suite版本的，debian使用的是Thomas Habets。
```shell

root@node1:~# arping
ARPing 2.24, by Thomas Habets <thomas@habets.se>
```
注意两个版本的的arping使用的参数有很大的区别，所以要根据自己的arping版本去使用相应的参数。
```shell
# 查看某个IP的MAC地址
root@node1:~# arping -I ens32 -c 1 172.16.7.31
ARPING 172.16.7.31
60 bytes from 00:0c:29:a5:19:4c (172.16.7.31): index=0 time=460.132 usec

--- 172.16.7.31 statistics ---
1 packets transmitted, 1 packets received,   0% unanswered (0 extra)
rtt min/avg/max/std-dev = 0.460/0.460/0.460/0.000 ms
```

每台主机都会在自己的 ARP 缓冲区中建立一个 ARP 列表，以表示 IP 地址和 MAC 地址之间的对应关系，二层的数据传输靠的就是MAC地址。
不同厂商默认的ARP表老化时间也不一样：思科是 5分钟，华为是 20分钟。ARP 表缓存老化时间过长有时可能会导致一些网络问题.


### FDB表(Forwarding Database 转发数据库)
主要用于网络设备（如交换机）中，以实现二层数据转发。FDB表主要记录MAC地址、VLAN号、端口号和一些标志域等信息，是交换机进行二层数据转发的核心数据结构。

FDB表的主要作用是在交换机内部实现二层数据转发。当交换机收到一个数据帧时，它会根据数据帧的目的MAC地址来查询FDB表，以确定将数据帧从哪个端口转发出去。
如果目的MAC地址在FDB表中存在，交换机就会直接将该数据帧从对应的端口转发出去；如果不存在，交换机则会将该数据帧泛洪到除了接收端口之外的所有端口。

```shell
[root@worker-01 ~]# bridge fdb show dev flannel.1
0a:08:b0:d6:65:bc dst 172.16.7.30 self permanent
c6:73:f2:93:70:0a dst 172.16.7.32 self permanent

[root@worker-02 ~]# bridge fdb show dev flannel.1
0a:08:b0:d6:65:bc dst 172.16.7.30 self permanent
da:9c:34:59:c0:cd dst 172.16.7.31 self permanent
```


FDB表与ARP表的区别
- 作用层次不同：FDB表用于二层转发，而ARP表用于三层转发。FDB表记录的是MAC地址与端口的映射关系，而ARP表记录的是IP地址与MAC地址的映射关系。
- 查询时机不同：在二层转发过程中，交换机首先查询FDB表；而在三层转发过程中，路由器首先查询路由表，然后根据路由表确定下一跳IP地址，再查询ARP表获取下一跳MAC地址。

```shell
# ARP表

[root@worker-01 ~]# ip neigh show dev flannel.1
192.168.0.0 lladdr 0a:08:b0:d6:65:bc PERMANENT
192.168.2.0 lladdr c6:73:f2:93:70:0a PERMANENT

[root@worker-02 ~]# ip neigh show dev flannel.1
192.168.1.0 lladdr da:9c:34:59:c0:cd PERMANENT
192.168.0.0 lladdr 0a:08:b0:d6:65:bc PERMANENT
```

### ip 命令
如今很多系统管理员依然通过组合使用诸如ifconfig、route、arp和netstat等命令行工具(统称为net-tools)来配置网络功能，解决网络故障。
net-tools起源于BSD的TCP/IP工具箱，后来成为老版本Linux内核中配置网络功能的工具。但自2001年起，Linux社区已经对其停止维护；
iproute2的核心命令是ip.

{{<figure src="./net-tools_vs_iproute2.png#center" width=800px >}}
{{<figure src="./ip_command.png#center" width=800px >}}


一张路由表中会有多条路由规则。每一条规则至少包含这三项信息。

1. 目的网络：这个包想去哪儿？
2. 出口设备：将包从哪个口扔出去？
3. 下一跳网关：下一个路由器的地址。


静态路由配置
```shell
# 路由管理
[root@worker-01 ~]# ip route help
Usage: ip route { list | flush } SELECTOR
       ip route save SELECTOR
       ip route restore
       ip route showdump
       ip route get ADDRESS [ from ADDRESS iif STRING ]
                            [ oif STRING ] [ tos TOS ]
                            [ mark NUMBER ] [ vrf NAME ]
                            [ uid NUMBER ]
       ip route { add | del | change | append | replace } ROUTE
SELECTOR := [ root PREFIX ] [ match PREFIX ] [ exact PREFIX ]
            [ table TABLE_ID ] [ vrf NAME ] [ proto RTPROTO ]
            [ type TYPE ] [ scope SCOPE ]
ROUTE := NODE_SPEC [ INFO_SPEC ]
NODE_SPEC := [ TYPE ] PREFIX [ tos TOS ]
             [ table TABLE_ID ] [ proto RTPROTO ]
             [ scope SCOPE ] [ metric METRIC ]
INFO_SPEC := NH OPTIONS FLAGS [ nexthop NH ]...
NH := [ encap ENCAPTYPE ENCAPHDR ] [ via [ FAMILY ] ADDRESS ]
	    [ dev STRING ] [ weight NUMBER ] NHFLAGS
FAMILY := [ inet | inet6 | ipx | dnet | mpls | bridge | link ]
OPTIONS := FLAGS [ mtu NUMBER ] [ advmss NUMBER ] [ as [ to ] ADDRESS ]
           [ rtt TIME ] [ rttvar TIME ] [ reordering NUMBER ]
           [ window NUMBER ] [ cwnd NUMBER ] [ initcwnd NUMBER ]
           [ ssthresh NUMBER ] [ realms REALM ] [ src ADDRESS ]
           [ rto_min TIME ] [ hoplimit NUMBER ] [ initrwnd NUMBER ]
           [ features FEATURES ] [ quickack BOOL ] [ congctl NAME ]
           [ pref PREF ] [ expires TIME ]
TYPE := { unicast | local | broadcast | multicast | throw |
          unreachable | prohibit | blackhole | nat }
TABLE_ID := [ local | main | default | all | NUMBER ]
SCOPE := [ host | link | global | NUMBER ]
NHFLAGS := [ onlink | pervasive ]
RTPROTO := [ kernel | boot | static | NUMBER ]
PREF := [ low | medium | high ]
TIME := NUMBER[s|ms]
BOOL := [1|0]
FEATURES := ecn
ENCAPTYPE := [ mpls | ip | ip6 ]
ENCAPHDR := [ MPLSLABEL ]

# 添加路由写法: ip route add [network/prefix] via [gateway] dev [interface]
$ ip route add 10.176.48.0/20 via 10.173.32.1 dev eth0，# 就说明要去10.176.48.0/20这个目标网络，要从eth0端口出去，经过10.173.32.1。

# 设置系统默认路由
$ ip route add default via 192.168.1.254 

# 检查与特定目标IP地址的连通性
$ ip route get 8.8.8.8

# 在真实的复杂的网络环境中，除了可以根据目的ip地址配置路由外，还可以根据多个参数来配置路由，这就称为策略路由

# 表示从192.168.1.10/24这个网段来的，使用table 10中的路由表，而从192.168.2.0/24网段来的，使用table20的路由表
$ ip rule add from 192.168.1.0/24 table 10 
$ ip rule add from 192.168.2.0/24 table 20

# 下一跳有两个地方，分别是100.100.100.1和200.200.200.1，权重分别为1比2。
$ ip route add default scope global nexthop via 100.100.100.1 weight 1 nexthop via 200.200.200.1 weight 2
```



```shell
# 设备管理
[root@master-01 ~]# ip link help
Usage: ip link add [link DEV] [ name ] NAME
                   [ txqueuelen PACKETS ]
                   [ address LLADDR ]
                   [ broadcast LLADDR ]
                   [ mtu MTU ] [index IDX ]
                   [ numtxqueues QUEUE_COUNT ]
                   [ numrxqueues QUEUE_COUNT ]
                   type TYPE [ ARGS ]

       ip link delete { DEVICE | dev DEVICE | group DEVGROUP } type TYPE [ ARGS ]

       ip link set { DEVICE | dev DEVICE | group DEVGROUP }
	                  [ { up | down } ]
	                  [ type TYPE ARGS ]
	                  [ arp { on | off } ]
	                  [ dynamic { on | off } ]
	                  [ multicast { on | off } ]
	                  [ allmulticast { on | off } ]
	                  [ promisc { on | off } ]
	                  [ trailers { on | off } ]
	                  [ carrier { on | off } ]
	                  [ txqueuelen PACKETS ]
	                  [ name NEWNAME ]
	                  [ address LLADDR ]
	                  [ broadcast LLADDR ]
	                  [ mtu MTU ]
	                  [ netns { PID | NAME } ]
	                  [ link-netnsid ID ]
			  [ alias NAME ]
	                  [ vf NUM [ mac LLADDR ]
				   [ vlan VLANID [ qos VLAN-QOS ] [ proto VLAN-PROTO ] ]
				   [ rate TXRATE ]
				   [ max_tx_rate TXRATE ]
				   [ min_tx_rate TXRATE ]
				   [ spoofchk { on | off} ]
				   [ query_rss { on | off} ]
				   [ state { auto | enable | disable} ] ]
				   [ trust { on | off} ] ]
				   [ node_guid { eui64 } ]
				   [ port_guid { eui64 } ]
			  [ xdp { off |
				  object FILE [ section NAME ] [ verbose ] |
				  pinned FILE } ]
			  [ master DEVICE ][ vrf NAME ]
			  [ nomaster ]
			  [ addrgenmode { eui64 | none | stable_secret | random } ]
	                  [ protodown { on | off } ]

       ip link show [ DEVICE | group GROUP ] [up] [master DEV] [vrf NAME] [type TYPE]

       ip link xstats type TYPE [ ARGS ]

       ip link afstats [ dev DEVICE ]

       ip link help [ TYPE ]

TYPE := { vlan | veth | vcan | dummy | ifb | macvlan | macvtap |
          bridge | bond | team | ipoib | ip6tnl | ipip | sit | vxlan |
          gre | gretap | ip6gre | ip6gretap | vti | nlmon | team_slave |
          bond_slave | ipvlan | geneve | bridge_slave | vrf | macsec }
# 创建网络命名空间 ns1
ip netns add ns1

# 网卡连接到网桥上
ip link set eth0 master cni0

# 从网桥解绑eth0
ip link set eth0 nomaster

# 创建 veth pair 设备，一端叫eth0 ，另一端叫做 vethb4963f3
ip link add eth0 type veth peer name vethb4963f3

# 配置虚拟网卡的IP并启用
ip netns exec ns1 ip addr add 10.1.1.2/24 dev vethDemo0


```

```shell
[root@master-01 ~]# ip addr show flannel.1
7: flannel.1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UNKNOWN group default
    link/ether 0a:08:b0:d6:65:bc brd ff:ff:ff:ff:ff:ff
    inet 192.168.0.0/32 scope global flannel.1
       valid_lft forever preferred_lft forever
    inet6 fe80::808:b0ff:fed6:65bc/64 scope link
       valid_lft forever preferred_lft forever
```
- <BROADCAST,MULTICAST,UP,LOWER_UP> 是 net_device flags 网络设备的状态标识: UP 表示网卡处于启动的状态；BROADCAST 表示这个网卡有广播地址，可以发送广播包；MULTICAST 表示网卡可以发送多播包；LOWER_UP 表示 L1 是启动的，也即网线插着呢。


## Flannel的大致流程

{{<figure src="./cri_n_cni.png#center" width=800px >}}


1. flannel利用Kubernetes API或者etcd用于存储整个集群的网络配置，其中最主要的内容为设置集群的网络地址空间。
flannel上各Node的IP子网分配均基于K8S Node的spec.podCIDR属性(这依赖cluster-CIDR 配置). 例如k8s为 worker-02 节点分配的podCIDR为:192.168.2.0/24）
```shell
$ kubectl get node worker-02 -o yaml
apiVersion: v1
kind: Node
metadata:
  annotations:
    flannel.alpha.coreos.com/backend-data: '{"VNI":1,"VtepMAC":"c6:73:f2:93:70:0a"}'
    flannel.alpha.coreos.com/backend-type: vxlan
    flannel.alpha.coreos.com/kube-subnet-manager: "true"
    flannel.alpha.coreos.com/public-ip: 172.16.7.32
    node.alpha.kubernetes.io/ttl: "0"
    volumes.kubernetes.io/controller-managed-attach-detach: "true"
  creationTimestamp: "2025-02-27T14:08:53Z"
  labels:
    beta.kubernetes.io/arch: amd64
    beta.kubernetes.io/os: linux
    kubernetes.io/arch: amd64
    kubernetes.io/hostname: worker-02
    kubernetes.io/os: linux
    kubernetes.io/role: node
  name: worker-02
  resourceVersion: "12437160"
  uid: 09211d92-6344-4561-877a-91899f1490bc
spec:
  podCIDR: 192.168.2.0/24
  podCIDRs:
  - 192.168.2.0/24
```
```go
func newSubnetManager(ctx context.Context) (subnet.Manager, error) {
	if opts.kubeSubnetMgr { // api 的方式
		return kube.NewSubnetManager(ctx,
			opts.kubeApiUrl,
			opts.kubeConfigFile,
			opts.kubeAnnotationPrefix,
			opts.netConfPath,
			opts.setNodeNetworkUnavailable)
	}
    // etcd 方式
	cfg := &etcd.EtcdConfig{
		Endpoints: strings.Split(opts.etcdEndpoints, ","),
		Keyfile:   opts.etcdKeyfile,
		Certfile:  opts.etcdCertfile,
		CAFile:    opts.etcdCAFile,
		Prefix:    opts.etcdPrefix,
		Username:  opts.etcdUsername,
		Password:  opts.etcdPassword,
	}

	// Attempt to renew the lease for the subnet specified in the subnetFile
	prevSubnet := ReadCIDRFromSubnetFile(opts.subnetFile, "FLANNEL_SUBNET")
	prevIPv6Subnet := ReadIP6CIDRFromSubnetFile(opts.subnetFile, "FLANNEL_IPV6_SUBNET")

	return etcd.NewLocalManager(ctx, cfg, prevSubnet, prevIPv6Subnet, opts.subnetLeaseRenewMargin)
}
```
2. flannel在每个主机中运行 flanneld 作为agent，它会为所在主机从集群的网络地址空间中，获取一个小的网段subnet，本主机内所有容器的IP地址都将从中分配。
```go
// https://github.com/flannel-io/flannel/blob/8a6570f4e4411473d59538e101ddf95173ab9f07/pkg/subnet/kube/kube.go

func (m *kubeSubnetManager) HandleSubnetFile(path string, config *subnet.Config, ipMasq bool, sn ip.IP4Net, ipv6sn ip.IP6Net, mtu int) error {
	// 更新 snFileInfo
	m.snFileInfo = &subnetFileInfo{
		path:   path,
		ipMask: ipMasq,
		sn:     sn,
		IPv6sn: ipv6sn,
		mtu:    mtu,
	}
	// 写入 subnet 文件
	return subnet.WriteSubnetFile(path, config, ipMasq, sn, ipv6sn, mtu)
}
```
```shell
worker-01:/# cat /run/flannel/subnet.env
FLANNEL_NETWORK=192.168.0.0/16
FLANNEL_SUBNET=192.168.1.1/24
FLANNEL_MTU=1450
FLANNEL_IPMASQ=true
```
3. flanneld 再将本主机获取的subnet以及用于主机间通信的Public IP，同样通过kubernetes API或者etcd存储起来。
4. flannel利用各种backend ，例如udp，vxlan，host-gw等等，跨主机转发容器间的网络流量，完成容器间的跨主机通信。
```shell
[root@master-01 ~]# cat /etc/cni/net.d/10-flannel.conflist
{
  "name": "cbr0",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "flannel",
      "delegate": {
        "hairpinMode": true,
        "isDefaultGateway": true
      }
    },
    {
      "type": "portmap",
      "capabilities": {
        "portMappings": true
      }
    }
  ]
}
```
Delegate字段的意思是，这个CNI插件并不会自己做事儿，而是会调用Delegate指定的某种CNI内置插件来完成。对于Flannel来说，它调用的Delegate插件，就是前面介绍到的CNI bridge插件。


```shell
# Flannel CNI插件补充后的、完整的Delegate字段
{
    "hairpinMode":true,
    "ipMasq":false,
    "ipam":{
        "routes":[
            {
                "dst":"10.244.0.0/16"
            }
        ],
        "subnet":"10.244.1.0/24",
        "type":"host-local"
    },
    "isDefaultGateway":true,
    "isGateway":true,
    "mtu":1410,
    "name":"cbr0",
    "type":"bridge"
}
```

插件二进制调用
```go
// https://github.com/flannel-io/cni-plugin/blob/088da1a9c0def0cb57fb77e53da4979fe41d8494/flannel.go

func cmdAdd(args *skel.CmdArgs) error {
	n, err := loadFlannelNetConf(args.StdinData)
	if err != nil {
		return fmt.Errorf("loadFlannelNetConf failed: %w", err)
	}
	
	// 获取 subnet.env 信息
	fenv, err := loadFlannelSubnetEnv(n.SubnetFile)
	if err != nil {
		return fmt.Errorf("loadFlannelSubnetEnv failed: %w", err)
	}

    // 校验操作...

	return doCmdAdd(args, n, fenv)
}

func doCmdAdd(args *skel.CmdArgs, n *NetConf, fenv *subnetEnv) error {
	n.Delegate["name"] = n.Name


	if !hasKey(n.Delegate, "type") {
		// 不存在,默认调用 type:bridge 进行操作
		n.Delegate["type"] = "bridge"
	}

    // ...

	if n.Delegate["type"].(string) == "bridge" {
		if !hasKey(n.Delegate, "isGateway") {
			n.Delegate["isGateway"] = true
		}
	}
    // ..

	// 获取 ipam 分配插件
	ipam, err := getDelegateIPAM(n, fenv)
	if err != nil {
		return fmt.Errorf("failed to assemble Delegate IPAM: %w", err)
	}
	n.Delegate["ipam"] = ipam
	fmt.Fprintf(os.Stderr, "\n%#v\n", n.Delegate)

	
	return delegateAdd(args.ContainerID, n.DataDir, n.Delegate)
}


func delegateAdd(cid, dataDir string, netconf map[string]interface{}) error {
	netconfBytes, err := json.Marshal(netconf)
	fmt.Fprintf(os.Stderr, "delegateAdd: netconf sent to delegate plugin:\n")
	os.Stderr.Write(netconfBytes)
	if err != nil {
		return fmt.Errorf("error serializing delegate netconf: %v", err)
	}

	// save the rendered netconf for cmdDel
	if err = saveScratchNetConf(cid, dataDir, netconfBytes); err != nil {
		return err
	}

	// 调用 type 指定的插件
	result, err := invoke.DelegateAdd(context.TODO(), netconf["type"].(string), netconfBytes, nil)
	if err != nil {
		err = fmt.Errorf("failed to delegate add: %w", err)
		return err
	}
	return result.Print()
}
```

```go
// 获取 ipam
func getDelegateIPAM(n *NetConf, fenv *subnetEnv) (map[string]interface{}, error) {
	ipam := n.IPAM
	if ipam == nil {
		ipam = map[string]interface{}{}
	}

	// 如果没有指定的化使用 host-local
	if !hasKey(ipam, "type") {
		ipam["type"] = "host-local"
	}

	var rangesSlice [][]map[string]interface{}

	if fenv.sn != nil && fenv.sn.String() != "" {
		rangesSlice = append(rangesSlice, []map[string]interface{}{
			{"subnet": fenv.sn.String()},
		},
		)
	}

	if fenv.ip6Sn != nil && fenv.ip6Sn.String() != "" {
		rangesSlice = append(rangesSlice, []map[string]interface{}{
			{"subnet": fenv.ip6Sn.String()},
		},
		)
	}

	ipam["ranges"] = rangesSlice

	rtes, err := getIPAMRoutes(n)
	if err != nil {
		return nil, fmt.Errorf("failed to read IPAM routes: %w", err)
	}

	for _, nw := range fenv.nws {
		if nw != nil {
			rtes = append(rtes, types.Route{Dst: *nw})
		}
	}

    // ...

	ipam["routes"] = rtes

	return ipam, nil
}

```

## 三种主要的 backend
Flannel的数据包在集群节点间转发是由backend实现的，目前，已经支持核心官方推荐的模式有UDP、VXLAN、HOST-GW，以及扩展试用实验的模式有 IPIP，AWS VPC、GCE、Ali VPC、Tencent VPC等路由，其中VXLAN模式在实际的生产中使用最多。

| 模式	| 底层网络要求 | 	实现模式	| 封包/解包 |	overlay网络	| 转发效率 |
| :--: |:------:|:--------------------------:|:-----:|:---------:|:----:|
| Flannel UDP |  三层互通  |             overlay             |  用户态  |    三层     |  低   |
| Flannel VXLAN |  三层互通  |             overlay             |  内核态  |     二层      |  中   |
| Flannel host-gw |  二层互通  |            	路由            |   无   |    三层     |  高   |
| IPIP模式 |  三层互通  |             overlay             |  内核态  |    三层     |  高   |
| Cloud VPC |  三层互通  |             	路由            |   无   |    三层     |  高   |

Directrouting：同时支持VXLAN和Host-GW工作模式

{{<figure src="./flannel_backend.png#center" width=800px >}}
* 一种是用户态的 udp，这种是最早期的实现；
* 然后是内核的 Vxlan，这两种都算是 overlay 的方案。Vxlan 的性能会比较好一点，但是它对内核的版本是有要求的，需要内核支持 Vxlan 的特性功能；
* 如果你的集群规模不够大，又处于同一个二层域，也可以选择采用 host-gw 的方式。这种方式的 backend 基本上是由一段广播路由规则来启动的，性能比较高




### vxlan 模式

启动后会完成以下几件事情：

1. 启动容器会把/etc/kube-flannel/cni-conf.json文件复制到/etc/cni/net.d/10-flannel.conflist，这个文件是容器启动时从配置项挂载到容器上的，可以通过修改flannel部署的yaml文件来修改配置，选择使用其它的cni插件。
2. 运行容器会从api-server中获取属于本节点的pod-cidr，然后写一个配置文件/run/flannel/subnet.env给flannel-cni用
3. 如果是vxlan模式，则创建一个名为flannel.1的vxlan设备（关闭了自动学习机制），把这个设备的MAC地址和IP以及本节点的IP记录到节点的注解中。
4. 启动一个协程，不断地检查本机的路由信息是否被删除，如果检查到缺失，则重新创建，防止误删导致网络不通的情况。
5. 从api-server或etcd订阅资源变化的事件，维护路由表项、arp 表、fdb表
```go

func (be *VXLANBackend) RegisterNetwork(ctx context.Context, wg *sync.WaitGroup, config *subnet.Config) (backend.Network, error) {
	// Parse our configuration
	cfg := struct {
		VNI           int
		Port          int
		MTU           int
		GBP           bool
		Learning      bool
		DirectRouting bool
	}{
		VNI: defaultVNI,
		MTU: be.extIface.Iface.MTU,
	}

	if len(config.Backend) > 0 {
		if err := json.Unmarshal(config.Backend, &cfg); err != nil {
			return nil, fmt.Errorf("error decoding VXLAN backend config: %v", err)
		}
	}
	log.Infof("VXLAN config: VNI=%d Port=%d GBP=%v Learning=%v DirectRouting=%v", cfg.VNI, cfg.Port, cfg.GBP, cfg.Learning, cfg.DirectRouting)

	var dev, v6Dev *vxlanDevice
	var err error

	// When flannel is restarted, it will get the MAC address from the node annotations to set flannel.1 MAC address
	var hwAddr, hwAddrv6 net.HardwareAddr

	macStr, macStrv6 := be.subnetMgr.GetStoredMacAddresses(ctx)
	if macStr != "" {
		hwAddr, err = net.ParseMAC(macStr)
		if err != nil {
			log.Errorf("Failed to parse mac addr(%s): %v", macStr, err)
		}
		log.Infof("Interface flannel.%d mac address set to: %s", cfg.VNI, macStr)
	}

	if config.EnableIPv4 {
		devAttrs := vxlanDeviceAttrs{
			vni:       uint32(cfg.VNI),
			name:      fmt.Sprintf("flannel.%d", cfg.VNI),
			MTU:       cfg.MTU,
			vtepIndex: be.extIface.Iface.Index,
			vtepAddr:  be.extIface.IfaceAddr,
			vtepPort:  cfg.Port,
			gbp:       cfg.GBP, // Group Based Policy  基于组的策略进行微分段和宏分段
			learning:  cfg.Learning,
			hwAddr:    hwAddr,
		}
        // 创建flannel.1的vxlan设备
		dev, err = newVXLANDevice(&devAttrs)
		if err != nil {
			return nil, err
		}
		dev.directRouting = cfg.DirectRouting
	}

    // ... ip v6 设置

	subnetAttrs, err := newSubnetAttrs(be.extIface.ExtAddr, be.extIface.ExtV6Addr, uint32(cfg.VNI), dev, v6Dev)
	if err != nil {
		return nil, err
	}

	lease, err := be.subnetMgr.AcquireLease(ctx, subnetAttrs)
	switch err {
	case nil:
	case context.Canceled, context.DeadlineExceeded:
		return nil, err
	default:
		return nil, fmt.Errorf("failed to acquire lease: %v", err)
	}

	// Ensure that the device has a /32 address so that no broadcast routes are created.
	// This IP is just used as a source address for host to workload traffic (so
	// the return path for the traffic has an address on the flannel network to use as the destination)
	if config.EnableIPv4 {
		if err := dev.Configure(ip.IP4Net{IP: lease.Subnet.IP, PrefixLen: 32}, config.Network); err != nil {
			return nil, fmt.Errorf("failed to configure interface %s: %w", dev.link.Attrs().Name, err)
		}
	}
    // ...
	
	return newNetwork(be.subnetMgr, be.extIface, dev, v6Dev, ip.IP4Net{}, lease, cfg.MTU)
}

```






```go
// https://github.com/flannel-io/flannel/blob/d1eeea067e12865d9aaa79c5300d090719a7ae5a/pkg/backend/vxlan/vxlan_network.go
func (nw *network) Run(ctx context.Context) {
	wg := sync.WaitGroup{}

	log.V(0).Info("watching for new subnet leases")
	events := make(chan []lease.Event)
	wg.Add(1)
	go func() {
		// 监听 lease
		subnet.WatchLeases(ctx, nw.subnetMgr, nw.SubnetLease, events)
		log.V(1).Info("WatchLeases exited")
		wg.Done()
	}()

	defer wg.Wait()

	for {
		evtBatch, ok := <-events
		if !ok {
			log.Infof("evts chan closed")
			return
		}
		nw.handleSubnetEvents(evtBatch)
	}
}

// 处理事件
func (nw *network) handleSubnetEvents(batch []lease.Event) {
	for _, event := range batch {
		sn := event.Lease.Subnet
		v6Sn := event.Lease.IPv6Subnet
		attrs := event.Lease.Attrs
		log.Infof("Received Subnet Event with VxLan: %s", attrs.String())
		if attrs.BackendType != "vxlan" {
			log.Warningf("ignoring non-vxlan v4Subnet(%s) v6Subnet(%s): type=%v", sn, v6Sn, attrs.BackendType)
			continue
		}

		var (
			vxlanAttrs, v6VxlanAttrs           vxlanLeaseAttrs
			directRoutingOK, v6DirectRoutingOK bool
			directRoute, v6DirectRoute         netlink.Route
			vxlanRoute, v6VxlanRoute           netlink.Route
		)

		if event.Lease.EnableIPv4 && nw.dev != nil {
			if err := json.Unmarshal(attrs.BackendData, &vxlanAttrs); err != nil {
				log.Error("error decoding subnet lease JSON: ", err)
				continue
			}

			// This route is used when traffic should be vxlan encapsulated
			vxlanRoute = netlink.Route{
				LinkIndex: nw.dev.link.Attrs().Index,
				Scope:     netlink.SCOPE_UNIVERSE,
				Dst:       sn.ToIPNet(),
				Gw:        sn.IP.ToIP(),
			}
			vxlanRoute.SetFlag(syscall.RTNH_F_ONLINK)

			// directRouting is where the remote host is on the same subnet so vxlan isn't required.
			directRoute = netlink.Route{
				Dst: sn.ToIPNet(),
				Gw:  attrs.PublicIP.ToIP(),
			}
			if nw.dev.directRouting {
				// 判断是否可以路由，不能路由则使用隧道转发 ip route get
				if dr, err := ip.DirectRouting(attrs.PublicIP.ToIP()); err != nil {
					log.Error(err)
				} else {
					directRoutingOK = dr
				}
			}
		}

        // ... ip v6 处理

		switch event.Type {
		case lease.EventAdded:
			if event.Lease.EnableIPv4 {
				if directRoutingOK {
					log.V(2).Infof("Adding direct route to subnet: %s PublicIP: %s", sn, attrs.PublicIP)

					if err := retry.Do(func() error {
						return netlink.RouteReplace(&directRoute)
					}); err != nil {
						log.Errorf("Error adding route to %v via %v: %v", sn, attrs.PublicIP, err)
						continue
					}
				} else {
					log.V(2).Infof("adding subnet: %s PublicIP: %s VtepMAC: %s", sn, attrs.PublicIP, net.HardwareAddr(vxlanAttrs.VtepMAC))
					if err := retry.Do(func() error {
						// 新增一条邻居表信息 ip neigh replace
						return nw.dev.AddARP(neighbor{IP: sn.IP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)})
					}); err != nil {
						log.Error("AddARP failed: ", err)
						continue
					}

					if err := retry.Do(func() error {
						// 新增一条fdb（forwarding database)记录: ip neigh replace
						return nw.dev.AddFDB(neighbor{IP: attrs.PublicIP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)})
					}); err != nil {
						log.Error("AddFDB failed: ", err)

						// Try to clean up the ARP entry then continue
						if err := retry.Do(func() error {
							return nw.dev.DelARP(neighbor{IP: event.Lease.Subnet.IP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)})
						}); err != nil {
							log.Error("DelARP failed: ", err)
						}

						continue
					}

					// Set the route - the kernel would ARP for the Gw IP address if it hadn't already been set above so make sure
					// this is done last.
					if err := retry.Do(func() error {
						return netlink.RouteReplace(&vxlanRoute)
					}); err != nil {
						log.Errorf("failed to add vxlanRoute (%s -> %s): %v", vxlanRoute.Dst, vxlanRoute.Gw, err)

						// Try to clean up both the ARP and FDB entries then continue
						if err := nw.dev.DelARP(neighbor{IP: event.Lease.Subnet.IP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
							log.Error("DelARP failed: ", err)
						}

						if err := nw.dev.DelFDB(neighbor{IP: event.Lease.Attrs.PublicIP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
							log.Error("DelFDB failed: ", err)
						}

						continue
					}
				}
			}
            // .... ip v6 处理
		case lease.EventRemoved: // 删除操作
            
            // .... ip v6 处理
		default:
			log.Error("internal error: unknown event type: ", int(event.Type))
		}
	}
}

```

#### 实现原理
{{<figure src="./flannel_process.svg#center" width=800px >}}
只要发送数据包肯定要到达cni0，cni0在这里充当了网桥docker0的作用，二层交换，容器以cni0的网桥作为网关，不管是不是处于同网段都会到达cni0网桥这里.

Flannel为每个主机提供独立的子网，整个集群的网络信息存储在etcd上。对于跨主机的转发，目标容器的IP地址，需要从etcd获取。
- Flannel创建名为flannel.1的网桥
- flannel.1网桥一端连接docker0网桥，另一端连接flanneld进程
- flanneld进程一端连接etcd，利用etcd管理分配的ip地址资源，同时监控pod地址，建立pod节点路由表
- flanneld进程一端连接docker0和物理网络，配合路由表，完成数据包投递，完成pod之间通讯

步骤：
```shell
# 节点1
[root@worker-01 ~]# nsenter -t 60054 --net
[root@worker-01 ~]# ip --detail link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
2: tunl0@NONE: <NOARP> mtu 1480 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ipip 0.0.0.0 brd 0.0.0.0 promiscuity 0
    ipip remote any local any ttl inherit nopmtudisc numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
3: eth0@if61: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether ea:2e:d6:4c:b8:89 brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 0
    veth addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
    
[root@worker-01 ~]# ip route
default via 192.168.1.1 dev eth0 # default 这是一条默认路由。当系统需要发送数据包到不在其他特定路由规则中的目标地址时，会使用这条路由. via 192.168.1.1 默认路由的下一跳（网关）是192.168.1.1。所有非本地网络的数据包都将通过这个地址转发。dev eth0 数据包将通过名为 eth0 的网络接口发送。
192.168.0.0/16 via 192.168.1.1 dev eth0
192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.7 #  192.168.1.0/24 这条路由规则适用于IP地址范围为192.168.1.0到192.168.1.255的网络. dev eth0: 数据包将通过名为 eth0 的网络接口发送. proto kernel这条路由是由内核自动添加的. scope link: 这是一个链路范围的路由，意味着目标地址在直接连接的网络上。 src 192.168.1.7: 当从这个接口发送数据包时，源IP地址将是 192.168.1.7


# 节点2
[root@worker-02 ~]# ip -d link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
2: tunl0@NONE: <NOARP> mtu 1480 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ipip 0.0.0.0 brd 0.0.0.0 promiscuity 0
    ipip remote any local any ttl inherit nopmtudisc numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
3: eth0@if23: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 9e:ad:7b:6c:71:cd brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 0
    veth addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
[root@worker-02 ~]# ip route
default via 192.168.2.1 dev eth0
192.168.0.0/16 via 192.168.2.1 dev eth0
192.168.2.0/24 dev eth0 proto kernel scope link src 192.168.2.3
```
- IP数据报被封装并通过容器的eth0发送。
```shell
[root@worker-01 ~]# bridge link show docker0
61: vethadce958f state UP @docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 master cni0 state forwarding priority 32 cost 2

```
- Container1的eth0通过veth对与Docker0交互并将数据包发送到Docker0。然后Docker0转发包。
```shell
[root@worker-01 ~]# ip route
default via 172.16.0.254 dev ens32 proto static metric 100
172.16.0.0/16 dev ens32 proto kernel scope link src 172.16.7.31 metric 100
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1
192.168.0.0/24 via 192.168.0.0 dev flannel.1 onlink
192.168.1.0/24 dev cni0 proto kernel scope link src 192.168.1.1
192.168.2.0/24 via 192.168.2.0 dev flannel.1 onlink
192.168.37.192/26 via 172.16.7.32 dev tunl0 proto bird onlink
blackhole 192.168.171.0/26 proto bird
192.168.171.1 dev cali3261fb6a4b6 scope link
192.168.171.2 dev cali005e8af0501 scope link
192.168.171.3 dev cali24ec0f5f8e5 scope link
192.168.171.4 dev calif06d79561a0 scope link
192.168.171.7 dev cali27583b52bad scope link
192.168.171.8 dev cali11239f98883 scope link
192.168.171.9 dev cali8bac6c0ff3f scope link
192.168.171.34 dev cali2528fb049ef scope link
192.168.171.42 dev caliba820c98c54 scope link
192.168.171.43 dev cali955f4579127 scope link
192.168.171.44 dev calid04592fe6a2 scope link
192.168.171.45 dev cali6043633cea4 scope link
192.168.171.46 dev calid75abf4f5e0 scope link
192.168.184.64/26 via 172.16.7.30 dev tunl0 proto bird onlink



[root@worker-02 ~]# ip route
default via 172.16.0.254 dev ens32 proto static metric 100
172.16.0.0/16 dev ens32 proto kernel scope link src 172.16.7.32 metric 100
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1
192.168.0.0/24 via 192.168.0.0 dev flannel.1 onlink
192.168.1.0/24 via 192.168.1.0 dev flannel.1 onlink
192.168.2.0/24 dev cni0 proto kernel scope link src 192.168.2.1
blackhole 192.168.37.192/26 proto bird
192.168.37.193 dev cali7e442cf0311 scope link
192.168.37.196 dev cali15c7619fccc scope link
192.168.37.204 dev calicac1c622361 scope link
192.168.184.64/26 via 172.16.7.30 dev tunl0 proto bird onlink
```
- Docker0确定Container3的IP地址，通过查询本地路由表到外部容器，并将数据包发送到虚拟NIC Flannel1。
```shell
[root@worker-01 ~]# ip neigh show dev flannel.1
192.168.0.0 lladdr 0a:08:b0:d6:65:bc PERMANENT
192.168.2.0 lladdr c6:73:f2:93:70:0a PERMANENT
```
- Flannel0收到的数据包被转发到Flanneld进程。 Flanneld进程封装了数据包通过查询etcd维护的路由表并发送数据包通过主机的eth0。

```shell
[root@worker-01 ~]# ip neigh show dev ens32
172.16.7.30 lladdr 00:0c:29:e0:d7:e1 REACHABLE
172.16.7.32 lladdr 00:0c:29:b3:7c:bb REACHABLE
172.16.0.254 lladdr 7c:a2:3e:fb:30:c1 REACHABLE
172.16.111.254 lladdr d4:94:e8:08:e6:d6 STALE
172.16.111.253 lladdr 84:5b:12:3f:30:76 STALE

[root@worker-02 ~]# ip neigh show dev ens32
172.16.111.253 lladdr 84:5b:12:3f:30:76 STALE
172.16.111.254 lladdr d4:94:e8:08:e6:d6 STALE
172.16.7.31 lladdr 00:0c:29:a5:19:4c REACHABLE
172.16.7.30 lladdr 00:0c:29:e0:d7:e1 REACHABLE
172.16.0.254 lladdr 7c:a2:3e:fb:30:c1 STALE
```
- 数据包确定网络中的目标主机主机。
- 目的主机的 Flanneld 进程监听8285端口，负责解封包。
- 解封装的数据包将转发到虚拟 NIC Flannel0。
- Flannel0查询路由表，解封包，并将数据包发送到Docker0。
- Docker0确定目标容器并发送包到目标容器。


### hostgw 
“host-gw”的含义: 主机”（Host）会充当这条容器通信路径里的“网关”（Gateway）.

host-gw模式的工作原理，其实就是将每个Flannel子网（Flannel Subnet，比如：10.244.1.0/24）的“下一跳”，设置成了该子网对应的宿主机的IP地址。

例如，我们从etcd中监听到一个EventAdded事件subnet为10.1.15.0/24被分配给主机Public IP 192.168.0.100，hostgw要做的工作就是在本主机上添加一条目的地址为10.1.15.0/24，网关地址为192.168.0.100，输出设备为上文中选择的集群间交互的网卡即可。
对于EventRemoved事件，只需删除对应的路由.



## flannel 子网租约管理

flannel的子网租约系统基于分布式状态机设计，核心数据结构围绕租约生命周期和事件传播构建。

{{<figure src="./subnet_apply.png#center" width=800px >}}

{{<figure src="./two_node_apply_subnet#center" width=800px >}}

- 正常路径（NodeA）：租约创建→事务成功→获得子网
- 冲突路径（NodeB）：租约创建→事务失败→重新选网→事务成功
```go
// https://github.com/flannel-io/flannel/blob/1bcfa6ce99f9a9660a539152a28db7f602b41021/subnet/etcd/registry.go

func (esr *etcdSubnetRegistry) createSubnet(ctx context.Context, sn ip.IP4Net, sn6 ip.IP6Net, attrs *LeaseAttrs, ttl time.Duration) (time.Time, error) {
	key := path.Join(esr.etcdCfg.Prefix, "subnets", MakeSubnetKey(sn, sn6))
	value, err := json.Marshal(attrs)
	if err != nil {
		return time.Time{}, err
	}

	// 1. 创建etcd租约（TTL由flannel配置的--subnet-lease-duration指定，默认24小时）
	lresp, err := esr.cli.Grant(ctx, int64(ttl.Seconds()))
	if err != nil {
		return time.Time{}, err
	}

	// 2. 以事务方式创建子网键，绑定租约ID
	req := etcd.OpPut(key, string(value), etcd.WithLease(lresp.ID))
	cond := etcd.Compare(etcd.Version(key), "=", 0) // 检查键是否不存在（冲突检测）
	tresp, err := esr.cli.Txn(ctx).If(cond).Then(req).Commit()
	if err != nil {
		_, rerr := esr.cli.Revoke(ctx, lresp.ID)
		if rerr != nil {
			log.Error(rerr)
		}
		return time.Time{}, err
	}
	if !tresp.Succeeded {
		_, rerr := esr.cli.Revoke(ctx, lresp.ID)
		if rerr != nil {
			log.Error(rerr)
		}
		return time.Time{}, errSubnetAlreadyexists
	}
    // 3. 计算过期时间（当前时间+TTL）
	exp := time.Now().Add(time.Duration(lresp.TTL) * time.Second)
	return exp, nil
}

```

etcd会自动删除过期租约绑定的键，触发EventRemoved事件。


租约续约流程：节点心跳实现

```go
func (esr *etcdSubnetRegistry) updateSubnet(ctx context.Context, sn ip.IP4Net, sn6 ip.IP6Net, attrs *LeaseAttrs, ttl time.Duration, asof int64) (time.Time, error) {
	key := path.Join(esr.etcdCfg.Prefix, "subnets", MakeSubnetKey(sn, sn6))
	value, err := json.Marshal(attrs)
	if err != nil {
		return time.Time{}, err
	}

	lresp, lerr := esr.cli.Grant(ctx, int64(ttl.Seconds()))
	if lerr != nil {
		return time.Time{}, lerr
	}

	_, perr := esr.kv().Put(ctx, key, string(value), etcd.WithLease(lresp.ID))
	if perr != nil {
		_, rerr := esr.cli.Revoke(ctx, lresp.ID)
		if rerr != nil {
			log.Error(rerr)
		}
		return time.Time{}, perr
	}

	exp := time.Now().Add(time.Duration(lresp.TTL) * time.Second)

	return exp, nil
}

```

## 参考
- https://github.com/flannel-io/flannel
- https://github.com/flannel-io/cni-plugin
- [图文并茂VLAN详解](https://cloud.tencent.com/developer/article/1412795)
- [VXLAN-原理介绍+报文分析+配置实例 ](https://www.cnblogs.com/FengXingZhe008/p/17335124.html)
- [Flannel Vxlan封包原理剖析](https://izsk.me/2022/03/25/Kubernetes-Flannel-Vxlan/)
- [ip route 命令](https://cloud.tencent.com/developer/article/2101102)
- [vlan 基础知识](https://cshihong.github.io/2017/11/05/VLAN%E5%9F%BA%E7%A1%80%E7%9F%A5%E8%AF%86/)