---
title: "Flannel"
date: 2025-02-27T20:51:18+08:00
summary: "flannel 及源码 v0.26.0 实现"
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

### Vxlan(Virtual Extensible LAN 虚拟可扩展局域网）
在vlan的基础之上进行的扩展, 可以划分的vlan个数扩大到16M个


{{<figure src="./vxlan_info.png#center" width=800px >}}

在常用的vxlan模式中，涉及到封包和拆包，这也是Flannel网络传输效率相对低的原因。

### VTEP（VXLAN Tunnel Endpoints，VXLAN隧道端点）
可以是个物理设备，也可以是虚拟设备，flannel创建的flannel.1就是vtep设备,flannel中vxlan所说的封包解包就是由这个设备完成

vtep设置即有ip地址，也有mac地址.

```shell
[root@master-01 opt]# ip --details link show flannel.1
8: flannel.1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UNKNOWN mode DEFAULT group default
    link/ether 0a:08:b0:d6:65:bc brd ff:ff:ff:ff:ff:ff promiscuity 0
    vxlan id 1 local 172.16.7.30 dev ens32 srcport 0 0 dstport 8472 nolearning ageing 300 noudpcsum noudp6zerocsumtx noudp6zerocsumrx addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
```


### VNI（VXLAN Network Identifier，VXLAN 网络标识符）
VNI是一种类似于VLAN ID的用户标识，一个VNI代表了一个租户. 在flannel中，vni默认都是1, 所以这就是为什么flannel创建的vtep设备的名称叫做flannel.1的原因


```shell
[root@master-01 opt]# ip --details link show docker0
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT group default
    link/ether 02:42:54:41:3c:e4 brd ff:ff:ff:ff:ff:ff promiscuity 0
    bridge forward_delay 1500 hello_time 200 max_age 2000 ageing_time 30000 stp_state 0 priority 32768 vlan_filtering 0 vlan_protocol 802.1Q bridge_id 8000.2:42:54:41:3c:e4 designated_root 8000.2:42:54:41:3c:e4 root_port 0 root_path_cost 0 topology_change 0 topology_change_detected 0 hello_timer    0.00 tcn_timer    0.00 topology_change_timer    0.00 gc_timer   21.99 vlan_default_pvid 1 vlan_stats_enabled 0 group_fwd_mask 0 group_address 01:80:c2:00:00:00 mcast_snooping 1 mcast_router 1 mcast_query_use_ifaddr 0 mcast_querier 0 mcast_hash_elasticity 4 mcast_hash_max 512 mcast_last_member_count 2 mcast_startup_query_count 2 mcast_last_member_interval 100 mcast_membership_interval 26000 mcast_querier_interval 25500 mcast_query_interval 12500 mcast_query_response_interval 1000 mcast_startup_query_interval 3125 mcast_stats_enabled 0 mcast_igmp_version 2 mcast_mld_version 1 nf_call_iptables 0 nf_call_ip6tables 0 nf_call_arptables 0 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
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

### FDB表(Forwarding Database 转发数据库)
主要用于网络设备（如交换机）中，以实现二层数据转发。FDB表主要记录MAC地址、VLAN号、端口号和一些标志域等信息，是交换机进行二层数据转发的核心数据结构。

FDB表的主要作用是在交换机内部实现二层数据转发。当交换机收到一个数据帧时，它会根据数据帧的目的MAC地址来查询FDB表，以确定将数据帧从哪个端口转发出去。
如果目的MAC地址在FDB表中存在，交换机就会直接将该数据帧从对应的端口转发出去；如果不存在，交换机则会将该数据帧泛洪到除了接收端口之外的所有端口。


FDB表与ARP表的区别
- 作用层次不同：FDB表用于二层转发，而ARP表用于三层转发。FDB表记录的是MAC地址与端口的映射关系，而ARP表记录的是IP地址与MAC地址的映射关系。
- 查询时机不同：在二层转发过程中，交换机首先查询FDB表；而在三层转发过程中，路由器首先查询路由表，然后根据路由表确定下一跳IP地址，再查询ARP表获取下一跳MAC地址。

```shell
[root@master-01 net.d]# bridge fdb show dev flannel.1
da:9c:34:59:c0:cd dst 172.16.7.31 self permanent
c6:73:f2:93:70:0a dst 172.16.7.32 self permanent
```




## Flannel的大致流程

{{<figure src="./cri_n_cni.png#center" width=800px >}}


1. flannel利用Kubernetes API或者etcd用于存储整个集群的网络配置，其中最主要的内容为设置集群的网络地址空间。例如，设定整个集群内所有容器的IP都取自网段“10.1.0.0/16”。
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
2. flannel在每个主机中运行flanneld作为agent，它会为所在主机从集群的网络地址空间中，获取一个小的网段subnet，本主机内所有容器的IP地址都将从中分配。
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
3. flanneld再将本主机获取的subnet以及用于主机间通信的Public IP，同样通过kubernetes API或者etcd存储起来。
4. flannel利用各种backend ，例如udp，vxlan，host-gw等等，跨主机转发容器间的网络流量，完成容器间的跨主机通信。

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
			gbp:       cfg.GBP,
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
	if config.EnableIPv6 {
		if err := v6Dev.ConfigureIPv6(ip.IP6Net{IP: lease.IPv6Subnet.IP, PrefixLen: 128}, config.IPv6Network); err != nil {
			return nil, fmt.Errorf("failed to configure interface %s: %w", v6Dev.link.Attrs().Name, err)
		}
	}
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
{{<figure src="./flannel_process.png#center" width=800px >}}
只要发送数据包肯定要到达cni0，cni0在这里充当了网桥docker0的作用，二层交换，容器以cni0的网桥作为网关，不管是不是处于同网段都会到达cni0网桥这里.

Flannel为每个主机提供独立的子网，整个集群的网络信息存储在etcd上。对于跨主机的转发，目标容器的IP地址，需要从etcd获取。
- Flannel创建名为flannel0的网桥
- flannel0网桥一端连接docker0网桥，另一端连接flanneld进程
- flanneld进程一端连接etcd，利用etcd管理分配的ip地址资源，同时监控pod地址，建立pod节点路由表
- flanneld进程一端连接docker0和物理网络，配合路由表，完成数据包投递，完成pod之间通讯

步骤：

- IP数据报被封装并通过容器的eth0发送。
- Container1的eth0通过veth对与Docker0交互并将数据包发送到Docker0。然后Docker0转发包。
- Docker0确定Container3的IP地址，通过查询本地路由表到外部容器，并将数据包发送到虚拟NIC Flannel0。
- Flannel0收到的数据包被转发到Flanneld进程。 Flanneld进程封装了数据包通过查询etcd维护的路由表并发送数据包通过主机的eth0。
- 数据包确定网络中的目标主机主机。
- 目的主机的 Flanneld 进程监听8285端口，负责解封包。
- 解封装的数据包将转发到虚拟 NIC Flannel0。
- Flannel0查询路由表，解封包，并将数据包发送到Docker0。
- Docker0确定目标容器并发送包到目标容器。


### hostgw 
它的原理非常简单，直接添加路由，将目的主机当做网关，直接路由原始封包。

例如，我们从etcd中监听到一个EventAdded事件subnet为10.1.15.0/24被分配给主机Public IP 192.168.0.100，hostgw要做的工作就是在本主机上添加一条目的地址为10.1.15.0/24，网关地址为192.168.0.100，输出设备为上文中选择的集群间交互的网卡即可。对于EventRemoved事件，只需删除对应的路由


## 参考

- [VXLAN-原理介绍+报文分析+配置实例 ](https://www.cnblogs.com/FengXingZhe008/p/17335124.html)
- [Flannel Vxlan封包原理剖析](https://izsk.me/2022/03/25/Kubernetes-Flannel-Vxlan/)