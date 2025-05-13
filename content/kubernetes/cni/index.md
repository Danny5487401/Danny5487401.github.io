<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [CNI Plugin](#cni-plugin)
  - [插件分类](#%E6%8F%92%E4%BB%B6%E5%88%86%E7%B1%BB)
  - [macvlan](#macvlan)
  - [host-local](#host-local)
  - [bridge](#bridge)
    - [hairpin mode](#hairpin-mode)
  - [vlan](#vlan)
- [实现一个 CNI 插件](#%E5%AE%9E%E7%8E%B0%E4%B8%80%E4%B8%AA-cni-%E6%8F%92%E4%BB%B6)
- [cni 调用入口 cri](#cni-%E8%B0%83%E7%94%A8%E5%85%A5%E5%8F%A3-cri)
  - [cni 调用方:pod 初始化 sandbox 时网络设置](#cni-%E8%B0%83%E7%94%A8%E6%96%B9pod-%E5%88%9D%E5%A7%8B%E5%8C%96-sandbox-%E6%97%B6%E7%BD%91%E7%BB%9C%E8%AE%BE%E7%BD%AE)
  - [cni 被调用方: 启动配置解析](#cni-%E8%A2%AB%E8%B0%83%E7%94%A8%E6%96%B9-%E5%90%AF%E5%8A%A8%E9%85%8D%E7%BD%AE%E8%A7%A3%E6%9E%90)
- [模拟 Kubernetes 的 CNI 环境](#%E6%A8%A1%E6%8B%9F-kubernetes-%E7%9A%84-cni-%E7%8E%AF%E5%A2%83)
- [参考](#%E5%8F%82%E8%80%83)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

---
title: "Cni( Container Network Interface)"
date: 2025-01-12T14:52:13+08:00
summary: cni 规范及实现原理, 常见的 cni 插件实现 
categories:
  - kubernetes
  - cni
tags:
  - k8s
  - cni
  - 源码
---


CNI（容器网络接口）规范为容器运行时和网络插件之间提供了一个通用的接口.
CNI 的目的是将网络配置与容器平台解耦，在不同的平台只需要使用不同的网络插件，其他容器化的内容仍然可以复用。


CNI 规范包含以下几个核心组成部分：

- 网络配置的格式：定义了管理员如何定义网络配置。
- 请求协议：描述了容器运行时如何向网络插件发出网络配置或清理请求。
- 插件执行过程：详细阐述了插件如何根据提供的配置执行网络设置或清理。
- 插件委派：允许插件将特定功能委托给其他插件执行。
- 结果返回：定义了插件执行完成后如何向运行时返回结果的数据格式


如果没有 CNI，我们需要手动执行以下操作：

- 创建接口（物理网络接口和虚拟网络接口）
- 创建 veth 对
- 设置命名空间网络
- 设置静态路由
- 配置以太网桥（eth bridge）
- 分配 IP 地址
- 创建 NAT 规则。

## CNI Plugin
github.com/containernetworking/plugins 

### 插件分类

{{<figure src="./plugin_category.png#center" width=800px >}}

Main 插件：创建具体的网络设备
- bridge: Creates a bridge, adds the host and the container to it.
- ipvlan: 所有的虚拟接口都有相同的 mac 地址，而拥有不同的 ip 地址.
- loopback: Set the state of loopback interface to up.
- macvlan: 可以从一个主机接口虚拟出多个macvtap，且每个macvtap设备都拥有不同的mac地址（对应不同的linux字符设备）。
- ptp: 通过veth pair给容器和host创建点对点连接：veth pair一端在container netns内，另一端在host上
- vlan: Allocates a vlan device.
- host-device: Move an already-existing device into a container.
- dummy: Creates a new Dummy device in the container.

IPAM(IP Address Management)插件：负责分配 IP 地址
- dhcp：容器向 DHCP 服务器发起请求，给 Pod 发放或回收 IP 地址；
- host-local：使用预先配置的 IP 地址段来进行分配
- github.com/k8snetworkplumbingwg/whereabouts: cluster-wide ip 分配插件. 比 host-local 多了集群内可以跨节点.

META 插件：其他功能的插件
- tuning：通过 sysctl 调整网络设备参数；
- portmap：通过 iptables 配置端口映射；
- bandwidth：使用 Token Bucket Filter（TBF） 来限流；
- sbr：为网卡设置 source based routing；
- firewall：通过 iptables 给容器网络的进出流量进行限制。

### macvlan

```go
// https://github.com/containernetworking/plugins/blob/fec2d62676cbe4f2fd587b4840c7fc021bead3f9/plugins/main/macvlan/macvlan.go

func cmdAdd(args *skel.CmdArgs) error {
	// /加载一下 CNI 的配置，这个配置包括：CNI 版本、CNI 名称、网络插件类型、IPAM 类型、DNS、以及当前网络插件需要的定制信息如：macvlan 主接口等。
	n, cniVersion, err := loadConf(args, args.Args)
	if err != nil {
		return err
	}
    // 这里判断当前是 3 层网络，还是 2 层网络。
	// n.IPAM.Type 的值是 "host-local"，因此，isLayer3 一定是 true
	isLayer3 := n.IPAM.Type != ""

    // 获取网络空间，并用此网络空间，创建 macvlan 子接口
	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", netns, err)
	}
	defer netns.Close()

	// 创建 macvlan 设备
	macvlanInterface, err := createMacvlan(n, args.IfName, netns)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil { //  如果 cni 插件执行出错，需要删除不完整的 macvlan 子接口网卡
			netns.Do(func(_ ns.NetNS) error {
				return ip.DelLinkByName(args.IfName)
			})
		}
	}()

	// Assume L2 interface only
	result := &current.Result{
		CNIVersion: current.ImplementedSpecVersion,
		Interfaces: []*current.Interface{macvlanInterface},
	}

	if isLayer3 {
		//  调用 IPAM 插件，拿网络信息，包括：IP、路由表等等
		r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
		if err != nil {
			return err
		}

		// Invoke ipam del if err to avoid ip leak
		defer func() {
			if err != nil {// 如果 macvlan 执行发生错误，需要删除之前拿到的网络信息
				// 因为 ipam 和 macvlan 是 2 个不同的二进制插件，如果 macvlan 执行出错后 ipam 不做删除，会导致 ipam 已分配的 IP 无法回收
				ipam.ExecDel(n.IPAM.Type, args.StdinData)
			}
		}()

		// Convert whatever the IPAM result was into the current Result type
		ipamResult, err := current.NewResultFromResult(r)
		if err != nil {
			return err
		}

		if len(ipamResult.IPs) == 0 {
			return errors.New("IPAM plugin returned missing IP config")
		}

		result.IPs = ipamResult.IPs
		result.Routes = ipamResult.Routes

		for _, ipc := range result.IPs {
			// All addresses apply to the container macvlan interface
			ipc.Interface = current.Int(0)
		}

		err = netns.Do(func(_ ns.NetNS) error {
			// 自动发送 Gratuitous ARP (GARP) 请求。GARP 请求是一种特殊的 ARP 数据包，设备发送该数据包是为了通知其 IP 地址到 MAC 地址的映射，即使没有收到 ARP 请求。
			_, _ = sysctl.Sysctl(fmt.Sprintf("net/ipv4/conf/%s/arp_notify", args.IfName), "1")
			// NDISC: 邻居发现协议(Neighbour Discovery Protocol, NDISC),
			_, _ = sysctl.Sysctl(fmt.Sprintf("net/ipv6/conf/%s/ndisc_notify", args.IfName), "1")
            // 配置网卡信息
			return ipam.ConfigureIface(args.IfName, result)
		})
		if err != nil {
			return err
		}
	} else {
		// 	对于纯粹的2层网络来说，不对容器网卡 eth0 配置 IP，只是单纯的启用网卡就可以了（有 MAC）。
		err = netns.Do(func(_ ns.NetNS) error {
			macvlanInterfaceLink, err := netlink.LinkByName(args.IfName)
			if err != nil {
				return fmt.Errorf("failed to find interface name %q: %v", macvlanInterface.Name, err)
			}

			if err := netlink.LinkSetUp(macvlanInterfaceLink); err != nil {
				return fmt.Errorf("failed to set %q UP: %v", args.IfName, err)
			}

			return nil
		})
		if err != nil {
			return err
		}
	}

	result.DNS = n.DNS

	return types.PrintResult(result, cniVersion)
}

func createMacvlan(conf *NetConf, ifName string, netns ns.NetNS) (*current.Interface, error) {
	macvlan := &current.Interface{}

	mode, err := modeFromString(conf.Mode)
	if err != nil {
		return nil, err
	}

	var m netlink.Link
	if conf.LinkContNs {
		err = netns.Do(func(_ ns.NetNS) error {
			m, err = netlink.LinkByName(conf.Master)
			return err
		})
	} else {
		m, err = netlink.LinkByName(conf.Master)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to lookup master %q: %v", conf.Master, err)
	}

	// due to kernel bug we have to create with tmpName or it might
	// collide with the name on the host and error out
	tmpName, err := ip.RandomVethName()
	if err != nil {
		return nil, err
	}

	linkAttrs := netlink.NewLinkAttrs()
	linkAttrs.MTU = conf.MTU
	linkAttrs.Name = tmpName
	linkAttrs.ParentIndex = m.Attrs().Index
	linkAttrs.Namespace = netlink.NsFd(int(netns.Fd()))

	if conf.Mac != "" {
		addr, err := net.ParseMAC(conf.Mac)
		if err != nil {
			return nil, fmt.Errorf("invalid args %v for MAC addr: %v", conf.Mac, err)
		}
		linkAttrs.HardwareAddr = addr
	}

	mv := &netlink.Macvlan{
		LinkAttrs: linkAttrs,
		Mode:      mode,
	}

	mv.BCQueueLen = conf.BcQueueLen

	if conf.LinkContNs {
		err = netns.Do(func(_ ns.NetNS) error {
			return netlink.LinkAdd(mv)
		})
	} else {
		if err = netlink.LinkAdd(mv); err != nil {
			return nil, fmt.Errorf("failed to create macvlan: %v", err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create macvlan: %v", err)
	}

	err = netns.Do(func(_ ns.NetNS) error {
		err := ip.RenameLink(tmpName, ifName)
		if err != nil {
			_ = netlink.LinkDel(mv)
			return fmt.Errorf("failed to rename macvlan to %q: %v", ifName, err)
		}
		macvlan.Name = ifName

		// Re-fetch macvlan to get all properties/attributes
		contMacvlan, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to refetch macvlan %q: %v", ifName, err)
		}
		macvlan.Mac = contMacvlan.Attrs().HardwareAddr.String()
		macvlan.Sandbox = netns.Path()

		return nil
	})
	if err != nil {
		return nil, err
	}

	return macvlan, nil
}
```

### host-local
一般用于单机 pod IP管理.host-local插件从address ranges 中分配IP，将分配的结果存在本地机器，所以这也是为什么叫做host-local

Kube-controller-manager为每个节点分配一个podCIDR。从podCIDR中的子网值中为节点上的Pod分配IP地址。由于所有节点上的podCIDR是不相交的子网，因此它允许为每个pod分配唯一的IP地址。

```go
func cmdAdd(args *skel.CmdArgs) error {
	ipamConf, confVersion, err := allocator.LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	result := &current.Result{CNIVersion: current.ImplementedSpecVersion}

	if ipamConf.ResolvConf != "" {
		dns, err := parseResolvConf(ipamConf.ResolvConf)
		if err != nil {
			return err
		}
		result.DNS = *dns
	}
    // 存储使用IP，以IP地址写入文件，以及最后一次IP记录
	store, err := disk.New(ipamConf.Name, ipamConf.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()

	// Keep the allocators we used, so we can release all IPs if an error
	// occurs after we start allocating
	allocs := []*allocator.IPAllocator{}

	// Store all requested IPs in a map, so we can easily remove ones we use
	// and error if some remain
	requestedIPs := map[string]net.IP{} // net.IP cannot be a key

	for _, ip := range ipamConf.IPArgs {
		requestedIPs[ip.String()] = ip
	}

	for idx, rangeset := range ipamConf.Ranges {
		// 初始化IP分配器
		allocator := allocator.NewIPAllocator(&rangeset, store, idx)

		// Check to see if there are any custom IPs requested in this range.
		var requestedIP net.IP
		for k, ip := range requestedIPs {
			if rangeset.Contains(ip) {
				requestedIP = ip
				delete(requestedIPs, k)
				break
			}
		}
        // 分配 ip 
		ipConf, err := allocator.Get(args.ContainerID, args.IfName, requestedIP)
		if err != nil {
			// Deallocate all already allocated IPs
			for _, alloc := range allocs {
				_ = alloc.Release(args.ContainerID, args.IfName)
			}
			return fmt.Errorf("failed to allocate for range %d: %v", idx, err)
		}

		allocs = append(allocs, allocator)

		result.IPs = append(result.IPs, ipConf)
	}

	// If an IP was requested that wasn't fulfilled, fail
	if len(requestedIPs) != 0 { // 如果还有需要分配的ip不在rangeset
		for _, alloc := range allocs {
			_ = alloc.Release(args.ContainerID, args.IfName)
		}
		errstr := "failed to allocate all requested IPs:"
		for _, ip := range requestedIPs {
			errstr = errstr + " " + ip.String()
		}
		return errors.New(errstr)
	}

	result.Routes = ipamConf.Routes

	return types.PrintResult(result, confVersion)
}
```
```go
func (a *IPAllocator) Get(id string, ifname string, requestedIP net.IP) (*current.IPConfig, error) {
	a.store.Lock()
	defer a.store.Unlock()

	var reservedIP *net.IPNet
	var gw net.IP

	if requestedIP != nil { // 如果请求ip不为空，则查看请求的ip是否满足分配的条件
		if err := canonicalizeIP(&requestedIP); err != nil {
			return nil, err
		}

		r, err := a.rangeset.RangeFor(requestedIP)
		if err != nil {
			return nil, err
		}

		if requestedIP.Equal(r.Gateway) {
			return nil, fmt.Errorf("requested ip %s is subnet's gateway", requestedIP.String())
		}

		reserved, err := a.store.Reserve(id, ifname, requestedIP, a.rangeID)
		if err != nil {
			return nil, err
		}
		if !reserved {
			return nil, fmt.Errorf("requested IP address %s is not available in range set %s", requestedIP, a.rangeset.String())
		}
		reservedIP = &net.IPNet{IP: requestedIP, Mask: r.Subnet.Mask}
		gw = r.Gateway

	} else { // 否则分配一个新的未使用的ip回去
		allocatedIPs := a.store.GetByID(id, ifname)
		for _, allocatedIP := range allocatedIPs {
			// check whether the existing IP belong to this range set
			if _, err := a.rangeset.RangeFor(allocatedIP); err == nil {
				return nil, fmt.Errorf("%s has been allocated to %s, duplicate allocation is not allowed", allocatedIP.String(), id)
			}
		}
        // 获取迭代器，迭代器指向上一个分配的ip
		iter, err := a.GetIter()
		if err != nil {
			return nil, err
		}
		for {
			// 从迭代器获取其下一个ip作为分配的ip
			reservedIP, gw = iter.Next()
			if reservedIP == nil {
				break
			}

			reserved, err := a.store.Reserve(id, ifname, reservedIP.IP, a.rangeID)
			if err != nil {
				return nil, err
			}

			if reserved {
				break
			}
		}
	}

	if reservedIP == nil {
		return nil, fmt.Errorf("no IP addresses available in range set: %s", a.rangeset.String())
	}

	return &current.IPConfig{
		Address: *reservedIP,
		Gateway: gw,
	}, nil
}


func (i *RangeIter) Next() (*net.IPNet, net.IP) {
	r := (*i.rangeset)[i.rangeIdx]

	// 如果是第一次分配，则取第一个ip
	if i.cur == nil {
		i.cur = r.RangeStart
		i.startIP = i.cur
		if i.cur.Equal(r.Gateway) {
			return i.Next()
		}
		return &net.IPNet{IP: i.cur, Mask: r.Subnet.Mask}, r.Gateway
	}

	//  如果到了末端，则重头开始
	if i.cur.Equal(r.RangeEnd) {
		i.rangeIdx++
		i.rangeIdx %= len(*i.rangeset)
		r = (*i.rangeset)[i.rangeIdx]

		i.cur = r.RangeStart
	} else {
		// 如果没到末端，则取下一个ip
		i.cur = ip.NextIP(i.cur)
	}

	if i.startIP == nil {
		i.startIP = i.cur
	} else if i.cur.Equal(i.startIP) {
		// IF we've looped back to where we started, give up
		return nil, nil
	}

	if i.cur.Equal(r.Gateway) {
		return i.Next()
	}

	return &net.IPNet{IP: i.cur, Mask: r.Subnet.Mask}, r.Gateway
}

```

### bridge
```go
func cmdAdd(args *skel.CmdArgs) error {
	var success bool = false

	n, cniVersion, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}
    // 如果 ipam 类型不为空则为3层, 这里一般是 host-local
	isLayer3 := n.IPAM.Type != ""

	if n.IsDefaultGW {
		n.IsGW = true
	}

	if n.HairpinMode && n.PromiscMode {
		return fmt.Errorf("cannot set hairpin mode and promiscous mode at the same time.")
	}
    // 创建网桥，如果需要的话
	br, brInterface, err := setupBridge(n)
	if err != nil {
		return err
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()
    // 创建 veth pair
	hostInterface, containerInterface, err := setupVeth(netns, br, args.IfName, n.MTU, n.HairpinMode, n.Vlan)
	if err != nil {
		return err
	}

	// Assume L2 interface only
	result := &current.Result{CNIVersion: cniVersion, Interfaces: []*current.Interface{brInterface, hostInterface, containerInterface}}

	if isLayer3 {
		// 运行 IPAM 插件，并获取结果
		r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
		if err != nil {
			return err
		}

		// release IP in case of failure
		defer func() {
			if !success {
				ipam.ExecDel(n.IPAM.Type, args.StdinData)
			}
		}()

		// Convert whatever the IPAM result was into the current Result type
		ipamResult, err := current.NewResultFromResult(r)
		if err != nil {
			return err
		}

		result.IPs = ipamResult.IPs
		result.Routes = ipamResult.Routes

		if len(result.IPs) == 0 {
			return errors.New("IPAM plugin returned missing IP config")
		}

		// 获取IPv4，IPv6的网关信息
		gwsV4, gwsV6, err := calcGateways(result, n)
		if err != nil {
			return err
		}

		// Configure the container hardware address and IP address(es)
		if err := netns.Do(func(_ ns.NetNS) error {
			// Disable IPv6 DAD just in case hairpin mode is enabled on the
			// bridge. Hairpin mode causes echos of neighbor solicitation
			// packets, which causes DAD failures.
			for _, ipc := range result.IPs {
				if ipc.Version == "6" && (n.HairpinMode || n.PromiscMode) {
					if err := disableIPV6DAD(args.IfName); err != nil {
						return err
					}
					break
				}
			}

			// Add the IP to the interface
			if err := ipam.ConfigureIface(args.IfName, result); err != nil {
				return err
			}
			return nil
		}); err != nil {
			return err
		}

		// check bridge port state
		retries := []int{0, 50, 500, 1000, 1000}
		for idx, sleep := range retries {
			time.Sleep(time.Duration(sleep) * time.Millisecond)

			hostVeth, err := netlink.LinkByName(hostInterface.Name)
			if err != nil {
				return err
			}
			if hostVeth.Attrs().OperState == netlink.OperUp {
				break
			}

			if idx == len(retries)-1 {
				return fmt.Errorf("bridge port in error state: %s", hostVeth.Attrs().OperState)
			}
		}

		// Send a gratuitous arp
		if err := netns.Do(func(_ ns.NetNS) error {
			contVeth, err := net.InterfaceByName(args.IfName)
			if err != nil {
				return err
			}

			for _, ipc := range result.IPs {
				if ipc.Version == "4" {
					_ = arping.GratuitousArpOverIface(ipc.Address.IP, *contVeth)
				}
			}
			return nil
		}); err != nil {
			return err
		}

		if n.IsGW {
			var firstV4Addr net.IP
			var vlanInterface *current.Interface
			// Set the IP address(es) on the bridge and enable forwarding
			for _, gws := range []*gwInfo{gwsV4, gwsV6} {
				for _, gw := range gws.gws {
					if gw.IP.To4() != nil && firstV4Addr == nil {
						firstV4Addr = gw.IP
					}
					if n.Vlan != 0 {
						vlanIface, err := ensureVlanInterface(br, n.Vlan)
						if err != nil {
							return fmt.Errorf("failed to create vlan interface: %v", err)
						}

						if vlanInterface == nil {
							vlanInterface = &current.Interface{Name: vlanIface.Attrs().Name,
								Mac: vlanIface.Attrs().HardwareAddr.String()}
							result.Interfaces = append(result.Interfaces, vlanInterface)
						}
                        // 设置网桥地址
						err = ensureAddr(vlanIface, gws.family, &gw, n.ForceAddress)
						if err != nil {
							return fmt.Errorf("failed to set vlan interface for bridge with addr: %v", err)
						}
					} else {
						err = ensureAddr(br, gws.family, &gw, n.ForceAddress)
						if err != nil {
							return fmt.Errorf("failed to set bridge addr: %v", err)
						}
					}
				}

				if gws.gws != nil {
					if err = enableIPForward(gws.family); err != nil {
						return fmt.Errorf("failed to enable forwarding: %v", err)
					}
				}
			}
		}

		if n.IPMasq {
			chain := utils.FormatChainName(n.Name, args.ContainerID)
			comment := utils.FormatComment(n.Name, args.ContainerID)
			for _, ipc := range result.IPs {
				if err = ip.SetupIPMasq(&ipc.Address, chain, comment); err != nil {
					return err
				}
			}
		}
	}

	// Refetch the bridge since its MAC address may change when the first
	// veth is added or after its IP address is set
	br, err = bridgeByName(n.BrName)
	if err != nil {
		return err
	}
	brInterface.Mac = br.Attrs().HardwareAddr.String()

	result.DNS = n.DNS

	// Return an error requested by testcases, if any
	if debugPostIPAMError != nil {
		return debugPostIPAMError
	}

	success = true

	return types.PrintResult(result, cniVersion)
}
```
#### hairpin mode
bridge不允许包从收到包的端口发出，比如bridge从一个端口收到一个广播报文后，会将其广播到所有其他端口。
bridge的某个端口打开hairpin mode后允许从这个端口收到的包仍然从这个端口发出。
这个特性用于NAT场景下，比如docker的nat网络，一个容器访问其自身映射到主机的端口时，包到达bridge设备后走到ip协议栈，经过iptables规则的dnat转换后发现又需要从bridge的收包端口发出，需要开启端口的hairpin mode。

### vlan
```go
func cmdAdd(args *skel.CmdArgs) error {
	n, cniVersion, err := loadConf(args)
	if err != nil {
		return err
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	// 创建 vlan 设备
	vlanInterface, err := createVlan(n, args.IfName, netns)
	if err != nil {
		return err
	}

	// run the IPAM plugin and get back the config to apply
	r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to execute IPAM delegate: %v", err)
	}

	// Invoke ipam del if err to avoid ip leak
	defer func() {
		if err != nil {
			ipam.ExecDel(n.IPAM.Type, args.StdinData)
		}
	}()

	// Convert whatever the IPAM result was into the current Result type
	result, err := current.NewResultFromResult(r)
	if err != nil {
		return err
	}

	if len(result.IPs) == 0 {
		return errors.New("IPAM plugin returned missing IP config")
	}
	for _, ipc := range result.IPs {
		// All addresses belong to the vlan interface
		ipc.Interface = current.Int(0)
	}

	result.Interfaces = []*current.Interface{vlanInterface}

	err = netns.Do(func(_ ns.NetNS) error {
		return ipam.ConfigureIface(args.IfName, result)
	})
	if err != nil {
		return err
	}

	result.DNS = n.DNS

	return types.PrintResult(result, cniVersion)
}

func createVlan(conf *NetConf, ifName string, netns ns.NetNS) (*current.Interface, error) {
	vlan := &current.Interface{}

	var m netlink.Link
	var err error
	if conf.LinkContNs {
		err = netns.Do(func(_ ns.NetNS) error {
			m, err = netlink.LinkByName(conf.Master)
			return err
		})
	} else {
		m, err = netlink.LinkByName(conf.Master)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to lookup master %q: %v", conf.Master, err)
	}

	// due to kernel bug we have to create with tmpname or it might
	// collide with the name on the host and error out
	tmpName, err := ip.RandomVethName()
	if err != nil {
		return nil, err
	}

	linkAttrs := netlink.NewLinkAttrs()
	linkAttrs.MTU = conf.MTU
	linkAttrs.Name = tmpName
	linkAttrs.ParentIndex = m.Attrs().Index
	linkAttrs.Namespace = netlink.NsFd(int(netns.Fd()))

	v := &netlink.Vlan{
		LinkAttrs: linkAttrs,
		VlanId:    conf.VlanID,
	}

	if conf.LinkContNs {
		err = netns.Do(func(_ ns.NetNS) error {
			return netlink.LinkAdd(v)
		})
	} else {
		err = netlink.LinkAdd(v)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create vlan: %v", err)
	}

	err = netns.Do(func(_ ns.NetNS) error {
		err := ip.RenameLink(tmpName, ifName)
		if err != nil {
			return fmt.Errorf("failed to rename vlan to %q: %v", ifName, err)
		}
		vlan.Name = ifName

		// Re-fetch interface to get all properties/attributes
		contVlan, err := netlink.LinkByName(vlan.Name)
		if err != nil {
			return fmt.Errorf("failed to refetch vlan %q: %v", vlan.Name, err)
		}
		vlan.Mac = contVlan.Attrs().HardwareAddr.String()
		vlan.Sandbox = netns.Path()

		return nil
	})
	if err != nil {
		return nil, err
	}

	return vlan, nil
}
```


## 实现一个 CNI 插件
实现一个 CNI 插件首先需要一个 JSON 格式的配置文件，配置文件需要放到每个节点的 /etc/cni/net.d/ 目录，一般命名为 <数字>-<CNI-plugin>.conf.

默认配置及二进制目录
```go
// https://github.com/containerd/containerd/blob/8ff5827e98ee6efeee161421abdc6da48c8f27b4/vendor/github.com/containerd/go-cni/types.go
const (
	CNIPluginName        = "cni"
	DefaultNetDir        = "/etc/cni/net.d"
	DefaultCNIDir        = "/opt/cni/bin"
)
```

{{<figure src="./k8s-cni-conf.png#center" width=800px >}}

加载配置
```shell
# 默认目录/etc/cni/net.d 
[root@master-01 net.d]# ls
10-calico.conflist  calico-kubeconfig  calico-tls
[root@master-01 net.d]# cat 10-calico.conflist
{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "log_level": "info",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "etcd_endpoints": "https://172.16.7.30:2379",
      "etcd_key_file": "/etc/calico/ssl/calico-key.pem",
      "etcd_cert_file": "/etc/calico/ssl/calico.pem",
      "etcd_ca_cert_file": "/etc/kubernetes/ssl/ca.pem",
      "mtu": 1500,
      "ipam": {
          "type": "calico-ipam"
      },
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "/etc/cni/net.d/calico-kubeconfig"
      }
    },
    {
      "type": "portmap",
      "snat": true,
      "capabilities": {"portMappings": true}
    },
    {
      "type": "bandwidth",
      "capabilities": {"bandwidth": true}
    }
  ]
}
```

## cni 调用入口 cri
{{<figure src="./cni-process.png#center" width=800px >}}

加载配置初始化 network: 数据用来传给 cni 插件
```go
// https://github.com/containerd/containerd/blob/e9f22e008b18a383cb440d86c8fd3a93e364f3f4/vendor/github.com/containerd/go-cni/opts.go

type Network struct {
    cni    cnilibrary.CNI
    config *cnilibrary.NetworkConfigList
    ifName string
}

// 从目录加载 cni 配置
func loadFromConfDir(c *libcni, max int) error {
	files, err := cnilibrary.ConfFiles(c.pluginConfDir, []string{".conf", ".conflist", ".json"})
    // ..
	i := 0
	var networks []*Network
	for _, confFile := range files {
		var confList *cnilibrary.NetworkConfigList
		if strings.HasSuffix(confFile, ".conflist") {
			// 从文件读取
			confList, err = cnilibrary.ConfListFromFile(confFile)
            // ..
		} else {
            // ...
		}
		networks = append(networks, &Network{
			cni:    c.cniConfig,
			config: confList,
			ifName: getIfName(c.prefix, i),
		})
		i++
		if i == max { // 最多读取配置数量,默认是 	DefaultMaxConfNum    = 1
			break
		}
	}
	if len(networks) == 0 {
		return fmt.Errorf("no valid networks found in %s: %w", c.pluginDirs, ErrCNINotInitialized)
	}
	c.networks = append(c.networks, networks...)
	return nil
}

func ConfListFromFile(filename string) (*NetworkConfigList, error) {
    bytes, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("error reading %s: %w", filename, err)
    }
    return ConfListFromBytes(bytes)
}


func ConfListFromBytes(bytes []byte) (*NetworkConfigList, error) {
	rawList := make(map[string]interface{})
	if err := json.Unmarshal(bytes, &rawList); err != nil {
		return nil, fmt.Errorf("error parsing configuration list: %w", err)
	}

    // ...

	list := &NetworkConfigList{
		Name:         name,
		DisableCheck: disableCheck,
		CNIVersion:   cniVersion,
		Bytes:        bytes,
	}

	var plugins []interface{}
	plug, ok := rawList["plugins"]
	if !ok {
		return nil, fmt.Errorf("error parsing configuration list: no 'plugins' key")
	}
	plugins, ok = plug.([]interface{})
	if !ok {
		return nil, fmt.Errorf("error parsing configuration list: invalid 'plugins' type %T", plug)
	}
	if len(plugins) == 0 {
		return nil, fmt.Errorf("error parsing configuration list: no plugins in list")
	}

	for i, conf := range plugins {
		newBytes, err := json.Marshal(conf)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal plugin config %d: %w", i, err)
		}
		netConf, err := ConfFromBytes(newBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse plugin config %d: %w", i, err)
		}
		// 这里的数据用来传给 cni
		list.Plugins = append(list.Plugins, netConf)
	}

	return list, nil
}
```

### cni 调用方:pod 初始化 sandbox 时网络设置
```go
// https://github.com/containerd/containerd/blob/6c6cc5ec107f10ccf4d4acbfe89d572a52d58a92/pkg/cri/server/sandbox_run.go
func (c *criService) setupPodNetwork(ctx context.Context, sandbox *sandboxstore.Sandbox) error {
	var (
		id        = sandbox.ID
		config    = sandbox.Config
		path      = sandbox.NetNSPath
		netPlugin = c.getNetworkPlugin(sandbox.RuntimeHandler)
	)
    // ...
	result, err := netPlugin.Setup(ctx, id, path, opts...)
    // ...

	// Check if the default interface has IP config
	if configs, ok := result.Interfaces[defaultIfName]; ok && len(configs.IPConfigs) > 0 {
		sandbox.IP, sandbox.AdditionalIPs = selectPodIPs(ctx, configs.IPConfigs, c.config.IPPreference)
		sandbox.CNIResult = result
		return nil
	}
	return fmt.Errorf("failed to find network info for sandbox %q", id)
}
```

```go
func (c *libcni) Setup(ctx context.Context, id string, path string, opts ...NamespaceOpts) (*Result, error) {
	if err := c.Status(); err != nil {
		return nil, err
	}
	ns, err := newNamespace(id, path, opts...)
	if err != nil {
		return nil, err
	}
	result, err := c.attachNetworks(ctx, ns)
	if err != nil {
		return nil, err
	}
	return c.createResult(result)
}


func (c *libcni) attachNetworks(ctx context.Context, ns *Namespace) ([]*types100.Result, error) {
	var wg sync.WaitGroup
	var firstError error
	results := make([]*types100.Result, len(c.Networks()))
	rc := make(chan asynchAttachResult)

	for i, network := range c.Networks() {
		wg.Add(1)
		go asynchAttach(ctx, i, network, ns, &wg, rc)
	}

	for range c.Networks() {
		rs := <-rc
		if rs.err != nil && firstError == nil {
			firstError = rs.err
		}
		results[rs.index] = rs.res
	}
	wg.Wait()

	return results, firstError
}

func asynchAttach(ctx context.Context, index int, n *Network, ns *Namespace, wg *sync.WaitGroup, rc chan asynchAttachResult) {
	defer wg.Done()
	r, err := n.Attach(ctx, ns)
	rc <- asynchAttachResult{index: index, res: r, err: err}
}
```

```go
func (n *Network) Attach(ctx context.Context, ns *Namespace) (*types100.Result, error) {
	r, err := n.cni.AddNetworkList(ctx, n.config, ns.config(n.ifName))
	if err != nil {
		return nil, err
	}
	return types100.NewResultFromResult(r)
}
```

```go
func (c *CNIConfig) AddNetworkList(ctx context.Context, list *NetworkConfigList, rt *RuntimeConf) (types.Result, error) {
	var err error
	var result types.Result
	for _, net := range list.Plugins { // 对插件顺序执行
		result, err = c.addNetwork(ctx, list.Name, list.CNIVersion, net, result, rt)
		if err != nil {
			return nil, fmt.Errorf("plugin %s failed (add): %w", pluginDescription(net.Network), err)
		}
	}

	if err = c.cacheAdd(result, list.Bytes, list.Name, rt); err != nil {
		return nil, fmt.Errorf("failed to set network %q cached result: %w", list.Name, err)
	}

	return result, nil
}


func (c *CNIConfig) addNetwork(ctx context.Context, name, cniVersion string, net *NetworkConfig, prevResult types.Result, rt *RuntimeConf) (types.Result, error) {
	c.ensureExec()
	// 寻找二进制
	pluginPath, err := c.exec.FindInPath(net.Network.Type, c.Path)
	if err != nil {
		return nil, err
	}
    // ..
    // 构建配置
	newConf, err := buildOneConfig(name, cniVersion, net, prevResult, rt)
	if err != nil {
		return nil, err
	}
    // 调用 add 接口
	return invoke.ExecPluginWithResult(ctx, pluginPath, newConf.Bytes, c.args("ADD", rt), c.exec)
}

func buildOneConfig(name, cniVersion string, orig *NetworkConfig, prevResult types.Result, rt *RuntimeConf) (*NetworkConfig, error) {
	var err error

	inject := map[string]interface{}{
		"name":       name,
		"cniVersion": cniVersion,
	}
	// 添加之前插件的结果
	if prevResult != nil {
		inject["prevResult"] = prevResult
	}

	// Ensure every config uses the same name and version
	orig, err = InjectConf(orig, inject)
	if err != nil {
		return nil, err
	}
    // 添加运行时 Capabilities
	return injectRuntimeConfig(orig, rt)
}
```

实际调用
```go
func ExecPluginWithResult(ctx context.Context, pluginPath string, netconf []byte, args CNIArgs, exec Exec) (types.Result, error) {
	if exec == nil {
		exec = defaultExec
	}

	stdoutBytes, err := exec.ExecPlugin(ctx, pluginPath, netconf, args.AsEnv())// 运行时作为env, 网络配置作为stdin
	if err != nil {
		return nil, err
	}

	resultVersion, fixedBytes, err := fixupResultVersion(netconf, stdoutBytes)
	if err != nil {
		return nil, err
	}

	return create.Create(resultVersion, fixedBytes)
}


func (e *RawExec) ExecPlugin(ctx context.Context, pluginPath string, stdinData []byte, environ []string) ([]byte, error) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	c := exec.CommandContext(ctx, pluginPath)
	c.Env = environ //作为环境变量
	c.Stdin = bytes.NewBuffer(stdinData) // 作为标准输入
	c.Stdout = stdout
	c.Stderr = stderr

	// Retry the command on "text file busy" errors
	for i := 0; i <= 5; i++ {
		err := c.Run()

		// Command succeeded
		if err == nil {
			break
		}

		// If the plugin is currently about to be written, then we wait a
		// second and try it again
		if strings.Contains(err.Error(), "text file busy") {
			time.Sleep(time.Second)
			continue
		}

		// All other errors except than the busy text file
		return nil, e.pluginErr(err, stdout.Bytes(), stderr.Bytes())
	}

	// Copy stderr to caller's buffer in case plugin printed to both
	// stdout and stderr for some reason. Ignore failures as stderr is
	// only informational.
	if e.Stderr != nil && stderr.Len() > 0 {
		_, _ = stderr.WriteTo(e.Stderr)
	}
	return stdout.Bytes(), nil
}
```
环境变量转换
```go
func (args *Args) AsEnv() []string {
	env := os.Environ()
	pluginArgsStr := args.PluginArgsStr
	if pluginArgsStr == "" {
		pluginArgsStr = stringify(args.PluginArgs)
	}

	// Duplicated values which come first will be overridden, so we must put the
	// custom values in the end to avoid being overridden by the process environments.
	env = append(env,
		"CNI_COMMAND="+args.Command,
		"CNI_CONTAINERID="+args.ContainerID,
		"CNI_NETNS="+args.NetNS,
		"CNI_ARGS="+pluginArgsStr,
		"CNI_IFNAME="+args.IfName,
		"CNI_PATH="+args.Path,
	)
	return dedupEnv(env)
}

```




CNI 规范定义的核心接口：

- ADD：将容器添加到网络；
- DEL：从网络中删除一个容器；
- CHECK：检查容器的网络是否符合预期等；

- CNI 官方已经提供了工具包，我们只需要实现cmdAdd, cmdCheck, cmdDel接口即可实现一个 CNI 插件.

### cni 被调用方: 启动配置解析

```go
func (t *dispatcher) getCmdArgsFromEnv() (string, *CmdArgs, *types.Error) {
	var cmd, contID, netns, ifName, args, path string

	vars := []struct {
		name      string
		val       *string
		reqForCmd reqForCmdEntry
	}{
		// 逐个解析环境变量
		{
			"CNI_COMMAND",
			&cmd,
			reqForCmdEntry{
				"ADD":   true,
				"CHECK": true,
				"DEL":   true,
			},
		},
        // ...
	}

	argsMissing := make([]string, 0)
	for _, v := range vars {
		// 解析 env
		*v.val = t.Getenv(v.name)
		if *v.val == "" {
			if v.reqForCmd[cmd] || v.name == "CNI_COMMAND" {
				argsMissing = append(argsMissing, v.name)
			}
		}
	}

    // ...
	
    // 解析 stdin
	stdinData, err := ioutil.ReadAll(t.Stdin)
	if err != nil {
		return "", nil, types.NewError(types.ErrIOFailure, fmt.Sprintf("error reading from stdin: %v", err), "")
	}

	cmdArgs := &CmdArgs{
		ContainerID: contID,
		Netns:       netns,
		IfName:      ifName,
		Args:        args,
		Path:        path,
		StdinData:   stdinData,
	}
	return cmd, cmdArgs, nil
}
```


## 模拟 Kubernetes 的 CNI 环境
CNI 插件的测试过程，不需要一定安装一个 K8s 出来，走 K8s CNI 流程来测试。CNI 官方 repo 中，提供了 [cnitool](https://github.com/containernetworking/cni/tree/v1.2.3/cnitool) 工具来测试 CNI 的插件:



## 参考
- https://github.com/containernetworking/plugins
- https://github.com/containernetworking/cni/blob/main/SPEC.md
- [深入解读 CNI：容器网络接口](https://jimmysong.io/blog/cni-deep-dive/)
- [手写一个Kubernetes CNI网络插件](https://qingwave.github.io/how-to-write-k8s-cni/)
- [源码分析：K8s CNI macvlan 网络插件](https://hansedong.github.io/2020/08/11/23/)
- [k8s pod使用sriov](https://blog.csdn.net/weixin_40579389/article/details/138086057)
- [bridge 插件使用](https://morningspace.github.io/tech/k8s-net-cni/)