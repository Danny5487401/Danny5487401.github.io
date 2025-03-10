---
title: "SR-IOV（Single Root I/O Virtualization)"
date: 2025-02-17T15:11:59+08:00
summary: SR-IOV 基本介绍及在 k8s 中应用
categories:
  - kubernetes

tags:
  - k8s
  - cni
  - sr-iov
  - bond
---


SR-IOV（Single Root I/O Virtualization）是一个将PCIe共享给虚拟机的标准，通过为虚拟机提供独立的内存空间、中断、DMA流，来绕过VMM实现数据访问。SR-IOV基于两种PCIe functions.

- PF (Physical Function)：包含完整的PCIe功能，包括SR-IOV的扩张能力，该功能用于SR-IOV的配置和管理。
- VF (Virtual Function)：包含轻量级的PCIe功能。每一个VF有它自己独享的PCI配置区域，并且可能与其他VF共享着同一个物理资源. 以Intel 10GE网卡82599为例，PF驱动是标准的ixgbe，VF驱动是ixgbevf。
尽管单个PF理论上可以生成65536个VF，但实际数量受到硬件资源限制，例如82599支持64个VF。


## SR-IOV 优点
性能提升: SR-IOV通过硬件辅助实现虚拟化，VF可以绕过宿主机直接与硬件交互，减少了数据包处理的延迟，提供了接近原生的性能。

资源利用率: SR-IOV设备能够高效利用物理设备资源，每个VF都有自己的硬件资源，提高了整体资源利用率。

隔离性: 每个VF都是独立的，互不干扰，提高了系统的安全性和稳定性。

可扩展性: 支持更多的虚拟机同时运行，而不会显著降低性能，使其适用于大型虚拟化环境。


## 基本知识
### PCI(Peripheral Component Interconnect 外围设备互联)
PCI是一种外设总线规范。我们先来看一下什么是总线：总线是一种传输信号的路径或信道。典型情况是，总线是连接于一个或多个导体的电气连线，总 线上连接的全部设备可在同一时间收到全部的传输内容。总线由电气接口和编程接口组成。

Linux PCI设备驱动实际包括Linux PCI设备驱动和设备本身驱动两部分。
PCI(Peripheral Component Interconnect 外围设备互联)有三种地址空间：PCI I/O空间、PCI内存地址空间和PCI配置空间。
其中，PCI I/O空间和PCI内存地址空间由设备驱动程序使用，而PCI配置空间由Linux PCI初始化代码使用，用于配置PCI设备，比如中断号以及I/O或内存基地址。

/proc/iomem描写叙述了系统中全部的设备I/O在内存地址空间上的映射。 40000000-400003ff : 0000:00:1f.1

一个PCI设备，40000000-400003ff是它所映射的内存地址空间，占领了内存地址空间的1024 bytes的位置，而 0000:00:1f.1则是一个PCI外设的地址,它以冒号和逗号分隔为4个部分



一般一类设备在出厂的时候会有相同的一串classid,而classid记录在/sys/bus/pci/devices/*/class文件中

### /sys/bus/pci/devices 目录介绍
```shell
# sys/class目录下 net/scsi_host/fc_host/infiband_host 等 是/sys/bus/pci/devices/*/class下面pci设备的映射，映射到它们指定的类型中
[root@master-01 ~]# ls /sys/class/
ata_device  block        dmi             hidraw       iommu     msr            power_supply  scsi_device   thermal  usbmon
ata_link    bsg          drm             hmm_device   leds      net            ppdev         scsi_disk     tpm      vc
ata_port    cpuid        drm_dp_aux_dev  hwmon        mdio_bus  pci_bus        pwm           scsi_generic  tpmrm    vtconsole
backlight   devcoredump  gpio            i2c-adapter  mem       pcmcia_socket  raw           scsi_host     tty      watchdog
bdi         dma          graphics        input        misc      powercap       rtc           spi_master    typec
```



- /sys/class/net/< device name >/device/sriov_numvfs 参数设置了 SR-IOV 网络设备VF数量


### /etc/sysconfig/netwrok-scripts/ 目录介绍

与网络接口配置相关的文件，以及控制网络接口状态的脚本文件，全都位于 /etc/sysconfig/netwrok-scripts/ 目录下。
网络接口配置文件用于控制系统中的软件网络接口，并通过这些接口实现对网络设备的控制。
当系统启动时，系统通过这些接口配置文件决定启动哪些接口，以及如何对这些接口进行配置。接口配置文件的名称通常类似于 ifcfg-，其中 与配置文件所控制的设备的名称相关。 
在所有的网络接口中，最常用的就是以太网接口ifcfg-eth0，它是系统中第一块网卡的配置文件。



### QoS(Quality of Service 服务质量)
三种服务模型：

Best-Effort service 尽力而为服务模型: 不提供任何保证

Integrated service 综合服务模型: 

Differentiated service 差分服务模型: 将网络流量分成多个类，不同类按不同优先级处理


### VLAN优先级

802.1P优先级，也叫CoS（Class of Service，服务等级）

## SR-IOV 基本操作


```shell
# lspci是查看设备上pcie设备信息的命令: 查看 SR-IOV 设备
$ lspci -v | grep -i SR-IOV

        Capabilities: [bcc] Single Root I/O Virtualization (SR-IOV)
        Capabilities: [160] Single Root I/O Virtualization (SR-IOV)
        Capabilities: [160] Single Root I/O Virtualization (SR-IOV)
        Capabilities: [160] Single Root I/O Virtualization (SR-IOV)
        Capabilities: [160] Single Root I/O Virtualization (SR-IOV)

```
其中 1 个 [bcc] 是 NVIDIA 显卡的 SR-IOV 设备，剩下的 4 个 [160] 是 Intel 网卡。

```shell
# 列出网卡
ls /sys/class/net/

eth0          eth1          bond1          lo        calixxx 
```
ethX 是真实的物理网卡，bondX 是网络绑定 (bonding) 接口，lo 是本机的 loopback 网络接口，calixxx 是网络插件 Calico 为容器提供的网络接口.


```shell
# ethtool命令用于获取以太网卡的配置信息, -i 显示网卡驱动的信息，如驱动的名称、版本等
$ ethtool -i eno49
 
driver: igb
version: 5.6.0-k
firmware-version: 1.61, 0x80000daa, 1.949.0
expansion-rom-version:
bus-info: 0000:04:00.0
supports-statistics: yes
supports-test: yes
supports-eeprom-access: yes
supports-register-dump: yes
supports-priv-flags: yes
```



```shell
# 查看之前是否已经开启 SR-IOV
cat /sys/class/net/eth0/device/sriov_numvfs

# 开启 SR-IOV: 给网卡创建了 2 个 SR-IOV VF
echo 2 > /sys/class/net/eth0/device/sriov_numvfs

$ lspci | grep Virtual

3d:02.0 Ethernet controller: Intel Corporation Ethernet Virtual Function 700 Series (rev 09)
3d:02.1 Ethernet controller: Intel Corporation Ethernet Virtual Function 700 Series (rev 09)

# 查看网卡
ip link show eth0

4: eth0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether 90:f7:b2:4b:dc:3d brd ff:ff:ff:ff:ff:ff
    vf 0     link/ether 2e:3a:41:bc:02:cc brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 1     link/ether 5a:d4:e4:45:83:7b brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    altname enp61s0f0

# 删除 SR-IOV VF
echo 0 > /sys/class/net/eth0/device/sriov_numvfs

```
这里需要注意VF设备是不能增量添加的，如果需要修改启动的VF数量，需要先将sriov_numvfs值重置为0后再重新设置为目标值，所以在使用SR-IOV功能最好能确定最多会使用到几个VF，以防在业务运行过程中需要扩展VF数影响正在使用VF的业务。

Linux Kernel version 3.8.x 及以上版本可以通过上述调整 sriov_numvfs 方法动态调整VF数量。但是，对于 3.7.x 或更低版本，则不能动态调整，而是要在加载内核模块时传递参数:

{{<figure src="./virtfn.png#center" width=800px >}}
开启SR-IOV功能后，在/sys/class/net/eth1/device目录下会多出多个virtfnX的目录，这些目录下分别记录了对应VF的信息，例如可以通过ls /sys/class/net/eth1/device/virtfn*/net显示对应vf设备名称.
如果VF已经被放入了其他网络名字空间，那么net目录下会显示为空，例如上图中的virtfn0。


## 网卡 bond

{{<figure src="./bond.png#center" width=800px >}}

网卡bond，即网卡绑定。网卡绑定有多种叫法：Port Trunking, Channel Bonding, Link Aggregation, NIC teaming等等。
主要是将多个物理网卡绑定到一个逻辑网卡上。通过绑定可以达到链路冗余、带宽扩容、负载均衡等目的。
网卡bond一般主要用于网络吞吐量很大，以及对于网络稳定性要求较高的场景，是生产场景中提高性能和可靠性的一种常用技术。

多网卡绑定实际上需要提供一个额外的软件的bond驱动程序实现。通过驱动程序可以将多块网卡屏蔽。
对TCP/IP协议层只存在一个Bond网卡，在Bond程序中实现网络流量的负载均衡，即将一个网络请求重定位到不同的网卡上，来提高总体网络的可用性

怎么看当前bond的mode？
- #cat /proc/net/bonding/bond0
- #vim /etc/sysconfig/network-scripts/ifcfg-bond0的BONDING_OPTS参数
```shell
# 查看 bond 绑定的网卡
cat /proc/net/bonding/bond1

Ethernet Channel Bonding Driver: v3.7.1 (April 27, 2011)
...

Slave Interface: eth5
MII Status: up
Speed: 10000 Mbps
...

Slave Interface: eth4
MII Status: up
Speed: 10000 Mbps
...

```


### Bond 七种模式
网卡Bond模式总共有7种，最常用的是负载模式（模式0）和主备模式（模式1），在网络流量较大的场景下推荐使用负载模式（Bond0），而在可靠性要求较高的场景下则推荐使用主备模式（Bond1）。

```go
// github.com/vishvananda/netlink/link.go

type BondMode int

// Possible BondMode
const (
	BOND_MODE_BALANCE_RR BondMode = iota
	BOND_MODE_ACTIVE_BACKUP
	BOND_MODE_BALANCE_XOR
	BOND_MODE_BROADCAST
	BOND_MODE_802_3AD
	BOND_MODE_BALANCE_TLB
	BOND_MODE_BALANCE_ALB
	BOND_MODE_UNKNOWN
)

```
#### Mode 0 - Balance-RR（轮询模式 round-robin）
* 描述：链路负载均衡，增加带宽，支持容错，一条链路故障会自动切换正常链路。交换机需要配置聚合口，思科叫port channel。
* 优点：增加网络吞吐量，另外也会增加高可用
* 缺点：不提供冗余性，交换机需要配置trunking。
* 适用场景：报文无冗余，并在存在数据包顺序问题，例如流媒体服务
#### Mode 1 - Active-Backup（主备模式）
* 原理：主备模式，可以多网卡bond，只有一个网卡传输数据，备网卡均处于就绪状态，在主网卡出故障时接管数据传输任务，接管任务时仍使用原来主网卡的mac，避免切网卡导致网络中断
* 优点：高可用，提供冗余。
* 缺点：端口利用率低，浪费一个网卡的性能。
* 适用场景：需要高可用性的场景。
#### Mode 2 - Balance-XOR（平衡异或模式）
* 描述：基于源目的mac、传输层协议和端口选择传输的端口，两个口均处于工作中。
* 优点：提供负载均衡。
* 缺点：需要交换机支持链路聚合。
* 适用场景：需要负载均衡且交换机支持链路聚合的环境。
#### Mode 3 - Broadcast（广播模式）
* 描述：将所有数据包发送到所有接口，所有网卡mac一致。
* 优点：实现广播传输，保证了网络的可靠性。
* 缺点：浪费带宽，可能会导致网络阻塞
* 适用场景：需要高可靠性但不介意带宽浪费的场合，如金融行业。
#### Mode 4 - 802.3ad（LACP模式）
* 描述：使用LACP协议动态协商，数据传输时使用hash策略，可基于源目的mac，传输层ip端口hash。
* 优点：提供负载均衡和高可用，遵循标准协议。
* 缺点：需要交换机支持LACP。
* 适用场景：交换机支持LACP并且需要高可用和高带宽的场景
#### Mode 5 - Balance-TLB（自适应传输负载均衡模式）
* 描述：根据网卡当前的负载情况动态调整，使其能够负载均衡
* 优点：提供传输方向的负载均衡，不需要交换机支持。
* 缺点：对于数据接收方不能有负载均衡
#### Mode 6 - Balance-ALB（自适应负载均衡模式）
* 描述：与mode5类似，不同的是在接收端也支持负载均衡
* 优点：在传输和接收方向上都实现负载均衡，不需要交换机特殊支持。


LACP（Link Aggregation Control Protocol）链路聚合包含两种类型
- 静态 LACP 模式链路聚合: Eth-Trunk 接口的建立，成员接口的加入，都是由手工配置完成的
- 动态 LACP 模式链路: Eth-Trunk 接口的建立，成员接口的加入，活动接口的选择完全由LACP 协议通过协商完成。

链路聚合控制的相关参数
- Aggregator ID： 在一个设备上，能进行多组聚合，即有多个Aggregator，为了区分这些Aggregator，给每个Aggregator分配了一个聚合ID（Aggregator ID），为一个16位整数
- 操作key : 在动态LACP聚合中，只有操作KEY相同的端口才能属于同一个聚合组，你可以认为操作KEY相同的端口，其属性相

### 参数介绍
```go
// github.com/vishvananda/netlink/link.go

type Bond struct {
	LinkAttrs
	Mode            BondMode
	ActiveSlave     int
	Miimon          int // 指定MII链路监控频率，单位是毫秒(ms)
	UpDelay         int // 指定当发现一个链路恢复时，在激活该链路之前的等待时间，以毫秒计算。该选项只对miimon链路侦听有效
	DownDelay       int // 指定一个时间，用于在发现链路故障后，等待一段时间然后禁止一个slave，单位是毫秒(ms)。该选项只对miimon监控有效。
	UseCarrier      int // 指定miimon是否需要使用MII或者ETHTOOL ioctls还是netif_carrier_ok()来判定链路状态。MII或ETHTOOL ioctls更低效一些，而且使用了内核里废弃的旧调用序列；而netif_carrier_ok()依赖于设备驱动来维护状态（判断载波）
	ArpInterval     int // 指定ARP链路监控频率，单位是毫秒(ms)。ARP监控不应该和miimon同时使用
	ArpIpTargets    []net.IP
	ArpValidate     BondArpValidate
	ArpAllTargets   BondArpAllTargets
	Primary         int // 哪个slave成为主设备（primary device），取值为字符串，如eth0，eth1等。只要指定的设备可用，它将一直是激活的slave。只有在主设备（primary device）断线时才会切换设备。primary 选项只对active-backup(mode=1)模式有效。
	PrimaryReselect BondPrimaryReselect
	FailOverMac     BondFailOverMac // 指定 active-backup 模式是否应该将所有从属连接设定为使用同一 MAC 地址作为 enslavement（传统行为），或在启用时根据所选策略执行绑定 MAC 地址的特殊处理。
	XmitHashPolicy  BondXmitHashPolicy // 分发策略 
	ResendIgmp      int  // 指定故障转移事件后要进行的 IGMP 成员报告数。故障转移后会立即提交一个报告，之后会每隔 200 毫秒发送数据包。
    NumPeerNotif    int
	AllSlavesActive int
	MinLinks        int
	LpInterval      int
	PacketsPerSlave int
	LacpRate        BondLacpRate
	AdSelect        BondAdSelect // 指定要使用的 802.3ad(mode=4) 聚合选择逻辑
	// looking at iproute tool AdInfo can only be retrived. It can't be set.
	AdInfo         *BondAdInfo
	AdActorSysPrio int
	AdUserPortKey  int
	AdActorSystem  net.HardwareAddr
	TlbDynamicLb   int
}
```
xmit_hash_policy
1. layer2： 使用二层帧头作为计算分发出口的参数，这导致通过同一个网关的数据流将完全从一个端口发送，为了更加细化分发策略，必须使用一些三层信息，然而却增加了计算开销。

2. layer2+3： 在1的基础上增加了三层的ip报头信息，计算量增加了，然而负载却更加均衡了，一个个主机到主机的数据流形成并且同一个流被分发到同一个端口，根据这个思想，如果要使负载更加均衡，我们在继续增加代价的前提下可以拿到4层的信息。

3. layer3+4： 该策略在可能的时候使用上层协议的信息来生成hash。这将允许特定网络对（network peer）的流量分摊到多个slave上，尽管同一个连接（connection）不会分摊到多个slave上。




### bond口创建的一般流程：

Step 1、创建slave口

Step 2、slave口配置网卡队列、网口启动

Step 3、创建bond口

Step 4、bond口添加slave口

Step 5、bond口配置网卡队列、网口启动

Step 6、通过bond口id进行收发包

```go
// https://github.com/k8snetworkplumbingwg/bond-cni/blob/9f57b80f66ccfcba6167dba560b8b93184177cd4/bond/bond.go
func createBond(bondName string, bondConf *bondingConfig, nspath string, ns ns.NetNS) (*current.Interface, error) {
	bond := &current.Interface{}

	// get the namespace from the CNI_NETNS environment variable
	netNs, err := netns.GetFromPath(nspath)
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve netNs from path (%+v), error: %+v", nspath, err)
	}
	defer netNs.Close()

	// get a handle for the namespace above, this handle will be used to interact with existing links and add a new one
	netNsHandle, err := netlink.NewHandleAt(netNs)
	if err != nil {
		return nil, fmt.Errorf("Failed to create a new handle at netNs (%+v), error: %+v", netNs, err)
	}
	defer netNsHandle.Close()

	if !bondConf.LinksContNs {
		if err := setLinksInNetNs(bondConf, nspath, false); err != nil {
			return nil, fmt.Errorf("Failed to move the links (%+v) in container network namespace, error: %+v", bondConf.Links, err)
		}
	}

	linkObjectsToBond, err := getLinkObjectsFromConfig(bondConf, netNsHandle, false)
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve link objects from configuration file (%+v), error: %+v", bondConf, err)
	}

	err = util.ValidateMTU(linkObjectsToBond, bondConf.MTU)
	if err != nil {
		return nil, err
	}

	if bondConf.FailOverMac < 0 || bondConf.FailOverMac > 2 {
		return nil, fmt.Errorf("FailOverMac mode should be 0, 1 or 2 actual: %+v", bondConf.FailOverMac)
	}
	
	bondLinkObj, err := createBondedLink(bondName, bondConf.Mode, bondConf.Miimon, bondConf.MTU, bondConf.FailOverMac, netNsHandle)
	if err != nil {
		return nil, fmt.Errorf("Failed to create bonded link (%+v), error: %+v", bondName, err)
	}

	err = attachLinksToBond(bondLinkObj, linkObjectsToBond, netNsHandle)
	if err != nil {
		return nil, fmt.Errorf("Failed to attached links to bond, error: %+v", err)
	}

	if err := netNsHandle.LinkSetUp(bondLinkObj); err != nil {
		return nil, fmt.Errorf("Failed to set bond link UP, error: %v", err)
	}

	bond.Name = bondName

	// Re-fetch interface to get all properties/attributes
	contBond, err := netNsHandle.LinkByName(bond.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to refetch bond %q: %v", bond.Name, err)
	}
	bond.Mac = contBond.Attrs().HardwareAddr.String()
	bond.Sandbox = ns.Path()

	return bond, nil

}
```


## SR-IOV 在 k8s 中应用

intel官方也给出了SR-IOV技术在容器中使用的开源组件，例如：sriov-cni 和 sriov-device-plugin等.
当前招商银行数据库服务就是使用这方面的技术.


```go
// 根据 pci 地址获取 pf 和 vfid
func getVfInfo(vfPci string) (string, int, error) {
	var vfID int

	pf, err := utils.GetPfName(vfPci)
	if err != nil {
		return "", vfID, err
	}

	vfID, err = utils.GetVfid(vfPci, pf)
	if err != nil {
		return "", vfID, err
	}

	return pf, vfID, nil
}


```
```go
// https://github.com/k8snetworkplumbingwg/sriov-cni/blob/36e2d17af18803d0a1ced3c0c62a33b321d05a5b/pkg/utils/utils.go
var (
	sriovConfigured = "/sriov_numvfs"
	// NetDirectory sysfs net directory
	NetDirectory = "/sys/class/net"
	// SysBusPci is sysfs pci device directory
	SysBusPci = "/sys/bus/pci/devices"
	// SysV4ArpNotify is the sysfs IPv4 ARP Notify directory
	SysV4ArpNotify = "/proc/sys/net/ipv4/conf/"
	// SysV6NdiscNotify is the sysfs IPv6 Neighbor Discovery Notify directory
	SysV6NdiscNotify = "/proc/sys/net/ipv6/conf/"
	// UserspaceDrivers is a list of driver names that don't have netlink representation for their devices
	UserspaceDrivers = []string{"vfio-pci", "uio_pci_generic", "igb_uio"}
)


func GetPfName(vf string) (string, error) {
	pfSymLink := filepath.Join(SysBusPci, vf, "physfn", "net")
	_, err := os.Lstat(pfSymLink)
	if err != nil {
		return "", err
	}

	files, err := os.ReadDir(pfSymLink)
	if err != nil {
		return "", err
	}

	if len(files) < 1 {
		return "", fmt.Errorf("PF network device not found")
	}

	return strings.TrimSpace(files[0].Name()), nil
}

func GetVfid(addr string, pfName string) (int, error) {
	var id int
	vfTotal, err := GetSriovNumVfs(pfName)
	if err != nil {
		return id, err
	}
	for vf := 0; vf < vfTotal; vf++ {
		vfDir := filepath.Join(NetDirectory, pfName, "device", fmt.Sprintf("virtfn%d", vf))
		_, err := os.Lstat(vfDir)
		if err != nil {
			continue
		}
		pciinfo, err := os.Readlink(vfDir) // readlink用于显示符号链接的值，即符号链接所指向的实际文件或目录的路径
		if err != nil {
			continue
		}
		pciaddr := filepath.Base(pciinfo)
		if pciaddr == addr {
			return vf, nil
		}
	}
	return id, fmt.Errorf("unable to get VF ID with PF: %s and VF pci address %v", pfName, addr)
}

```


## 参考
- https://github.com/k8snetworkplumbingwg/sriov-network-device-plugin/blob/master/docs/vf-setup.md
- https://www.howtoforge.com/tutorial/how-to-configure-high-availability-and-network-bonding-on-linux/
- [SR-IOV 技术及在Pod 中使用](https://www.chenshaowen.com/blog/sr-iov-technique.html)
- [SR-IOV vs DPDK](https://feisky.gitbooks.io/sdn/content/linux/sr-iov.html)
- [BONDING_OPTS参数详细说明](https://blog.csdn.net/cuichongxin/article/details/116160277)
- [LSPCI具体解释分析](https://www.cnblogs.com/yxwkf/p/3996202.html)
- [Single Root IO Virtualization (SR-IOV)二：SR-IOV 配置](https://blog.csdn.net/lincolnjunior_lj/article/details/131683558)