---
title: "kube-proxy"
date: 2024-12-03T16:41:05+08:00
summary: "kube-proxy 实现原理及源码 release-1.27 分析,主要 iptables 模式为例讲解"
categories:
  - kubernetes
authors:
  - Danny

tags:
  - k8s
  - kube-proxy
  - 源码
---


```go
// https://github.com/kubernetes/kubernetes/blob/c2bae4dfbd5fb84cbcc53a949231935276a75a51/pkg/proxy/apis/config/types.go
const (
	ProxyModeIPTables    ProxyMode = "iptables"
	ProxyModeIPVS        ProxyMode = "ipvs"
	ProxyModeKernelspace ProxyMode = "kernelspace"
)

```
kube-proxy先后出现了三种模式：userspace、iptables、ipvs，其中userspace模式是通过用户态程序实现转发，因性能问题基本被弃用，当前主流的模式是iptables和ipvs。


## 问题

### kube-proxy是否可以不用安装，是否有其他替代品?


## iptables 模式

iptables 的功能：

- 流量转发：DNAT 实现 IP 地址和端口的映射；
- 负载均衡：statistic 模块为每个后端设置权重；
- 会话保持：recent 模块设置会话保持时间；

kube-proxy iptables模式只在nat表和filter表增加了iptables规则

### proxier 初始化

```go
func NewProxier(ipFamily v1.IPFamily,
	ipt utiliptables.Interface,
	sysctl utilsysctl.Interface,
	exec utilexec.Interface,
	syncPeriod time.Duration,
	minSyncPeriod time.Duration,
	masqueradeAll bool,
	localhostNodePorts bool,
	masqueradeBit int,
	localDetector proxyutiliptables.LocalTrafficDetector,
	hostname string,
	nodeIP net.IP,
	recorder events.EventRecorder,
	healthzServer healthcheck.ProxierHealthUpdater,
	nodePortAddressStrings []string,
) (*Proxier, error) {
    // ...

	// 初始化 proxier
	proxier := &Proxier{
		svcPortMap:               make(proxy.ServicePortMap),
		serviceChanges:           proxy.NewServiceChangeTracker(newServiceInfo, ipFamily, recorder, nil),
		endpointsMap:             make(proxy.EndpointsMap),
		endpointsChanges:         proxy.NewEndpointChangeTracker(hostname, newEndpointInfo, ipFamily, recorder, nil),
		needFullSync:             true,
		syncPeriod:               syncPeriod,
		iptables:                 ipt,
		masqueradeAll:            masqueradeAll,
		masqueradeMark:           masqueradeMark, // 用来标记 k8s 管理的报文，masqueradeBit 默认为 14, 标记 0x4000 的报文（即 POD 发出的报文)，在离开 Node 的时候需要进行 SNAT 转换
		exec:                     exec,
		localDetector:            localDetector,
		hostname:                 hostname,
		nodeIP:                   nodeIP,
		recorder:                 recorder,
		serviceHealthServer:      serviceHealthServer,
		healthzServer:            healthzServer,
		precomputedProbabilities: make([]string, 0, 1001),
		iptablesData:             bytes.NewBuffer(nil),
		existingFilterChainsData: bytes.NewBuffer(nil),
		filterChains:             utilproxy.LineBuffer{},
		filterRules:              utilproxy.LineBuffer{},
		natChains:                utilproxy.LineBuffer{},
		natRules:                 utilproxy.LineBuffer{},
		localhostNodePorts:       localhostNodePorts,
		nodePortAddresses:        nodePortAddresses,
		networkInterfacer:        utilproxy.RealNetwork{},
	}

    // 初始化 syncRunner，BoundedFrequencyRunner 是一个定时执行器，会定时执行
    // proxier.syncProxyRules 方法,syncProxyRules 是每个 proxier 实际刷新iptables 规则的方法
	proxier.syncRunner = async.NewBoundedFrequencyRunner("sync-runner", proxier.syncProxyRules, minSyncPeriod, time.Hour, burstSyncs)

    // ...

	return proxier, nil
}
```


### 更新规则 syncProxyRules 

<details>
    <summary> 更新 proxier.endpointsMap，proxier.servieMap 两个对象 </summary>
    <p>
    </p>
    <pre><code>
func (proxier *Proxier) syncProxyRules() {
	proxier.mu.Lock()
	defer proxier.mu.Unlock()
    // ...
	serviceUpdateResult := proxier.svcPortMap.Update(proxier.serviceChanges)
	endpointUpdateResult := proxier.endpointsMap.Update(proxier.endpointsChanges)
}
	</code></pre>
</details>


<details>
    <summary> 创建所需要的 iptable 链 </summary>
    <p>
    </p>
    <pre><code>
if !tryPartialSync {
	for _, jump := range append(iptablesJumpChains, iptablesKubeletJumpChains...) {
		// 创建自定义链
		if _, err := proxier.iptables.EnsureChain(jump.table, jump.dstChain); err != nil {
			klog.ErrorS(err, "Failed to ensure chain exists", "table", jump.table, "chain", jump.dstChain)
			return
		}
		args := jump.extraArgs
		if jump.comment != "" {
			args = append(args, "-m", "comment", "--comment", jump.comment)
		}
		args = append(args, "-j", string(jump.dstChain))
		// 插入到已有的链
		if _, err := proxier.iptables.EnsureRule(utiliptables.Prepend, jump.table, jump.srcChain, args...); err != nil {
			klog.ErrorS(err, "Failed to ensure chain jumps", "table", jump.table, "srcChain", jump.srcChain, "dstChain", jump.dstChain)
			return
		}
	}
}
	</code></pre>
</details>


待补充



## 参考

- [iptables 详解--朱双印笔记](https://www.zsythink.net/archives/tag/iptables/page/1)
- [kube-proxy iptables模式实现的普通clusterIP类型的service原理](https://juejin.cn/post/7134143215380201479)
- [BoundedFrequencyRunner 源码分析: 周期性的执行同步方法，并且提供了执行失败进行重试，内部封装了运行的限流器](https://juejin.cn/post/7326478882068447242)
- [源码分析 kubernetes kube-proxy 的实现原理-ipvs 模式讲解](https://github.com/rfyiamcool/notes/blob/main/kubernetes_kube_proxy_code.md)
- [kube-proxy iptables 模式源码分析](https://cloud.tencent.com/developer/article/1553957)