---
title: "Multus Cni 多网卡"
date: 2025-03-28T22:24:08+08:00
summary: 多网卡方案 Multus Cni 实现原理,macvlan 实践
categories:
  - kubernetes
  - cni
tags:
  - k8s
  - cni
  - 源码
---

一个容器启动后，在默认情况下一般都会只存在两个虚拟网络接口（loopback 和 eth0），而 loopback 的流量始终都会在本容器内或本机循环，真正对业务起到支撑作用的只有 eth0，当然这对大部分业务场景而言已经能够满足。


但是如果一个应用或服务既需要对外提供 API 调用服务，也需要满足自身基于分布式特性产生的数据同步，那么这时候一张网卡的性能显然很难达到生产级别的要求，网络流量延时、阻塞便成为此应用的一项瓶颈
## 使用
```shell
# 部署 thick 插件
kubectl apply -f https://github.com/k8snetworkplumbingwg/multus-cni/blob/19f9283db44d8533924e172a0359c115c43bd480/deployments/multus-daemonset-thick.yml
```

thick 插件包含两个二进制: multus-daemon and multus-shim CNI plugin

thin 插件不包含 multus-daemon




验证安装
```shell
[root@master-01 ~]# cat /etc/cni/net.d/00-multus.conf  | jq .
{
  "capabilities": {
    "portMappings": true
  },
  "cniVersion": "0.3.1",
  "logLevel": "verbose",
  "logToStderr": true,
  "name": "multus-cni-network",
  "clusterNetwork": "/host/etc/cni/net.d/10-flannel.conflist",
  "type": "multus-shim"
}
```



{{<figure src="./multus_with_macvlan.png#center" width=800px >}}

```shell
# 查看主机网卡
[root@master-01 ~]# ip link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: ens32: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether 00:0c:29:e0:d7:e1 brd ff:ff:ff:ff:ff:ff
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT group default
    link/ether 02:42:72:14:7d:5c brd ff:ff:ff:ff:ff:ff
4: dummy0: <BROADCAST,NOARP> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether b6:47:f1:db:31:f1 brd ff:ff:ff:ff:ff:ff
5: kube-ipvs0: <BROADCAST,NOARP> mtu 1500 qdisc noop state DOWN mode DEFAULT group default
    link/ether 5e:df:62:98:fd:e3 brd ff:ff:ff:ff:ff:ff
6: nodelocaldns: <BROADCAST,NOARP> mtu 1500 qdisc noop state DOWN mode DEFAULT group default
    link/ether 86:f6:e3:35:46:65 brd ff:ff:ff:ff:ff:ff
7: flannel.1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UNKNOWN mode DEFAULT group default
    link/ether 0a:08:b0:d6:65:bc brd ff:ff:ff:ff:ff:ff
8: cni0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 0a:32:e4:8a:37:a0 brd ff:ff:ff:ff:ff:ff
10: veth842cff09@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue master cni0 state UP mode DEFAULT group default qlen 1000
    link/ether ae:fc:36:03:70:af brd ff:ff:ff:ff:ff:ff link-netnsid 1
11: vethcb6c5598@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue master cni0 state UP mode DEFAULT group default qlen 1000
    link/ether f2:ae:4e:ff:fc:c4 brd ff:ff:ff:ff:ff:ff link-netnsid 2
12: vethd5fcd3c6@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue master cni0 state UP mode DEFAULT group default qlen 1000
    link/ether 22:06:19:01:a6:e8 brd ff:ff:ff:ff:ff:ff link-netnsid 3
18: veth8e814977@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue master cni0 state UP mode DEFAULT group default qlen 1000
    link/ether 16:c9:f3:3a:54:dc brd ff:ff:ff:ff:ff:ff link-netnsid 0
19: veth86107cfc@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue master cni0 state UP mode DEFAULT group default qlen 1000
    link/ether 36:96:e6:6a:78:74 brd ff:ff:ff:ff:ff:ff link-netnsid 4


# 创建 macvlan  NetworkAttachmentDefinition
(⎈|kubeasz-test:multus)➜  ~ cat <<EOF | kubectl apply -f -
apiVersion: "k8s.cni.cncf.io/v1"
kind: NetworkAttachmentDefinition
metadata:
  name: macvlan-conf
spec:
  config: '{
      "cniVersion": "0.3.0",
      "type": "macvlan",
      "master": "ens32", # 父接口
      "mode": "bridge", # 模式
      "ipam": {
        "type": "host-local",
        "subnet": "192.168.1.0/24",
        "rangeStart": "192.168.1.200",
        "rangeEnd": "192.168.1.216",
        "routes": [
          { "dst": "0.0.0.0/0" }
        ],
        "gateway": "192.168.1.1"
      }
    }'
EOF
```
我这里的默认网卡是 ens32, 其他人可能是 eth0


```shell
(⎈|kubeasz-test:multus)➜  ~ cat <<EOF | kubectl create -f -
apiVersion: v1
kind: Pod
metadata:
  name: samplepod
  annotations:
    k8s.v1.cni.cncf.io/networks: macvlan-conf
spec:
  containers:
  - name: samplepod
    command: ["/bin/ash", "-c", "trap : TERM INT; sleep infinity & wait"]
    image: swr.cn-north-4.myhuaweicloud.com/ddn-k8s/docker.io/nicolaka/netshoot:v0.13
EOF

samplepod:~# ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host proto kernel_lo
       valid_lft forever preferred_lft forever
2: eth0@if76: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UP group default qlen 1000
    link/ether 66:59:21:19:8f:ae brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.233.75.110/32 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::6459:21ff:fe19:8fae/64 scope link proto kernel_ll
       valid_lft forever preferred_lft forever
3: net1@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 8a:1f:45:26:b5:22 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 192.168.1.201/24 brd 192.168.1.255 scope global net1
       valid_lft forever preferred_lft forever
    inet6 fe80::881f:45ff:fe26:b522/64 scope link proto kernel_ll
       valid_lft forever preferred_lft forever

# 查看网卡  eth0 是默认设备, net1 是macvlan 设置
samplepod:~# ip --detail link show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0 allmulti 0 minmtu 0 maxmtu 0 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 gso_ipv4_max_size 65536 gro_ipv4_max_size 65536
2: eth0@if76: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 66:59:21:19:8f:ae brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 0 allmulti 0 minmtu 68 maxmtu 65535
    veth numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 gso_ipv4_max_size 65536 gro_ipv4_max_size 65536
3: net1@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default
    link/ether 8a:1f:45:26:b5:22 brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 0 allmulti 0 minmtu 68 maxmtu 16110
    macvlan mode bridge bcqueuelen 1000 usedbcqueuelen 1000 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 65536 tso_max_segs 65535 gro_max_size 65536 gso_ipv4_max_size 65536 gro_ipv4_max_size 65536
      
# 查看调度的主机
(⎈|kubeasz-test:multus)➜  ~ kubectl get pod -n multus samplepod -o wide
NAME        READY   STATUS    RESTARTS   AGE    IP              NODE    NOMINATED NODE   READINESS GATES
samplepod   1/1     Running   0          6m5s   10.233.75.110   node6   <none>           <none>


root@node6:~# ip --detail link show ens32
2: ens32: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether 00:0c:29:84:50:cf brd ff:ff:ff:ff:ff:ff promiscuity 1  allmulti 0 minmtu 46 maxmtu 16110 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 65536 tso_max_segs 65535 gro_max_size 65536 parentbus pci parentdev 0000:02:00.0
    altname enp2s0
```

```shell
(⎈|kubeasz-test:multus)➜  ~ kubectl get pod  -n multus samplepod -o yaml | yq .metadata.annotations
cni.projectcalico.org/containerID: b1939350a0b3ecd99b52f90366838e0da8843e9f8b7945c6e153ea971cd80a89
cni.projectcalico.org/podIP: 10.233.75.110/32
cni.projectcalico.org/podIPs: 10.233.75.110/32
k8s.v1.cni.cncf.io/network-status: |-
  [{
      "name": "k8s-pod-network",
      "ips": [
          "10.233.75.110"
      ],
      "default": true,
      "dns": {}
  },{
      "name": "multus/macvlan-conf",
      "interface": "net1",
      "ips": [
          "192.168.1.201"
      ],
      "mac": "8a:1f:45:26:b5:22",
      "dns": {},
      "gateway": [
          "\u003cnil\u003e"
      ]
  }]
k8s.v1.cni.cncf.io/networks: macvlan-conf
```


## 流程

### 添加

客户端调用
```go
// https://github.com/k8snetworkplumbingwg/multus-cni/blob/7eb9673a1ae4e3e6b7e47951646f5c57513d696f/pkg/server/api/shim.go
func CmdAdd(args *skel.CmdArgs) error {
	response, cniVersion, err := postRequest(args, WaitUntilAPIReady)
	if err != nil {
		return logging.Errorf("CmdAdd (shim): %v", err)
	}

	logging.Verbosef("CmdAdd (shim): %v", *response.Result)
	return cnitypes.PrintResult(response.Result, cniVersion)
}

func postRequest(args *skel.CmdArgs, readinessCheck readyCheckFunc) (*Response, string, error) {
	// 获取配置
	multusShimConfig, err := shimConfig(args.StdinData)
	if err != nil {
		return nil, "", fmt.Errorf("invalid CNI configuration passed to multus-shim: %w", err)
	}

	// ready 检查
	// Execute the readiness check as necessary (e.g. don't wait on CNI DEL)
	if err := readinessCheck(multusShimConfig.MultusSocketDir); err != nil {
		return nil, multusShimConfig.CNIVersion, err
	}

	// 准备请求
	cniRequest, err := newCNIRequest(args)
	if err != nil {
		return nil, multusShimConfig.CNIVersion, err
	}

	// 调用 本地 unix socket 
	var body []byte
	body, err = DoCNI("http://dummy/cni", cniRequest, SocketPath(multusShimConfig.MultusSocketDir))
	if err != nil {
		return nil, multusShimConfig.CNIVersion, fmt.Errorf("%s: StdinData: %s", err.Error(), string(args.StdinData))
	}

	response := &Response{}
	if len(body) != 0 {
		if err = json.Unmarshal(body, response); err != nil {
			err = fmt.Errorf("failed to unmarshal response '%s': %v", string(body), err)
			return nil, multusShimConfig.CNIVersion, err
		}
	}
	return response, multusShimConfig.CNIVersion, nil
}

```


服务端处理

```go
// https://github.com/k8snetworkplumbingwg/multus-cni/blob/a439f917215a42f7fce4695c3d98546fa2961e2a/pkg/server/server.go

func (s *Server) handleCNIRequest(r *http.Request) ([]byte, error) {
	var cr api.Request
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &cr); err != nil {
		return nil, err
	}
	cmdType, cniCmdArgs, err := s.extractCniData(&cr, s.serverConfig)
	if err != nil {
		return nil, fmt.Errorf("could not extract the CNI command args: %w", err)
	}

	// 获取 k8s 运行参数
	k8sArgs, err := kubernetesRuntimeArgs(cr.Env, s.kubeclient)
	if err != nil {
		return nil, fmt.Errorf("could not extract the kubernetes runtime args: %w", err)
	}

	result, err := s.HandleCNIRequest(cmdType, k8sArgs, cniCmdArgs)
	if err != nil {
		// Prefix error with request information for easier debugging
		return nil, fmt.Errorf("%s ERRORED: %v", printCmdArgs(cniCmdArgs), err)
	}
	return result, nil
}

func (s *Server) HandleCNIRequest(cmd string, k8sArgs *types.K8sArgs, cniCmdArgs *skel.CmdArgs) ([]byte, error) {
	var result []byte
	var err error

	logging.Verbosef("%s starting CNI request %s", cmd, printCmdArgs(cniCmdArgs))
	switch cmd {
	case "ADD":
		result, err = s.cmdAdd(cniCmdArgs, k8sArgs)
	case "DEL":
		err = s.cmdDel(cniCmdArgs, k8sArgs)
	case "CHECK":
		err = s.cmdCheck(cniCmdArgs, k8sArgs)
	case "GC":
		err = s.cmdGC(cniCmdArgs, k8sArgs)
	case "STATUS":
		err = s.cmdStatus(cniCmdArgs, k8sArgs)
	default:
		return []byte(""), fmt.Errorf("unknown cmd type: %s", cmd)
	}
	logging.Verbosef("%s finished CNI request %s, result: %q, err: %v", cmd, printCmdArgs(cniCmdArgs), string(result), err)
	return result, err
}


func (s *Server) cmdAdd(cmdArgs *skel.CmdArgs, k8sArgs *types.K8sArgs) ([]byte, error) {
	namespace := string(k8sArgs.K8S_POD_NAMESPACE)
	podName := string(k8sArgs.K8S_POD_NAME)
	if namespace == "" || podName == "" {
		return nil, fmt.Errorf("required CNI variable missing. pod name: %s; pod namespace: %s", podName, namespace)
	}

	logging.Debugf("CmdAdd for [%s/%s]. CNI conf: %+v", namespace, podName, *cmdArgs)
	result, err := multus.CmdAdd(cmdArgs, s.exec, s.kubeclient)
	if err != nil {
		return nil, fmt.Errorf("error configuring pod [%s/%s] networking: %v", namespace, podName, err)
	}
	return serializeResult(result)
}
```

```go
func CmdAdd(args *skel.CmdArgs, exec invoke.Exec, kubeClient *k8s.ClientInfo) (cnitypes.Result, error) {
	n, err := types.LoadNetConf(args.StdinData)
	logging.Debugf("CmdAdd: %v, %v, %v", args, exec, kubeClient)
	if err != nil {
		return nil, cmdErr(nil, "error loading netconf: %v", err)
	}

	kubeClient, err = k8s.GetK8sClient(n.Kubeconfig, kubeClient)
	if err != nil {
		return nil, cmdErr(nil, "error getting k8s client: %v", err)
	}

	k8sArgs, err := k8s.GetK8sArgs(args)
	if err != nil {
		return nil, cmdErr(nil, "error getting k8s args: %v", err)
	}

	if n.ReadinessIndicatorFile != "" {
		if err := types.GetReadinessIndicatorFile(n.ReadinessIndicatorFile); err != nil {
			return nil, cmdErr(k8sArgs, "have you checked that your default network is ready? still waiting for readinessindicatorfile @ %v. pollimmediate error: %v", n.ReadinessIndicatorFile, err)
		}
	}

	pod, err := GetPod(kubeClient, k8sArgs, false)
	if err != nil {
		if err == errPodNotFound {
			logging.Verbosef("CmdAdd: Warning: pod [%s/%s] not found, exiting with empty CNI result", k8sArgs.K8S_POD_NAMESPACE, k8sArgs.K8S_POD_NAME)
			return &cni100.Result{
				CNIVersion: n.CNIVersion,
			}, nil
		}
		return nil, err
	}

	// resourceMap holds Pod device allocation information; only initizized if CRD contains 'resourceName' annotation.
	// This will only be initialized once and all delegate objects can reference this to look up device info.
	var resourceMap map[string]*types.ResourceInfo

	if n.ClusterNetwork != "" {
		resourceMap, err = k8s.GetDefaultNetworks(pod, n, kubeClient, resourceMap)
		if err != nil {
			return nil, cmdErr(k8sArgs, "failed to get clusterNetwork/defaultNetworks: %v", err)
		}
		// First delegate is always the master plugin
		n.Delegates[0].MasterPlugin = true
	}

	_, kc, err := k8s.TryLoadPodDelegates(pod, n, kubeClient, resourceMap)
	if err != nil {
		return nil, cmdErr(k8sArgs, "error loading k8s delegates k8s args: %v", err)
	}

	// cache the multus config
	if err := saveDelegates(args.ContainerID, n.CNIDir, n.Delegates); err != nil {
		return nil, cmdErr(k8sArgs, "error saving the delegates: %v", err)
	}

	var result, tmpResult cnitypes.Result
	var netStatus []nettypes.NetworkStatus
	for idx, delegate := range n.Delegates {
		ifName := getIfname(delegate, args.IfName, idx)
		rt, cniDeviceInfoPath := types.CreateCNIRuntimeConf(args, k8sArgs, ifName, n.RuntimeConfig, delegate)
		if cniDeviceInfoPath != "" && delegate.ResourceName != "" && delegate.DeviceID != "" {
			err = nadutils.CopyDeviceInfoForCNIFromDP(cniDeviceInfoPath, delegate.ResourceName, delegate.DeviceID)
			// Even if the filename is set, file may not be present. Ignore error,
			// but log and in the future may need to filter on specific errors.
			if err != nil {
				logging.Debugf("CmdAdd: CopyDeviceInfoForCNIFromDP returned an error - err=%v", err)
			}
		}

		// We collect the delegate netName for the cachefile name as well as following errors
		netName := delegate.Conf.Name
		if netName == "" {
			netName = delegate.ConfList.Name
		}
		// 逐个插件调用
		tmpResult, err = DelegateAdd(exec, kubeClient, pod, delegate, rt, n)
		if err != nil {
			// 调用失败, 还原环境
			// If the add failed, tear down all networks we already added
			// Ignore errors; DEL must be idempotent anyway
			_ = delPlugins(exec, nil, args, k8sArgs, n.Delegates, idx, n.RuntimeConfig, n)
			return nil, cmdPluginErr(k8sArgs, netName, "error adding container to network %q: %v", netName, err)
		}

		// Master plugin result is always used if present
		if delegate.MasterPlugin || result == nil {
			result = tmpResult
		}

		res, err := cni100.NewResultFromResult(tmpResult)
		if err != nil {
			logging.Errorf("CmdAdd: failed to read result: %v, but proceed", err)
		}

		// check Interfaces and IPs because some CNI plugin does not create any interface
		// and just returns empty result
		if res != nil && (res.Interfaces != nil || res.IPs != nil) {
			// Remove gateway from routing table if the gateway is not used
			deleteV4gateway := false
			deleteV6gateway := false
			adddefaultgateway := false
			if delegate.IsFilterV4Gateway {
				deleteV4gateway = true
				logging.Debugf("Marked interface %v for v4 gateway deletion", ifName)
			} else {
				// Otherwise, determine if this interface now gets our default route.
				// According to
				// https://docs.google.com/document/d/1Ny03h6IDVy_e_vmElOqR7UdTPAG_RNydhVE1Kx54kFQ (4.1.2.1.9)
				// the list can be empty; if it is, we'll assume the CNI's config for the default gateway holds,
				// else we'll update the defaultgateway to the one specified.
				if delegate.GatewayRequest != nil && len(*delegate.GatewayRequest) != 0 {
					deleteV4gateway = true
					adddefaultgateway = true
					logging.Debugf("Detected gateway override on interface %v to %v", ifName, delegate.GatewayRequest)
				}
			}

			if delegate.IsFilterV6Gateway {
				deleteV6gateway = true
				logging.Debugf("Marked interface %v for v6 gateway deletion", ifName)
			} else {
				// Otherwise, determine if this interface now gets our default route.
				// According to
				// https://docs.google.com/document/d/1Ny03h6IDVy_e_vmElOqR7UdTPAG_RNydhVE1Kx54kFQ (4.1.2.1.9)
				// the list can be empty; if it is, we'll assume the CNI's config for the default gateway holds,
				// else we'll update the defaultgateway to the one specified.
				if delegate.GatewayRequest != nil && len(*delegate.GatewayRequest) != 0 {
					deleteV6gateway = true
					adddefaultgateway = true
					logging.Debugf("Detected gateway override on interface %v to %v", ifName, delegate.GatewayRequest)
				}
			}

			// Remove gateway if `default-route` network selection is specified
			if deleteV4gateway || deleteV6gateway {
				err = netutils.DeleteDefaultGW(args.Netns, ifName)
				if err != nil {
					return nil, cmdErr(k8sArgs, "error deleting default gateway: %v", err)
				}
				err = netutils.DeleteDefaultGWCache(n.CNIDir, rt, netName, ifName, deleteV4gateway, deleteV6gateway)
				if err != nil {
					return nil, cmdErr(k8sArgs, "error deleting default gateway in cache: %v", err)
				}
			}

			// Here we'll set the default gateway which specified in `default-route` network selection
			if adddefaultgateway {
				err = netutils.SetDefaultGW(args.Netns, ifName, *delegate.GatewayRequest)
				if err != nil {
					return nil, cmdErr(k8sArgs, "error setting default gateway: %v", err)
				}
				err = netutils.AddDefaultGWCache(n.CNIDir, rt, netName, ifName, *delegate.GatewayRequest)
				if err != nil {
					return nil, cmdErr(k8sArgs, "error setting default gateway in cache: %v", err)
				}
			}
		}

		// Read devInfo from CNIDeviceInfoFile if it exists so
		// it can be copied to the NetworkStatus.
		devinfo, err := getDelegateDeviceInfo(delegate, rt)
		if err != nil {
			// Even if the filename is set, file may not be present. Ignore error,
			// but log and in the future may need to filter on specific errors.
			logging.Debugf("CmdAdd: getDelegateDeviceInfo returned an error - err=%v", err)
		}

		// Create the network statuses, only in case Multus has kubeconfig
		if kubeClient != nil && kc != nil {
			if !types.CheckSystemNamespaces(string(k8sArgs.K8S_POD_NAME), n.SystemNamespaces) {
				delegateNetStatuses, err := nadutils.CreateNetworkStatuses(tmpResult, delegate.Name, delegate.MasterPlugin, devinfo)
				if err != nil {
					return nil, cmdErr(k8sArgs, "error setting network statuses: %v", err)
				}

				// Append all returned statuses after dereferencing each
				for _, status := range delegateNetStatuses {
					netStatus = append(netStatus, *status)
				}
			}
		} else if devinfo != nil {
			// Warn that devinfo exists but could not add it to downwards API
			logging.Errorf("devinfo available, but no kubeConfig so NetworkStatus not modified.")
		}
	}

	// set the network status annotation in apiserver, only in case Multus has kubeconfig
	if kubeClient != nil && kc != nil {
		if !types.CheckSystemNamespaces(string(k8sArgs.K8S_POD_NAME), n.SystemNamespaces) {
			err = k8s.SetNetworkStatus(kubeClient, k8sArgs, netStatus, n)
			if err != nil {
				if strings.Contains(err.Error(), `pod "`) && strings.Contains(err.Error(), `" not found`) {
					// Tolerate issues with writing the status due to pod deletion, and log them.
					logging.Verbosef("warning: tolerated failure writing network status (pod not found): %v", err)
				} else {
					return nil, cmdErr(k8sArgs, "error setting the networks status: %v", err)
				}
			}
		}
	}

	return result, nil
}
```



## 参考

- https://github.com/k8snetworkplumbingwg/multus-cni/blob/v4.2.2/docs/quickstart.md
- [kubernetes 多网卡方案之 Multus_CNI 部署和基本使用](https://xie.infoq.cn/article/e1d6c58939f6b1973221083fd)