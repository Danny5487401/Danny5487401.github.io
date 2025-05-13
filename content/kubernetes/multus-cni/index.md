

---
title: "Multus Cni 多网卡"
date: 2025-03-28T22:24:08+08:00
summary: 多网卡方案 Multus Cni 实现原理
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
# 部署
kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/master/deployments/multus-daemonset-thick.yml
```
thick 插件包含两个二进制: multus-daemon and multus-shim CNI plugin

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
      "master": "ens32",
      "mode": "bridge",
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

# 查看网卡  eth0 是默认设备, net1 是macvlan 设置
samplepod:~# ip --detail link show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
2: eth0@if29: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether de:c3:b0:e3:f4:ee brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 0
    veth addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
3: net1@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether e2:34:6b:40:74:c2 brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 0
    macvlan mode bridge addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
    
# 查看调度的主机
(⎈|kubeasz-test:multus)➜  ~ kubectl get pod -o wide -n multus
NAME        READY   STATUS    RESTARTS   AGE   IP             NODE        NOMINATED NODE   READINESS GATES
samplepod   1/1     Running   0          14m   192.168.1.47   worker-01   <none>           <none>


[root@worker-01 ~]# ip --detail link show 
2: ens32: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether 00:0c:29:a5:19:4c brd ff:ff:ff:ff:ff:ff promiscuity 1 addrgenmode none numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
    
29: veth58af91b3@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue master cni0 state UP mode DEFAULT group default qlen 1000
    link/ether 86:df:6b:15:20:ca brd ff:ff:ff:ff:ff:ff link-netnsid 4 promiscuity 1
    veth
    bridge_slave state forwarding priority 32 cost 2 hairpin on guard off root_block off fastleave off learning on flood on port_id 0x8005 port_no 0x5 designated_port 32773 designated_cost 0 designated_bridge 8000.7e:8d:b5:89:fd:5b designated_root 8000.7e:8d:b5:89:fd:5b hold_timer    0.00 message_age_timer    0.00 forward_delay_timer    0.00 topology_change_ack 0 config_pending 0 proxy_arp off proxy_arp_wifi off mcast_router 1 mcast_fast_leave off mcast_flood on addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
```

```shell
(⎈|kubeasz-test:multus)➜  ~ kubectl get pod  -n multus samplepod -o yaml | yq .metadata.annotations
k8s.v1.cni.cncf.io/network-status: |-
  [{
      "name": "cbr0",
      "interface": "eth0",
      "ips": [
          "192.168.1.47"
      ],
      "mac": "de:c3:b0:e3:f4:ee",
      "default": true,
      "dns": {},
      "gateway": [
          "192.168.1.1"
      ]
  },{
      "name": "multus/macvlan-conf",
      "interface": "net1",
      "ips": [
          "192.168.1.201"
      ],
      "mac": "e2:34:6b:40:74:c2",
      "dns": {},
      "gateway": [
          "\u003cnil\u003e"
      ]
  }]
k8s.v1.cni.cncf.io/networks: macvlan-conf
```


## 参考

- https://github.com/k8snetworkplumbingwg/multus-cni/blob/master/docs/quickstart.md
- [kubernetes 多网卡方案之 Multus_CNI 部署和基本使用](https://xie.infoq.cn/article/e1d6c58939f6b1973221083fd)