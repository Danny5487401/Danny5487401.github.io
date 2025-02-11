---
title: "k8s 部署"
date: 2024-12-27T17:16:39+08:00
summary: k8s 生产级别部署:内核参数调优等
categories:
  - kubernetes
tags:
  - k8s
---



## 部署工具
[部署工具对比](https://github.com/kubernetes-sigs/kubespray/blob/master/docs/getting_started/comparisons.md)

- github.com/kubernetes-sigs/kubespray: 使用 ansible 作为配置和编排的基础
- github.com/kubernetes/kops: 与云平台绑定深,比如 AWS (Amazon Web Services) and GCP (Google Cloud Platform)
- github.com/kubernetes/kubeadm
- github.com/easzlab/kubeasz: 使用 ansible 脚本安装K8S集群,方便国内网络环境


## 系统内核参数设置
- https://github.com/kubernetes-sigs/kubespray/blob/v2.26.0/roles/kubernetes/preinstall/tasks/0080-system-configurations.yml

```shell
# https://github.com/easzlab/kubeasz/blob/3.6.5/roles/prepare/templates/95-k8s-sysctl.conf.j2
net.ipv4.ip_forward = 1 # 启用ip转发另外也防止docker改变iptables
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-arptables = 1
net.ipv4.tcp_tw_reuse = 0
net.core.somaxconn = 32768
net.netfilter.nf_conntrack_max=1000000
vm.swappiness = 0
vm.max_map_count=655360 # 限制一个进程可以拥有的VMA(虚拟内存区域)的数量，一个更大的值对于 elasticsearch、mongo 或其他 mmap 用户来说非常有用
fs.file-max=6553600
{% if PROXY_MODE == "ipvs" %}
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 10
{% endif %}
```

### net.core.somaxconn 
{{<figure src="tcp_process.png#center" width=800px >}}
Client在收到Server的SYNACK包后，就会发出ACK，Server收到该ACK后，三次握手就完成了，即产生了一个TCP全连接（complete），它会被添加到全连接队列（accept queue）中。然后Server就会调用accept()来完成TCP连接的建立
全连接队列（accept queue）的长度有限制，目的就是为了防止Server不能及时调用accept()而浪费太多的系统资源.
全连接队列（accept queue）的长度是由listen(sockfd, backlog)这个函数里的backlog控制的，而该backlog的最大值则是somaxconn

somaxconn在5.4之前的内核中，默认都是128（5.4开始调整为了默认4096）.

当服务器中积压的全连接个数超过该值后，新的全连接就会被丢弃掉。Server在将新连接丢弃时，有的时候需要发送reset来通知Client，这样Client就不会再次重试了。不过，默认行为是直接丢弃不去通知Client。至于是否需要给Client发送reset，是由tcp_abort_on_overflow这个配置项来控制的，该值默认为0，即不发送reset给Client。



## kubeasz 使用

[AllinOne部署](https://github.com/easzlab/kubeasz/blob/master/docs/setup/quickStart.md),然后再添加 master,node.




## kubeadm 使用
- kubeadm init 创建新的控制平面节点
- kubeadm join 将节点快速连接到指定的控制平面

## 参考

- https://kubernetes.io/zh-cn/docs/setup/production-environment/tools/
- [基础篇 TCP连接的建立和断开受哪些系统配置影响](https://time.geekbang.org/column/article/284912)
- [Kubespray实现生产环境一键部署k8s v1.25.6集群](https://www.magiccloudnet.com/kubespray/)
- https://github.com/kubernetes/kubernetes/tree/v1.32.0/cmd/kubeadm
