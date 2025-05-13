<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [为什么需要集群均衡器](#%E4%B8%BA%E4%BB%80%E4%B9%88%E9%9C%80%E8%A6%81%E9%9B%86%E7%BE%A4%E5%9D%87%E8%A1%A1%E5%99%A8)
- [参考](#%E5%8F%82%E8%80%83)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

---
title: "Descheduler 集群均衡器"
summary: "集群已调度pod 再次调度"
date: 2025-03-11T20:47:47+08:00
draft: true
---

## 为什么需要集群均衡器
从 kube-scheduler 的角度来看，它通过各种算法计算出最佳节点去运行 Pod 是非常完美的，当出现新的 Pod 进行调度时，调度程序会根据其当时对 Kubernetes 集群的资源描述做出最佳调度决定。
但是 Kubernetes 集群是非常动态的，由于整个集群范围内的变化，比如一个节点为了维护，我们先执行了驱逐操作，这个节点上的所有 Pod 会被驱逐到其他节点去，
但是当我们维护完成后，之前的 Pod 并不会自动回到该节点上来，因为 Pod 一旦被绑定了节点是不会触发重新调度的，由于这些变化，Kubernetes 集群在一段时间内就出现了不均衡的状态，所以需要均衡器来重新平衡集群


- 一些节点过度使用
- 节点添加污点或则labels后,节点上的pod 不不符合要求
- 当新节点被添加到集群



## 参考
- https://github.com/kubernetes-sigs/descheduler
- [Kubernetes 集群均衡器 Descheduler](https://www.qikqiak.com/post/k8s-cluster-balancer/)