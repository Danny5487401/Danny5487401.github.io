---
title: "Kubelet 监控API"
date: 2025-08-24T11:14:48+08:00
draft: true
---




在Kubelet Server提供的监控API中，大致可以分为两类：stats（统计数据）和metrics（指标数据）。
从命名和实际作用来看，前者提供了粗粒度的基础监控能力，目前用于各种内置组件；而后者用于持久化地进行细粒度的容器监控，主要提供给Prometheus等。


## 指标类API
Kubelet Server提供的指标类API目前包括以下四个：

/metrics：提供kubelet自身相关的一些监控，包括：apiserver请求、go gc/内存/线程相关、kubelet子模块关键信息、client-go等指标
/metrics/cadvisor：提供Pod/容器监控信息
/metrics/probes：提供对容器Liveness/Readiness/Startup探针的指标数据
/metrics/resource：提供Pod/容器的CPU用量、wss内存、启动时间基础指标数据







## 参考

