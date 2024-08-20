---
title: "Workqueue"
date: 2024-08-20T13:43:28+08:00
draft: true
---

# workqueue


在 kubernetes 中，使用 go 的 channel 无法满足 kubernetes 的应用场景，如延迟、限速等；
在 kubernetes 中存在三种队列通用队列 common queue ，延迟队列 delaying queue，和限速队列 rate limiters queue


## 需求


**为什么队列需要去重功能 ?**

当一个资源对象被频繁变更, 然而同一个对象还未被消费, 没必要在在队列中存多份, 经过去重后只需要处理一次即可.

**为什么需要 delay 延迟入队功能 ?**

有些 k8s controller 是需要延迟队列功能的, 比如像 cronjob 依赖延迟队列实现定时功能. 另外也可以实现延迟 backoff 时长后重入队.

**为什么需要限频功能 ?**

避免过多事件并发入队, 使用限频策略对入队的事件个数进行控制. k8s 中的 controller 大把的使用限频.

**informer 中的 deltafifo 跟 workqueue 区别?**

deltafifo 虽然名为 fifo 队列, 但他的 fifo 不是全局事件, 而只是针对某资源对象的事件进行内部 fifo 排列. 比如某个 deployment 频繁做变更, 那么 deltafifo 逻辑是把后续收到的相关事件放在一起.


## 参考

- [Kubernetes 架构之 workqueue 原理解析](https://mp.weixin.qq.com/s/pkyBuTLtmKKWCBHSQ82d9g)