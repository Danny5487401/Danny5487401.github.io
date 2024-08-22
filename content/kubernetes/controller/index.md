---
title: "Controller"
date: 2024-08-22T10:41:17+08:00
summary: 控制器进化之旅
categories:
  - kubernetes
tags:
  - k8s
  - controller
---

# 控制器

控制循环就是一个用来调节系统状态的周期性操作，在 Kubernetes 中也叫调谐循环（Reconcile Loop）。我的手下控制着很多种不同类型的资源，比如 Pod，Deployment，Service 等等。就拿 Deployment 来说吧，我的控制循环主要分为三步：

从 API Server 中获取到所有属于该 Deployment 的 Pod，然后统计一下它们的数量，即它们的实际状态。

检查 Deployment 的 Replicas 字段，看看期望状态是多少个 Pod。

将这两个状态做比较，如果期望状态的 Pod 数量比实际状态多，就创建新 Pod，多几个就创建几个新的；如果期望状态的 Pod 数量比实际状态少，就删除旧 Pod，少几个就删除几个旧的。



## 控制器进化之旅


### 第一阶段：控制器直接访问api-server

{{<figure src="./controller_1.png#center" width=800px >}}

过多的请求，导致api-server压力过大

### 第二阶段：控制器通过informer访问api-server

{{<figure src="./controller_2.png#center" width=800px >}}
Reflector 大部分时间都在 WATCH，并没有通过 LIST 获取所有状态，这使 API Server 的压力大大减少.

- informer提供的List And Watch机制，增量的请求api-server
- watch时，只watch特定的资源

### 多个控制器共享informer访问api-server

{{<figure src="./controller_3.png#center" width=800px >}}

针对每个（受多个控制器管理的）资源招一个 Informer 小弟.SharedInformer 无法同时给多个控制器提供信息，这就需要每个控制器自己排队和重试。

为了配合控制器更好地实现排队和重试，SharedInformer  搞了一个 Delta FIFO Queue（增量先进先出队列），每当资源被修改时，它的助手 Reflector 就会收到事件通知，并将对应的事件放入 Delta FIFO Queue 中。与此同时，SharedInformer 会不断从 Delta FIFO Queue 中读取事件，然后更新本地缓存的状态。

这还不行，SharedInformer 除了更新本地缓存之外，还要想办法将数据同步给各个控制器，为了解决这个问题，它又搞了个工作队列（Workqueue），一旦有资源被添加、修改或删除，就会将相应的事件加入到工作队列中。所有的控制器排队进行读取，一旦某个控制器发现这个事件与自己相关，就执行相应的操作。如果操作失败，就将该事件放回队列，等下次排到自己再试一次。如果操作成功，就将该事件从队列中删除。


- 受多个控制器管理的资源对象，共享Informer，进一步提高效率。比如：Deployment和DaemonSet两个控制器都管理pod资源
- DeltaFIFO队列用于处理事件通知，并更新本地缓存
- WorkQueue队列用于通知各个控制器处理事件


### 第四阶段：自定义控制器+自定义资源访问 api-server
{{<figure src="./controller_4.png#center" width=800px >}}
随着容器及其编排技术的普及，使用 Kubernetes 的用户大量增长，用户已经不满足 Kubernetes 自带的那些资源（Pod，Node，Service）了，大家都希望能根据具体的业务创建特定的资源，并


### Open Application Model(OAM)
{{<figure src="./controller_5.png#center" width=800px >}}

Open Application Model 。这个模型就是为了解决上面提到的问题，将开发和运维的职责解耦，不同的角色履行不同的职责，并形成一个统一的规范，如下图所示




## 参考

- [Kubernetes控制器进化之旅：从资源控制到开放应用模型](https://mp.weixin.qq.com/s/9fdDLrUt-rCnwP7JZ35eog)
- oam 模型: https://github.com/oam-dev/spec
- oam 实现: https://github.com/kubevela/kubevela