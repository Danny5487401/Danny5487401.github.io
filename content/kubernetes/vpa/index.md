---
title: "VPA（Vertical Pod Autoscaler 垂直 Pod 自动缩放器）"
date: 2025-05-17T21:11:31+08:00
summary: vpa 介绍及未来扩展
draft: true
---


垂直自动伸缩（VPA，Vertical Pod Autoscaler） 是一个基于历史数据、集群可使用资源数量和实时的事件（如 OMM， 即 out of memory）来自动设置Pod所需资源并且能够在运行时自动调整资源基础服务。


## VPA一般需要具备以下三种关键能力

1、容器资源规格推荐。基于应用的真实负载，根据特定的算法计算出容器的合理资源规格。

2、对于新创建的Pod，需要基于k8s webhook，在创建Pod对象的过程中将资源规格修改为推荐值。

3、对于已经创建的Pod，需要定时动态调整容器的资源规格。


## VPA 组成
{{<figure src="./vpa_structure.png#center" width=800px >}}

三部分
- admission-controller（准入控制器）
- recommender（推荐器）
- updater（更新器）


### 准入控制器（Admission Controller）


VPA Admission Controller 拦截 Pod 创建请求。如果 Pod 与 VPA 配置匹配且模式未设置为 off，则控制器通过将建议的资源应用于 Pod spec 来重写资源请求。


### 推荐器（Recommender）

Recommender 是 VPA 的主要组成部分。它负责计算推荐的资源。在启动时，Recommender 获取所有 Pod 的历史资源利用率（无论它们是否使用 VPA ）以及历史存储中的 Pod OOM 事件的历史记录。
它聚合这些数据并将其保存在内存中。


pRecommender的推荐算法深受Google Borg Autopilot的moving window推荐器的启发，moving window推荐器的原理可以看下Autopilot论文。
Vertical Pod Autoscaler的推荐器vpa-recommend为每个vpa对象的每个container创建存储cpu和memory使用值的decay histogram对象，定期从prometheus中拉取所有pod的资源使用情况，将container的usage写入histogram中。
decay histogram的桶的大小是按照指数增长的，cpu第一个桶的大小（firstBucketSize）是0.01，memory是1e7，指数值ratio是1.05




### 更新器（Updater）


VPA Updater 是一个负责将推荐资源应用于现有 Pod 的组件。它监视集群中的所有 VPA object 和 Pod ，通过调用 Recommender API 定期获取由 VPA 控制的 Pod 的建议。
当推荐的资源与实际配置的资源明显不同时，Updater 可能会决定更新 Pod。


## 更新策略（Update Policy）

mode 可以设置为三种：

Initial: VPA 只在创建 Pod 时分配资源，在 Pod 的其他生命周期不改变Pod的资源。

Auto(默认)：VPA 在 Pod 创建时分配资源，并且能够在 Pod 的其他生命周期更新它们，包括淘汰和重新调度 Pod。

Off：VPA 从不改变Pod资源。Recommender 而依旧会在VPA对象中生成推荐信息，他们可以被用在演习中。


## VPA的不足
VPA的成熟度还不足 : 更新正在运行的 Pod 资源配置是 VPA 的一项试验性功能，会导致 Pod 的重建和重启，而且有可能被调度到其他的节点上

多个 VPA 同时匹配同一个 Pod 会造成未定义的行为



## 业务Pod发生OOM事件，自动调整资源的limit值

Recommender 通过 watch 机制监听集群中 Pod 驱逐事件。在发生 OOM(out of memory)事件时，Recommender 认为当前容器对 memory 资源实际需求是超出观测到的使用量的，利用下列公式估计容器对 memory 资源实际需求。

方法是将 OOM 事件转换为内存使用样本来建模，将“安全边际”乘数 (“safety margin” multiplier ) 应用于最后一次观察到的使用情况，即选择 OOMMinBumpUp 和 OOMBumpUpRatio 计算后较大的结果，以避免 VPA 推荐值过小，从而造成容器反复 OOM。

```go
// https://github.com/kubernetes/autoscaler/blob/f953f5c8fabbb633bb2e161fddb6e94f747f718a/vertical-pod-autoscaler/pkg/recommender/model/container.go
func (container *ContainerState) RecordOOM(timestamp time.Time, requestedMemory ResourceAmount) error {
    // ...
	// Get max of the request and the recent usage-based memory peak.
	// Omitting oomPeak here to protect against recommendation running too high on subsequent OOMs.
	memoryUsed := ResourceAmountMax(requestedMemory, container.memoryPeak)
	
	// memoryNeeded = max(memoryUsed+ 100MB,memoryUsed*1.2 )
	memoryNeeded := ResourceAmountMax(memoryUsed+MemoryAmountFromBytes(GetAggregationsConfig().OOMMinBumpUp),
		ScaleResource(memoryUsed, GetAggregationsConfig().OOMBumpUpRatio))

	oomMemorySample := ContainerUsageSample{
		MeasureStart: timestamp,
		Usage:        memoryNeeded,
		Resource:     ResourceMemory,
	}
	if !container.addMemorySample(&oomMemorySample, true) {
		return fmt.Errorf("adding OOM sample failed")
	}
	return nil
}
```


监听 OOM 事件

```go
func WatchEvictionEventsWithRetries(kubeClient kube_client.Interface, observer oom.Observer, namespace string) {
	go func() {
		options := metav1.ListOptions{
			FieldSelector: "reason=Evicted",
		}

		watchEvictionEventsOnce := func() {
			watchInterface, err := kubeClient.CoreV1().Events(namespace).Watch(context.TODO(), options)
			if err != nil {
				klog.Errorf("Cannot initialize watching events. Reason %v", err)
				return
			}
			watchEvictionEvents(watchInterface.ResultChan(), observer)
		}
		for {
			watchEvictionEventsOnce()
			// Wait between attempts, retrying too often breaks API server.
			waitTime := wait.Jitter(evictionWatchRetryWait, evictionWatchJitterFactor)
			klog.V(1).Infof("An attempt to watch eviction events finished. Waiting %v before the next one.", waitTime)
			time.Sleep(waitTime)
		}
	}()
}
```



解析 event 
```go
func (o *observer) OnEvent(event *apiv1.Event) {
	klog.V(1).Infof("OOM Observer processing event: %+v", event)
	for _, oomInfo := range parseEvictionEvent(event) {
		// 放入 event
		o.observedOomsChannel <- oomInfo
	}
}

/// 解析驱逐的 event
func parseEvictionEvent(event *apiv1.Event) []OomInfo {
	if event.Reason != "Evicted" ||
		event.InvolvedObject.Kind != "Pod" {
		return []OomInfo{}
	}
	extractArray := func(annotationsKey string) []string {
		str, found := event.Annotations[annotationsKey]
		if !found {
			return []string{}
		}
		return strings.Split(str, ",")
	}
	offendingContainers := extractArray("offending_containers")
	offendingContainersUsage := extractArray("offending_containers_usage")
	starvedResource := extractArray("starved_resource")
	if len(offendingContainers) != len(offendingContainersUsage) ||
		len(offendingContainers) != len(starvedResource) {
		return []OomInfo{}
	}

	result := make([]OomInfo, 0, len(offendingContainers))

	for i, container := range offendingContainers {
		if starvedResource[i] != "memory" {
			continue
		}
		memory, err := resource.ParseQuantity(offendingContainersUsage[i])
		if err != nil {
			klog.Errorf("Cannot parse resource quantity in eviction event %v. Error: %v", offendingContainersUsage[i], err)
			continue
		}
		oomInfo := OomInfo{
			Timestamp: event.CreationTimestamp.Time.UTC(),
			Memory:    model.ResourceAmount(memory.Value()),
			ContainerID: model.ContainerID{
				PodID: model.PodID{
					Namespace: event.InvolvedObject.Namespace,
					PodName:   event.InvolvedObject.Name,
				},
				ContainerName: container,
			},
		}
		result = append(result, oomInfo)
	}
	return result
}

```


## 参考
- https://github.com/kubernetes/autoscaler/tree/vertical-pod-autoscaler-1.3.1/cluster-autoscaler
- [Kubernetes 垂直自动伸缩走向何方](https://mp.weixin.qq.com/s/ykWgx1WJxBFSPidD1To53Q)
- [B站容器云平台VPA技术实践](https://mp.weixin.qq.com/s/LFytnn2m732aOwbHEtc1Mg)
- [vpa Recommender 设计理念](https://juejin.cn/post/7117936807622230053)
- [深入理解 VPA Recommender](https://www.infoq.cn/article/z40lmwmtoyvecq6tpoik)