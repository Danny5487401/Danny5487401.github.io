---
title: "Trimaran"
date: 2025-03-02T14:13:27+08:00
summary: Trimaran 算法 LoadVariationRiskBalancing,TargetLoadPacking,
categories:
  - kubernetes
  - scheduler
tags:
  - k8s
  - 源码
---



为了应对集群节点高负载、负载不均衡等问题，需要动态平衡各个节点之间的资源使用率，因此需要基于节点的相关监控指标，构建集群资源视图，从而为下述两种治理方向奠定实现基础：

- 方向一: 在 Pod 调度阶段，加入优先将 Pod 调度到资源实际使用率低的节点的节点Score插件
- 方向二: 在集群治理阶段，通过实时监控，在观测到节点资源率较高、节点故障、Pod 数量较多等情况时，可以自动干预，迁移节点上的一些 Pod 到利用率低的节点上
解决方式
- 针对方向一，可以通过赋予Kubernetes调度器感知集群实际负载的能力，计算资源分配和实际资源利用之间的差距，优化调度策略。
- 针对方向二，社区给出了Descheduler方案，Descheduler 可以根据一些规则和策略配置来帮助再平衡集群状态，当前项目实现了十余种策略


## 指标获取
通过 load-watcher,可以是service部署,或则直接作为客户端库嵌入.

```go
// https://github.com/kubernetes-sigs/scheduler-plugins/blob/59a8b1ca68d0256d10239a588d69ab0ba28d4076/pkg/trimaran/collector.go
func NewCollector(logger klog.Logger, trimaranSpec *pluginConfig.TrimaranSpec) (*Collector, error) {
	if err := checkSpecs(trimaranSpec); err != nil {
		return nil, err
	}
	logger.V(4).Info("Using TrimaranSpec", "type", trimaranSpec.MetricProvider.Type,
		"address", trimaranSpec.MetricProvider.Address, "watcher", trimaranSpec.WatcherAddress)

	var client loadwatcherapi.Client
	if trimaranSpec.WatcherAddress != "" {
		// 作为service
		client, _ = loadwatcherapi.NewServiceClient(trimaranSpec.WatcherAddress)
	} else {
		
		// 作为库
		opts := watcher.MetricsProviderOpts{
			Name:               string(trimaranSpec.MetricProvider.Type),
			Address:            trimaranSpec.MetricProvider.Address,
			AuthToken:          trimaranSpec.MetricProvider.Token,
			InsecureSkipVerify: trimaranSpec.MetricProvider.InsecureSkipVerify,
		}
		client, _ = loadwatcherapi.NewLibraryClient(opts)
	}

	collector := &Collector{
		client: client,
	}

	// 更新本地缓存指标
	// populate metrics before returning
	err := collector.updateMetrics(logger)
	if err != nil {
		logger.Error(err, "Unable to populate metrics initially")
	}
	// start periodic updates
	go func() {
		metricsUpdaterTicker := time.NewTicker(time.Second * metricsUpdateIntervalSeconds)
		for range metricsUpdaterTicker.C {
			err = collector.updateMetrics(logger)
			if err != nil {
				logger.Error(err, "Unable to update metrics")
			}
		}
	}()
	return collector, nil
}

```

作为库的方式
```go
func NewLibraryClient(opts watcher.MetricsProviderOpts) (Client, error) {
	var err error
	client := libraryClient{}
	switch opts.Name {
	case watcher.PromClientName: // promethues 客户端的方式
		client.fetcherClient, err = metricsprovider.NewPromClient(opts)
	case watcher.SignalFxClientName:
		client.fetcherClient, err = metricsprovider.NewSignalFxClient(opts)
	default:
		client.fetcherClient, err = metricsprovider.NewMetricsServerClient()
	}
	if err != nil {
		return client, err
	}
	client.watcher = watcher.NewWatcher(client.fetcherClient)
	// 开始抓取指标
	client.watcher.StartWatching()
	return client, nil
}

```


## LoadVariationRiskBalancing
LoadVariationRiskBalancing 插件的算法是利用节点负载在某段时间内（滑动窗口）的平均值（M）和标准差(V)这两个指标，假设集群所有节点的CPU利用率的M+V是0.3(30%)，那么每个节点的cpu利用率的M+V越接近0.3，得分应该越小。

LoadVariationRiskBalancing是分别计算每种资源的得分，再取得分的最小值，例：假设CPU得分0，内存得分10，则节点的最终得分是0。


算法步骤：

1. 获取待调度的Pod 的request的资源，设为r 。
```go
// pkg/trimaran/resourcestats.go

// GetResourceRequested : calculate the resource requests of a pod (CPU and Memory)
func GetResourceRequested(pod *v1.Pod) *framework.Resource {
	return GetEffectiveResource(pod, func(container *v1.Container) v1.ResourceList {
		return container.Resources.Requests
	})
}

```
2. 获取当前节点所有类型的资源（CPU、Memory等）的利用率的百分比（0到1），并根据计算的滑动窗口的平均数（V）和标准差（M），进行打分。
```go
func CreateResourceStats(logger klog.Logger, metrics []watcher.Metric, node *v1.Node, podRequest *framework.Resource,
	resourceName v1.ResourceName, watcherType string) (rs *ResourceStats, isValid bool) {
	// get resource usage statistics
	nodeUtil, nodeStd, metricFound := GetResourceData(metrics, watcherType)
	if !metricFound {
		logger.V(6).Info("Resource usage statistics for node : no valid data", "node", klog.KObj(node))
		return nil, false
	}
	// get resource capacity
	rs = &ResourceStats{}
	allocatableResources := node.Status.Allocatable
	am := allocatableResources[resourceName]

	if resourceName == v1.ResourceCPU {
		rs.Capacity = float64(am.MilliValue())
		rs.Req = float64(podRequest.MilliCPU)
	} else {
		rs.Capacity = float64(am.Value())
		rs.Capacity *= MegaFactor
		rs.Req = float64(podRequest.Memory) * MegaFactor
	}

	// calculate absolute usage statistics
	rs.UsedAvg = nodeUtil * rs.Capacity / 100
	rs.UsedStdev = nodeStd * rs.Capacity / 100

	logger.V(6).Info("Resource usage statistics for node", "node", klog.KObj(node), "resource", resourceName,
		"capacity", rs.Capacity, "required", rs.Req, "usedAvg", rs.UsedAvg, "usedStdev", rs.UsedStdev)
	return rs, true
}
```
3. 计算当前节点对各类资源的得分：Si = M + r + V 
```go
// computeScore : compute score given usage statistics
// - risk = [ average + margin * stDev^{1/sensitivity} ] / 2
// - score = ( 1 - risk ) * maxScore
func computeScore(logger klog.Logger, rs *trimaran.ResourceStats, margin float64, sensitivity float64) float64 {
	if rs.Capacity <= 0 {
		logger.Error(nil, "Invalid resource capacity", "capacity", rs.Capacity)
		return 0
	}

	// make sure values are within bounds
	rs.Req = math.Max(rs.Req, 0)
	rs.UsedAvg = math.Max(math.Min(rs.UsedAvg, rs.Capacity), 0)
	rs.UsedStdev = math.Max(math.Min(rs.UsedStdev, rs.Capacity), 0)

	// calculate average and deviation factors
	// mu-sigma图的mu指的是均值（μ），sigma指标准差（σ）。
	mu, sigma := trimaran.GetMuSigma(rs)

	// apply root power
	if sensitivity >= 0 {
		sigma = math.Pow(sigma, 1/sensitivity)
	}
	// apply multiplier
	sigma *= margin
	sigma = math.Max(math.Min(sigma, 1), 0)

	// evaluate overall risk factor
	risk := (mu + sigma) / 2
	logger.V(6).Info("Evaluating risk factor", "mu", mu, "sigma", sigma, "margin", margin, "sensitivity", sensitivity, "risk", risk)
	return (1. - risk) * float64(framework.MaxNodeScore)
}

```
4. 获取每种类型资源的分数并将其绑定到 [0,1]，意思就是最小值为0，最大值为1，小于最小值取最小值，大于最大值取最大值：Si = min(Si,1.0)
5. 计算当前节点每种资源的优先级得分：Ui = (1-Si) x MaxPriority。
6. 当前节点最终的得分为：U = min(Ui)，意思是cpu、内存的分数，哪个低取哪个：


## TargetLoadPacking

TargetLoadPacking即目标负载调度器，用于控制节点的CPU利用率不超过目标值x%（例如65%），通过打分让所有cpu利用率超过x%的都不被选中。目标负载调度器只支持CPU。

使用此插件结合LoadVariationRiskBalancing插件，可以保证在负载均衡调度的基础上，保证节点不会超负载，确保服务的稳定运行。成本的优化一定是建立在稳定性之上的。

```go
func (pl *TargetLoadPacking) Score(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, nodeName string) (int64, *framework.Status) {
	logger := klog.FromContext(ctx)
	score := framework.MinNodeScore
	nodeInfo, err := pl.handle.SnapshotSharedLister().NodeInfos().Get(nodeName)
	if err != nil {
		return score, framework.NewStatus(framework.Error, fmt.Sprintf("getting node %q from Snapshot: %v", nodeName, err))
	}

	// get node metrics
	metrics, allMetrics := pl.collector.GetNodeMetrics(logger, nodeName)
	if metrics == nil {
		klog.InfoS("Failed to get metrics for node; using minimum score", "nodeName", nodeName)
		// Avoid the node by scoring minimum
		return score, nil
		// TODO(aqadeer): If this happens for a long time, fall back to allocation based packing. This could mean maintaining failure state across cycles if scheduler doesn't provide this state

	}

	// 计算 pod 使用率
	var curPodCPUUsage int64
	for _, container := range pod.Spec.Containers {
		// Pod cpu使用量是优先通过limit取得，不存在才通过request获取,在公司内limit和Pod实际使用率偏差较大
		curPodCPUUsage += PredictUtilisation(&container)
	}
	logger.V(6).Info("Predicted utilization for pod", "podName", pod.Name, "cpuUsage", curPodCPUUsage)
	// 补充runtimeClass 定义的overhead
	if pod.Spec.Overhead != nil {
		curPodCPUUsage += pod.Spec.Overhead.Cpu().MilliValue()
	}
	// 计算当前节点的 cpu 使用率
	var nodeCPUUtilPercent float64
	var cpuMetricFound bool
	for _, metric := range metrics {
		if metric.Type == watcher.CPU {
			if metric.Operator == watcher.Average || metric.Operator == watcher.Latest {
				nodeCPUUtilPercent = metric.Value
				cpuMetricFound = true
			}
		}
	}

	if !cpuMetricFound {
		logger.Error(nil, "Cpu metric not found in node metrics", "nodeName", nodeName, "nodeMetrics", metrics)
		return score, nil
	}
	nodeCPUCapMillis := float64(nodeInfo.Node().Status.Capacity.Cpu().MilliValue())
	nodeCPUUtilMillis := (nodeCPUUtilPercent / 100) * nodeCPUCapMillis

	logger.V(6).Info("Calculating CPU utilization and capacity", "nodeName", nodeName, "cpuUtilMillis", nodeCPUUtilMillis, "cpuCapMillis", nodeCPUCapMillis)

	var missingCPUUtilMillis int64 = 0
	pl.eventHandler.RLock()
	for _, info := range pl.eventHandler.ScheduledPodsCache[nodeName] {
		// If the time stamp of the scheduled pod is outside fetched metrics window, or it is within metrics reporting interval seconds, we predict util.
		// Note that the second condition doesn't guarantee metrics for that pod are not reported yet as the 0 <= t <= 2*metricsAgentReportingIntervalSeconds
		// t = metricsAgentReportingIntervalSeconds is taken as average case and it doesn't hurt us much if we are
		// counting metrics twice in case actual t is less than metricsAgentReportingIntervalSeconds
		if info.Timestamp.Unix() > allMetrics.Window.End || info.Timestamp.Unix() <= allMetrics.Window.End &&
			(allMetrics.Window.End-info.Timestamp.Unix()) < metricsAgentReportingIntervalSeconds {
			for _, container := range info.Pod.Spec.Containers {
				missingCPUUtilMillis += PredictUtilisation(&container)
			}
			missingCPUUtilMillis += info.Pod.Spec.Overhead.Cpu().MilliValue()
			logger.V(6).Info("Missing utilization for pod", "podName", info.Pod.Name, "missingCPUUtilMillis", missingCPUUtilMillis)
		}
	}
	pl.eventHandler.RUnlock()
	logger.V(6).Info("Missing utilization for node", "nodeName", nodeName, "missingCPUUtilMillis", missingCPUUtilMillis)

	var predictedCPUUsage float64
	if nodeCPUCapMillis != 0 { 
		// 如果 Pod 调度在该节点下，计算预期利用率，即 target_cpu = node_cpu + pod_cpu
		predictedCPUUsage = 100 * (nodeCPUUtilMillis + float64(curPodCPUUsage) + float64(missingCPUUtilMillis)) / nodeCPUCapMillis
	}
	if predictedCPUUsage > float64(hostTargetUtilizationPercent) {
		if predictedCPUUsage > 100 {
			// 超过100%,直接返回 MinNodeScore 0
			return score, framework.NewStatus(framework.Success, "")
		}
		penalisedScore := int64(math.Round(float64(hostTargetUtilizationPercent) * (100 - predictedCPUUsage) / (100 - float64(hostTargetUtilizationPercent))))
		logger.V(6).Info("Penalised score for host", "nodeName", nodeName, "penalisedScore", penalisedScore)
		return penalisedScore, framework.NewStatus(framework.Success, "")
	}

	score = int64(math.Round((100-float64(hostTargetUtilizationPercent))*
		predictedCPUUsage/float64(hostTargetUtilizationPercent) + float64(hostTargetUtilizationPercent)))
	logger.V(6).Info("Score for host", "nodeName", nodeName, "score", score)
	return score, framework.NewStatus(framework.Success, "")
}

```

```go
func PredictUtilisation(container *v1.Container) int64 {
	if _, ok := container.Resources.Limits[v1.ResourceCPU]; ok {
		return container.Resources.Limits.Cpu().MilliValue()
	} else if _, ok := container.Resources.Requests[v1.ResourceCPU]; ok {
		return int64(math.Round(float64(container.Resources.Requests.Cpu().MilliValue()) * requestsMultiplier))
	}
	return requestsMilliCores
}

```

计算公式
```
cluster_cpu = 预设理想值
target_cpu = node_cpu + pod_cpu
if target_cpu <= cluster_cpu:
  score = (100 - cluster_cpu)target_cpu/cluster_cpu+ cluster_cpu 
else if cluster_cpu < target_cpu <= 100:
  score = cluster_cpu(100 - target_cpu)/(100 - cluster_cpu)
else:
  score = 0
```



## 参考
- https://github.com/kubernetes-sigs/scheduler-plugins/blob/v0.30.6/pkg/trimaran/README.md
- [哈啰Kubernetes基于水位的自定义调度器落地之路](https://segmentfault.com/a/1190000042066433)
- [装箱问题近似算法](https://cloud.tencent.com/developer/article/2252255)
- [Trimaran: 基于实际负载的K8s调度插件](https://zhuanlan.zhihu.com/p/595564563)
- [scheduler-plugins框架的LoadVariationRiskBalancing插件](https://wujiuye.com/article/085456ac59254f3592e81f6e3acc8c9f)
- [scheduler-plugins框架的TargetLoadPacking插件](https://wujiuye.com/article/13bed766a9174e27bb2a95afcee5a790)