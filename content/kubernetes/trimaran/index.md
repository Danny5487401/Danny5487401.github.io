---
title: "Trimaran"
date: 2025-03-02T14:13:27+08:00
draft: true
---



为了应对集群节点高负载、负载不均衡等问题，需要动态平衡各个节点之间的资源使用率，因此需要基于节点的相关监控指标，构建集群资源视图，从而为下述两种治理方向奠定实现基础：

- 方向一: 在 Pod 调度阶段，加入优先将 Pod 调度到资源实际使用率低的节点的节点Score插件
- 方向二: 在集群治理阶段，通过实时监控，在观测到节点资源率较高、节点故障、Pod 数量较多等情况时，可以自动干预，迁移节点上的一些 Pod 到利用率低的节点上
解决方式
- 针对方向一，可以通过赋予Kubernetes调度器感知集群实际负载的能力，计算资源分配和实际资源利用之间的差距，优化调度策略。
- 针对方向二，社区给出了Descheduler方案，Descheduler 可以根据一些规则和策略配置来帮助再平衡集群状态，当前项目实现了十余种策略



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



## 参考
- [Trimaran: 基于实际负载的K8s调度插件](https://zhuanlan.zhihu.com/p/595564563)
- [scheduler-plugins框架的LoadVariationRiskBalancing插件](https://wujiuye.com/article/085456ac59254f3592e81f6e3acc8c9f)
- [scheduler-plugins框架的TargetLoadPacking插件](https://wujiuye.com/article/13bed766a9174e27bb2a95afcee5a790)