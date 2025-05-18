---
title: "Descheduler 集群均衡器"
summary: "节点Pod重平衡, 策略包括 LowNodeUtilization 等."
date: 2025-03-11T20:47:47+08:00
---
## 为什么需要集群均衡器

从 kube-scheduler 的角度来看，它通过各种算法计算出最佳节点去运行 Pod 是非常完美的，当出现新的 Pod 进行调度时，调度程序会根据其当时对 Kubernetes 集群的资源描述做出最佳调度决定。
但是 Kubernetes 集群是非常动态的，由于整个集群范围内的变化，比如一个节点为了维护，我们先执行了驱逐操作，这个节点上的所有 Pod 会被驱逐到其他节点去，
但是当我们维护完成后，之前的 Pod 并不会自动回到该节点上来，因为 Pod 一旦被绑定了节点是不会触发重新调度的，由于这些变化，Kubernetes 集群在一段时间内就出现了不均衡的状态，所以需要均衡器来重新平衡集群

- 一些节点过度使用
- 节点添加污点或则labels后,节点上的pod 不不符合要求
- 当新节点被添加到集群

## descheduler 目前支持的策略


|                    策略                    |                                                                              描述                                                                              | 表头 |
| :-----------------------------------------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------: | :--: |
|              RemoveDuplicates              |                    将节点上同类型的Pod进行迁移，确保只有一个Pod与同一节点上运行的ReplicaSet、Replication Controller、StatefulSet或者Job关联                    | 内容 |
|             LowNodeUtilization             |  将 requests 比率较高节点上的Pod进行迁移，该策略主要用于查找未充分利用的节点，并从其他节点驱逐 Pod，以便 kube-scheudler 重新将它们调度到未充分利用的节点上。  | 内容 |
|             HighNodeUtilization             |                                                            将 requests 比率较低节点上的Pod进行迁移                                                            | 内容 |
|   RemovePodsViolatingInterPodAntiAffinity   |                                                                 将不满足反亲和性的Pod进行迁移                                                                 | 内容 |
|       RemovePodsViolatingNodeAffinity       |                                                            将不满足节点节点亲和性策略的Pod进行迁移                                                            | 内容 |
|        RemovePodsViolatingNodeTaints        |                                                               将不满足节点污点策略的Pod进行迁移                                                               | 内容 |
| RemovePodsViolatingTopologySpreadConstraint | 该策略确保从节点驱逐违反拓扑分布约束的 Pods，具体来说，它试图驱逐将拓扑域平衡到每个约束的 maxSkew 内所需的最小 Pod 数，不过该策略需要 k8s 版本高于1.18才能使用 | 内容 |
|       RemovePodsHavingTooManyRestarts       |                                                                  将重启次数过多的Pod进行迁移                                                                  | 内容 |
|                 PodLifeTime                 |                          该策略用于驱逐比 maxPodLifeTimeSeconds 更旧的 Pods，可以通过 podStatusPhases 来配置哪类状态的 Pods 会被驱逐                          | 内容 |
|              RemoveFailedPods              |                                                                    将运行失败的Pod进行迁移                                                                    | 内容 |



### LowNodeUtilization

该策略主要用于查找未充分利用资源的节点，并从其他节点驱逐 Pod 将它们重新调度到这些未充分利用的节点上。


- targetThresholds: 大于它,被认为需要被驱逐
- thresholds: 小于它,被认为需要调度到这
- numberOfNodes: 针对大集群,需要重调度节点数量大于它,才需要考虑
- evictionLimits: 驱逐限制

注意点: descheduler 默认基于 requests 和 limits,并未基于节点真实负载, 目的是保持与 kube-scheduler 一致 。



支持以下三种资源类型：cpu、memory、pods, 其他(包括GPU).

[v0.33.0 特性](https://github.com/kubernetes-sigs/descheduler/releases/tag/v0.33.0): 可以增加对于节点的监控，基于真实负载进行重调度调整,相关 commit : https://github.com/kubernetes-sigs/descheduler/pull/1533


LowNodeUtilization 初始化

```go
func NewLowNodeUtilization(
	genericArgs runtime.Object, handle frameworktypes.Handle,
) (frameworktypes.Plugin, error) {
	args, ok := genericArgs.(*LowNodeUtilizationArgs)
	if !ok {
		return nil, fmt.Errorf(
			"want args to be of type LowNodeUtilizationArgs, got %T",
			genericArgs,
		)
	}

	// resourceNames holds a list of resources for which the user has
	// provided thresholds for. extendedResourceNames holds those as well
	// as cpu, memory and pods if no prometheus collection is used.
	resourceNames := getResourceNames(args.Thresholds)
	extendedResourceNames := resourceNames

	// if we are using prometheus we need to validate we have everything we
	// need. if we aren't then we need to make sure we are also collecting
	// data for cpu, memory and pods.
	metrics := args.MetricsUtilization
	if metrics != nil && metrics.Source == api.PrometheusMetrics {
		// 相关 prometheus 参数校验 
		if err := validatePrometheusMetricsUtilization(args); err != nil {
			return nil, err
		}
	} else {
		extendedResourceNames = uniquifyResourceNames(
			append(
				resourceNames,
				v1.ResourceCPU,
				v1.ResourceMemory,
				v1.ResourcePods,
			),
		)
	}

	// 驱逐 pod 时过滤 pod
	podFilter, err := podutil.
		NewOptions().
		WithFilter(handle.Evictor().Filter).
		BuildFilterFunc()
	if err != nil {
		return nil, fmt.Errorf("error initializing pod filter function: %v", err)
	}

	// this plugins supports different ways of collecting usage data. each
	// different way provides its own "usageClient". here we make sure we
	// have the correct one or an error is triggered. XXX MetricsServer is
	// deprecated, removed once dropped.
	var usageClient usageClient = newRequestedUsageClient(
		extendedResourceNames, handle.GetPodsAssignedToNodeFunc(),
	)
	if metrics != nil {
		// metrics 来源
		usageClient, err = usageClientForMetrics(args, handle, extendedResourceNames)
		if err != nil {
			return nil, err
		}
	}

	return &LowNodeUtilization{
		handle:                handle,
		args:                  args,
		underCriteria:         thresholdsToKeysAndValues(args.Thresholds),
		overCriteria:          thresholdsToKeysAndValues(args.TargetThresholds),
		resourceNames:         resourceNames,
		extendedResourceNames: extendedResourceNames,
		podFilter:             podFilter,
		usageClient:           usageClient,
	}, nil
}
```



```go
// https://github.com/kubernetes-sigs/descheduler/blob/98e6ed65874eb223ba1f6861df87eb9a574e3f2c/pkg/framework/plugins/nodeutilization/lownodeutilization.go

// 平衡
func (l *LowNodeUtilization) Balance(ctx context.Context, nodes []*v1.Node) *frameworktypes.Status {
	// 这里用 prometheus 作为案例: 同步节点资源利用率及pod数量
	if err := l.usageClient.sync(ctx, nodes); err != nil {
		return &frameworktypes.Status{
			Err: fmt.Errorf("error getting node usage: %v", err),
		}
	}

	// starts by taking a snapshot ofthe nodes usage. we will use this
	// snapshot to assess the nodes usage and classify them as
	// underutilized or overutilized.
	nodesMap, nodesUsageMap, podListMap := getNodeUsageSnapshot(nodes, l.usageClient)
	capacities := referencedResourceListForNodesCapacity(nodes)

	// usage, by default, is exposed in absolute values. we need to normalize
	// them (convert them to percentages) to be able to compare them with the
	// user provided thresholds. thresholds are already provided in percentage
	// in the <0; 100> interval.
	var usage map[string]api.ResourceThresholds
	var thresholds map[string][]api.ResourceThresholds
	if l.args.UseDeviationThresholds {
            // 浮动的防水剂
		)
	} else {
		// 静态树枝
		usage, thresholds = assessNodesUsagesAndStaticThresholds(
			nodesUsageMap,
			capacities,
			l.args.Thresholds,
			l.args.TargetThresholds,
		)
	}

	// classify nodes in under and over utilized. we will later try to move
	// pods from the overutilized nodes to the underutilized ones.
	nodeGroups := classifier.Classify(
		usage, thresholds,
		// underutilization criteria processing. nodes that are
		// underutilized but aren't schedulable are ignored.
		func(nodeName string, usage, threshold api.ResourceThresholds) bool {
			// 过滤不可调度的
			if nodeutil.IsNodeUnschedulable(nodesMap[nodeName]) {
				klog.V(2).InfoS(
					"Node is unschedulable, thus not considered as underutilized",
					"node", klog.KObj(nodesMap[nodeName]),
				)
				return false
			}
			return isNodeBelowThreshold(usage, threshold)
		},
		// overutilization criteria evaluation.
		func(nodeName string, usage, threshold api.ResourceThresholds) bool {
			return isNodeAboveThreshold(usage, threshold)
		},
	)

	// the nodeutilization package was designed to work with NodeInfo
	// structs. these structs holds information about how utilized a node
	// is. we need to go through the result of the classification and turn
	// it into NodeInfo structs.
	nodeInfos := make([][]NodeInfo, 2)
	categories := []string{"underutilized", "overutilized"}
	classifiedNodes := map[string]bool{}
	for i := range nodeGroups {
		for nodeName := range nodeGroups[i] {
			classifiedNodes[nodeName] = true

			klog.InfoS(
				"Node has been classified",
				"category", categories[i],
				"node", klog.KObj(nodesMap[nodeName]),
				"usage", nodesUsageMap[nodeName],
				"usagePercentage", normalizer.Round(usage[nodeName]),
			)

			nodeInfos[i] = append(nodeInfos[i], NodeInfo{
				NodeUsage: NodeUsage{
					node:    nodesMap[nodeName],
					usage:   nodesUsageMap[nodeName],
					allPods: podListMap[nodeName],
				},
				available: capNodeCapacitiesToThreshold(
					nodesMap[nodeName],
					thresholds[nodeName][1],
					l.extendedResourceNames,
				),
			})
		}
	}

	// log nodes that are appropriately utilized.
	for nodeName := range nodesMap {
		if !classifiedNodes[nodeName] {
			klog.InfoS(
				"Node is appropriately utilized",
				"node", klog.KObj(nodesMap[nodeName]),
				"usage", nodesUsageMap[nodeName],
				"usagePercentage", normalizer.Round(usage[nodeName]),
			)
		}
	}

	lowNodes, highNodes := nodeInfos[0], nodeInfos[1]

	// log messages for nodes with low and high utilization
	klog.V(1).InfoS("Criteria for a node under utilization", l.underCriteria...)
	klog.V(1).InfoS("Number of underutilized nodes", "totalNumber", len(lowNodes))
	klog.V(1).InfoS("Criteria for a node above target utilization", l.overCriteria...)
	klog.V(1).InfoS("Number of overutilized nodes", "totalNumber", len(highNodes))

    // 校验逻辑 

	// this is a stop condition for the eviction process. we stop as soon
	// as the node usage drops below the threshold.
	continueEvictionCond := func(nodeInfo NodeInfo, totalAvailableUsage api.ReferencedResourceList) bool {
		if !isNodeAboveTargetUtilization(nodeInfo.NodeUsage, nodeInfo.available) {
			return false
		}
		for name := range totalAvailableUsage {
			if totalAvailableUsage[name].CmpInt64(0) < 1 {
				return false
			}
		}

		return true
	}

	// sort the nodes by the usage in descending order
	sortNodesByUsage(highNodes, false)

	var nodeLimit *uint
	if l.args.EvictionLimits != nil {
		nodeLimit = l.args.EvictionLimits.Node
	}

	// 驱逐 pod 
	evictPodsFromSourceNodes(
		ctx,
		l.args.EvictableNamespaces,
		highNodes,
		lowNodes,
		l.handle.Evictor(),
		evictions.EvictOptions{StrategyName: LowNodeUtilizationPluginName},
		l.podFilter,
		l.extendedResourceNames,
		continueEvictionCond,
		l.usageClient,
		nodeLimit,
	)

	return nil
}

```


## 参考

- https://github.com/kubernetes-sigs/descheduler
- [Kubernetes 集群均衡器 Descheduler](https://www.qikqiak.com/post/k8s-cluster-balancer/)
- [deschedule-节点Pod重平衡](https://isekiro.com/kubernetes%E5%BA%94%E7%94%A8-deschedule%E9%87%8D%E5%B9%B3%E8%A1%A1/)
- [Koordinator Descheduler与Kubernetes Descheduler的对比说明](https://help.aliyun.com/zh/ack/ack-managed-and-ack-dedicated/user-guide/koordinator-descheduler-and-kubernetes-descheduler)