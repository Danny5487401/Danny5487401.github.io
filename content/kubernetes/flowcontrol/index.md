---
title: "kube-apiserver API Priority and Fairness 优先级和公平性 "
date: 2024-11-18T10:32:16+08:00
summary: "kube-apiserver Flowcontrol 流量控制及 API Priority and Fairness 实现原理"
categories:
  - kubernetes
tags:
  - kube-apiserver
  - k8s
---


对于集群管理员来说，控制 Kubernetes API 服务器在过载情况下的行为是一项关键任务。 kube-apiserver 有一些控件（例如：命令行标志 --max-requests-inflight 和 --max-mutating-requests-inflight）， 可以限制将要接受的未处理的请求，从而防止过量请求入站，潜在导致 API 服务器崩溃。 但是这些标志不足以保证在高流量期间，最重要的请求仍能被服务器接受。

API 优先级和公平性（APF）是一种替代方案，可提升上述最大并发限制。 APF 以更细粒度的方式对请求进行分类和隔离。 它还引入了空间有限的排队机制，因此在非常短暂的突发情况下，API 服务器不会拒绝任何请求。 通过使用公平排队技术从队列中分发请求，这样， 一个行为不佳的控制器就不会饿死其他控制器 （即使优先级相同）


以下基于版本 release-1.27

```go
// staging/src/k8s.io/apiserver/pkg/server/options/recommended.go
func (o *RecommendedOptions) ApplyTo(config *server.RecommendedConfig) error {
    // ..
	// APIPriorityAndFairness判断是否开启
	if feature.DefaultFeatureGate.Enabled(features.APIPriorityAndFairness) {
		if config.ClientConfig != nil {
			if config.MaxRequestsInFlight+config.MaxMutatingRequestsInFlight <= 0 {
				return fmt.Errorf("invalid configuration: MaxRequestsInFlight=%d and MaxMutatingRequestsInFlight=%d; they must add up to something positive", config.MaxRequestsInFlight, config.MaxMutatingRequestsInFlight)

			}
			config.FlowControl = utilflowcontrol.New(
				config.SharedInformerFactory,
				kubernetes.NewForConfigOrDie(config.ClientConfig).FlowcontrolV1beta3(), // 1.27 是V1beta3版本,1.29 会是stable v1 
				config.MaxRequestsInFlight+config.MaxMutatingRequestsInFlight, // 总并发数为 --max-requests-inflight 和 --max-mutating-requests-inflight 两个配置值之和
				config.RequestTimeout/4,
			)
		} else {
			klog.Warningf("Neither kubeconfig is provided nor service-account is mounted, so APIPriorityAndFairness will be disabled")
		}
	}
	return nil
}
```
```go
// staging/src/k8s.io/apiserver/pkg/server/config.go
func DefaultBuildHandlerChain(apiHandler http.Handler, c *Config) http.Handler {
	handler := filterlatency.TrackCompleted(apiHandler)
    // ..

	if c.FlowControl != nil { 
		workEstimatorCfg := flowcontrolrequest.DefaultWorkEstimatorConfig()
		requestWorkEstimator := flowcontrolrequest.NewWorkEstimator(
			c.StorageObjectCountTracker.Get, c.FlowControl.GetInterestedWatchCount, workEstimatorCfg, c.FlowControl.GetMaxSeats)
		handler = filterlatency.TrackCompleted(handler)
		handler = genericfilters.WithPriorityAndFairness(handler, c.LongRunningFunc, c.FlowControl, requestWorkEstimator)
		handler = filterlatency.TrackStarted(handler, c.TracerProvider, "priorityandfairness")
	} else {
		// 旧版本
		handler = genericfilters.WithMaxInFlightLimit(handler, c.MaxRequestsInFlight, c.MaxMutatingRequestsInFlight, c.LongRunningFunc)
	}
}
```


## 传统限流方法的缺点

比如突然有一个人发起无数请求，这些请求一个人就可以将apiserver打死，然后它阻塞了其他的所有的请求。因为是一个共享集群，这个共享集群里面有无数的用户，然后无数的组件，如果有一个组件出现了问题，比如他发了1w个请求到apiserver，这些请求就将apiserver堵死了，请求请求只能在后面排队


## API Priority and Fairness
{{<figure src="./featured.png#center" width=800px >}}

APF 的核心：

- 多等级：它将整个集群分为了不同的限流等级FlowSchema，会把相近用户的请求分到不同等级里面，比如和系统相关，那么优先级可能比较高，普通用户的优先级可能比较低。

- 多队列：对于同一个 FlowSchema，会有多个队列，每个队列单独限流


```shell
(⎈|kind-kind:N/A)➜  ~ kubectl api-resources| head -1;kubectl api-resources |grep flowcontrol.apiserver.k8s.io
NAME                              SHORTNAMES   APIVERSION                             NAMESPACED   KIND
flowschemas                                    flowcontrol.apiserver.k8s.io/v1beta3   false        FlowSchema
prioritylevelconfigurations                    flowcontrol.apiserver.k8s.io/v1beta3   false        PriorityLevelConfiguration

```
APF限流通过两种资源
- PriorityLevelConfigurations 定义隔离类型和可处理的并发预算量，还可以调整排队行为。 
```shell
(⎈|kind-kind:N/A)➜  ~ kg prioritylevelconfigurations
NAME              TYPE      NOMINALCONCURRENCYSHARES   QUEUES   HANDSIZE   QUEUELENGTHLIMIT   AGE
catch-all         Limited   5                          <none>   <none>     <none>             37h
exempt            Exempt    <none>                     <none>   <none>     <none>             37h
global-default    Limited   20                         128      6          50                 37h
leader-election   Limited   10                         16       4          50                 37h
node-high         Limited   40                         64       6          50                 37h
system            Limited   30                         64       6          50                 37h
workload-high     Limited   40                         128      6          50                 37h
workload-low      Limited   100                        128      6          50                 37h
(⎈|kind-kind:N/A)➜  ~ kg prioritylevelconfigurations global-default -o yaml
apiVersion: flowcontrol.apiserver.k8s.io/v1beta3
kind: PriorityLevelConfiguration
metadata:
  name: global-default
spec:
  limited:
    lendablePercent: 50
    limitResponse:
      queuing:
        handSize: 6
        queueLengthLimit: 50
        queues: 128
      type: Queue
    nominalConcurrencyShares: 20
  type: Limited
```
- FlowSchemas用于对每个入站请求进行分类，并与一个 PriorityLevelConfigurations相匹配
```shell
(⎈|kind-kind:N/A)➜  ~ kubectl get  flowschemas
NAME                           PRIORITYLEVEL     MATCHINGPRECEDENCE   DISTINGUISHERMETHOD   AGE   MISSINGPL
exempt                         exempt            1                    <none>                37h   False
probes                         exempt            2                    <none>                37h   False
system-leader-election         leader-election   100                  ByUser                37h   False
endpoint-controller            workload-high     150                  ByUser                37h   False
workload-leader-election       leader-election   200                  ByUser                37h   False
system-node-high               node-high         400                  ByUser                37h   False
system-nodes                   system            500                  ByUser                37h   False
kube-controller-manager        workload-high     800                  ByNamespace           37h   False
kube-scheduler                 workload-high     800                  ByNamespace           37h   False
kube-system-service-accounts   workload-high     900                  ByNamespace           37h   False
service-accounts               workload-low      9000                 ByUser                37h   False
global-default                 global-default    9900                 ByUser                37h   False
catch-all                      catch-all         10000                ByUser                37h   False
```

每个flowschemas都有其对应的优先级，所以任何请求过来之后它都会从上到下去匹配，优先级数字越小的越优先匹配（第三列），它就通过优先级来决定它的限流策略是什么


## 处理流程

```go
func (cfgCtlr *configController) Handle(ctx context.Context, requestDigest RequestDigest,
	noteFn func(fs *flowcontrol.FlowSchema, pl *flowcontrol.PriorityLevelConfiguration, flowDistinguisher string),
	workEstimator func() fcrequest.WorkEstimate,
	queueNoteFn fq.QueueNoteFn,
	execFn func()) {
	// 对请求进行分类
	fs, pl, isExempt, req, startWaitingTime := cfgCtlr.startRequest(ctx, requestDigest, noteFn, workEstimator, queueNoteFn)
    // ..
	// 执行
	idle = req.Finish(func() {
        // ...
		executed = true
        // ...
		execFn()
	})
    /// ...
}

```


```go
// staging/src/k8s.io/apiserver/pkg/util/flowcontrol/apf_controller.go
func (cfgCtlr *configController) startRequest(ctx context.Context, rd RequestDigest,
	noteFn func(fs *flowcontrol.FlowSchema, pl *flowcontrol.PriorityLevelConfiguration, flowDistinguisher string),
	workEstimator func() fcrequest.WorkEstimate,
	queueNoteFn fq.QueueNoteFn) (fs *flowcontrol.FlowSchema, pl *flowcontrol.PriorityLevelConfiguration, isExempt bool, req fq.Request, startWaitingTime time.Time) {
	klog.V(7).Infof("startRequest(%#+v)", rd)
	cfgCtlr.lock.RLock()
	defer cfgCtlr.lock.RUnlock()
	var selectedFlowSchema, catchAllFlowSchema *flowcontrol.FlowSchema
	// 可以根据请求的主体 (User, Group, ServiceAccount)、动作 (Get, List, Create, Delete …)、资源类型 (pod, deployment …)、namespace、url 对请求进行分类
	for _, fs := range cfgCtlr.flowSchemas {
		/*
		1. 匹配请求主体 subject
		2. 对资源的请求，匹配 ResourceRules 中任意一条规则
		3. 对非资源的请求， 匹配 NonResourceRules 中任意一条规则
		 */
		if matchesFlowSchema(rd, fs) {
			selectedFlowSchema = fs
			break
		}
		if fs.Name == flowcontrol.FlowSchemaNameCatchAll {
			catchAllFlowSchema = fs
		}
	}
    // ...
	plName := selectedFlowSchema.Spec.PriorityLevelConfiguration.Name
	plState := cfgCtlr.priorityLevelStates[plName]
	if plState.pl.Spec.Type == flowcontrol.PriorityLevelEnablementExempt {
		noteFn(selectedFlowSchema, plState.pl, "")
		klog.V(7).Infof("startRequest(%#+v) => fsName=%q, distMethod=%#+v, plName=%q, immediate", rd, selectedFlowSchema.Name, selectedFlowSchema.Spec.DistinguisherMethod, plName)
		return selectedFlowSchema, plState.pl, true, immediateRequest{}, time.Time{}
	}
	var numQueues int32
	if plState.pl.Spec.Limited.LimitResponse.Type == flowcontrol.LimitResponseTypeQueue {
		numQueues = plState.pl.Spec.Limited.LimitResponse.Queuing.Queues
	}
	var flowDistinguisher string
	var hashValue uint64
	if numQueues > 1 {
        // APF 利用 FS 的 name 和请求的 userName 或 namespace 计算一个 hashFlowID 标识 Flow
		flowDistinguisher = computeFlowDistinguisher(rd, selectedFlowSchema.Spec.DistinguisherMethod)
		hashValue = hashFlowID(selectedFlowSchema.Name, flowDistinguisher) 
	}

	noteFn(selectedFlowSchema, plState.pl, flowDistinguisher)
	workEstimate := workEstimator()

	startWaitingTime = cfgCtlr.clock.Now()
	
	// 使用混洗分片 shuffle-shards 处理请求
	req, idle := plState.queues.StartRequest(ctx, &workEstimate, hashValue, flowDistinguisher, selectedFlowSchema.Name, rd.RequestInfo, rd.User, queueNoteFn)
	if idle {
		cfgCtlr.maybeReapReadLocked(plName, plState)
	}
	return selectedFlowSchema, plState.pl, false, req, startWaitingTime
}

```

```go
// staging/src/k8s.io/apiserver/pkg/util/flowcontrol/fairqueuing/queueset/queueset.go
func (qs *queueSet) StartRequest(ctx context.Context, workEstimate *fqrequest.WorkEstimate, hashValue uint64, flowDistinguisher, fsName string, descr1, descr2 interface{}, queueNoteFn fq.QueueNoteFn) (fq.Request, bool) {
	qs.lockAndSyncTime(ctx)
	defer qs.lock.Unlock()
	var req *request

	// ========================================================================
	// Step 0:
	// Apply only concurrency limit, if zero queues desired
	if qs.qCfg.DesiredNumQueues < 1 {
		if !qs.canAccommodateSeatsLocked(workEstimate.MaxSeats()) {
			klog.V(5).Infof("QS(%s): rejecting request %q %#+v %#+v because %d seats are asked for, %d seats are in use (%d are executing) and the limit is %d",
				qs.qCfg.Name, fsName, descr1, descr2, workEstimate, qs.totSeatsInUse, qs.totRequestsExecuting, qs.dCfg.ConcurrencyLimit)
			qs.totRequestsRejected++
			metrics.AddReject(ctx, qs.qCfg.Name, fsName, "concurrency-limit")
			return nil, qs.isIdleLocked()
		}
		req = qs.dispatchSansQueueLocked(ctx, workEstimate, flowDistinguisher, fsName, descr1, descr2)
		return req, false
	}

	// ========================================================================
	// Step 1:
	// 1) Start with shuffle sharding, to pick a queue.
	// 2) Reject old requests that have been waiting too long
	// 3) Reject current request if there is not enough concurrency shares and
	// we are at max queue length
	// 4) If not rejected, create a request and enqueue
	req = qs.timeoutOldRequestsAndRejectOrEnqueueLocked(ctx, workEstimate, hashValue, flowDistinguisher, fsName, descr1, descr2, queueNoteFn)
	// req == nil means that the request was rejected - no remaining
	// concurrency shares and at max queue length already
	if req == nil {
		klog.V(5).Infof("QS(%s): rejecting request %q %#+v %#+v due to queue full", qs.qCfg.Name, fsName, descr1, descr2)
        // ..
		return nil, qs.isIdleLocked()
	}

	// ========================================================================
	// Step 2:
	// The next step is to invoke the method that dequeues as much
	// as possible.
	// This method runs a loop, as long as there are non-empty
	// queues and the number currently executing is less than the
	// assured concurrency value.  The body of the loop uses the
	// fair queuing technique to pick a queue and dispatch a
	// request from that queue.
	qs.dispatchAsMuchAsPossibleLocked()

	return req, false
}

```




## 参考

- [官方文档: API 优先级和公平性](https://kubernetes.io/zh-cn/docs/concepts/cluster-administration/flow-control/)
- [Kubernetes APIServer 限流策略](https://blog.csdn.net/qq_34556414/article/details/125828537)
- [源码分析API 优先级和公平性](https://blog.csdn.net/qq_21127151/article/details/129997719)
