---
title: "Scheduler 及调度框架（scheduling framework）"
date: 2024-09-15T14:26:42+08:00
summary: "scheduler是kubernetes的调度器，主要任务是把定义的pod分配到集群的节点上。 基于源码 release-1.27"
categories:
  - kubernetes
authors:
  - Danny
tags:
  - k8s
  - scheduler
  - 源码
---


## 调度框架 Framework

Kubernetes v1.15版本中引入了可插拔架构的调度框架，使得定制调度器这个任务变得更加的容易。

调度框架（Schedule Framework）定义了一组扩展点，用户可以实现扩展点定义的接口来定义自己的调度逻辑（我们称之为扩展），并将扩展注册到扩展点上，调度框架在执行调度工作流时，遇到对应的扩展点时，将调用用户注册的扩展。
调度框架在预留扩展点时，都是有特定的目的，有些扩展点上的扩展可以改变调度程序的决策方法，有些扩展点上的扩展只是发送一个通知。

### 扩展点（Extension Points）

{{<figure src="./scheduler_framework_extensions.png#center" width=800px >}}
```go
type Framework interface {
    // ...

	// 扩展用于对 Pod 的待调度队列进行排序，以决定先调度哪个 Pod
	QueueSortFunc() LessFunc
	
	// 用于对 Pod 的信息进行预处理，或者检查一些集群或 Pod 必须满足的前提条件，如果  pre-filter  返回了 error，则调度过程终止
	RunPreFilterPlugins(ctx context.Context, state *CycleState, pod *v1.Pod) (*PreFilterResult, *Status)
	
	// 是一个通知类型的扩展点，调用该扩展的参数是  filter  阶段结束后被筛选为可选节点的节点列表，可以在扩展中使用这些信息更新内部状态，或者产生日志或 metrics 信息
	RunPostFilterPlugins(ctx context.Context, state *CycleState, pod *v1.Pod, filteredNodeStatusMap NodeToStatusMap) (*PostFilterResult, *Status)

	// 用于在 Pod 绑定之前执行某些逻辑。例如，pre-bind 扩展可以将一个基于网络的数据卷挂载到节点上，以便 Pod 可以使用
	RunPreBindPlugins(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string) *Status
    // 通知性质的扩展
	RunPostBindPlugins(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string)
	
	// 一个通知性质的扩展点，有状态的插件可以使用该扩展点来获得节点上为 Pod 预留的资源，该事件发生在调度器将 Pod 绑定到节点之前，目的是避免调度器在等待 Pod 与节点绑定的过程中调度新的 Pod 到节点上时，发生实际使用资源超出可用资源的情况。（因为绑定 Pod 到节点上是异步发生的）。
	RunReservePluginsReserve(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string) *Status
    // 是一个通知性质的扩展，如果为 Pod 预留了资源，Pod 又在被绑定过程中被拒绝绑定，则 unreserve 扩展将被调用。Unreserve 扩展应该释放已经为 Pod 预留的节点上的计算资源。
	RunReservePluginsUnreserve(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string)
	
	RunPermitPlugins(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string) *Status

	WaitOnPermit(ctx context.Context, pod *v1.Pod) *Status
	
	RunBindPlugins(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string) *Status

    // ..
}
```


## 插件分类

根据是否维护在 k8s 代码仓库本身，分为两类。

### 默认插件 in-tree plugins

```go
// https://github.com/kubernetes/kubernetes/blob/231849a90853363900391aaa3f406867c8421489/pkg/scheduler/framework/plugins/registry.go
func NewInTreeRegistry() runtime.Registry {
    // ...
	registry := runtime.Registry{
		dynamicresources.Name:                runtime.FactoryAdapter(fts, dynamicresources.New),
		selectorspread.Name:                  selectorspread.New,
		imagelocality.Name:                   imagelocality.New,
		tainttoleration.Name:                 tainttoleration.New,
		nodename.Name:                        nodename.New,
		nodeports.Name:                       nodeports.New,
		nodeaffinity.Name:                    nodeaffinity.New,
		podtopologyspread.Name:               runtime.FactoryAdapter(fts, podtopologyspread.New),
		nodeunschedulable.Name:               nodeunschedulable.New,
		noderesources.Name:                   runtime.FactoryAdapter(fts, noderesources.NewFit),
		noderesources.BalancedAllocationName: runtime.FactoryAdapter(fts, noderesources.NewBalancedAllocation),
		volumebinding.Name:                   runtime.FactoryAdapter(fts, volumebinding.New),
		volumerestrictions.Name:              runtime.FactoryAdapter(fts, volumerestrictions.New),
		volumezone.Name:                      volumezone.New,
		nodevolumelimits.CSIName:             runtime.FactoryAdapter(fts, nodevolumelimits.NewCSI),
		nodevolumelimits.EBSName:             runtime.FactoryAdapter(fts, nodevolumelimits.NewEBS),
		nodevolumelimits.GCEPDName:           runtime.FactoryAdapter(fts, nodevolumelimits.NewGCEPD),
		nodevolumelimits.AzureDiskName:       runtime.FactoryAdapter(fts, nodevolumelimits.NewAzureDisk),
		nodevolumelimits.CinderName:          runtime.FactoryAdapter(fts, nodevolumelimits.NewCinder),
		interpodaffinity.Name:                interpodaffinity.New,
		queuesort.Name:                       queuesort.New,
		defaultbinder.Name:                   defaultbinder.New,
		defaultpreemption.Name:               runtime.FactoryAdapter(fts, defaultpreemption.New),
		schedulinggates.Name:                 runtime.FactoryAdapter(fts, schedulinggates.New),
	}

	return registry
}
```

- node selectors 和 node affinity 用到了 NodeAffinity plugin；
- taint/toleration 用到了 TaintToleration plugin

### 第三方插件 out-of-tree plugins

github.com/kubernetes-sigs/scheduler-plugins。 用户只需要引用这个包，编写自己的调度器插件，然后以普通 pod 方式部署就行.


### 插件注册

```go
// https://github.com/kubernetes/kubernetes/blob/66974670620142271755e165e72fe03ec404dc6e/pkg/scheduler/scheduler.go
func New(client clientset.Interface,
    informerFactory informers.SharedInformerFactory,
    dynInformerFactory dynamicinformer.DynamicSharedInformerFactory,
    recorderFactory profile.RecorderFactory,
    stopCh <-chan struct{},
    opts ...Option) (*Scheduler, error) {
    // ...
    if options.applyDefaultProfile {
		// 默认插件
		var versionedCfg configv1.KubeSchedulerConfiguration
		scheme.Scheme.Default(&versionedCfg)
		cfg := schedulerapi.KubeSchedulerConfiguration{}
		if err := scheme.Scheme.Convert(&versionedCfg, &cfg, nil); err != nil {
			return nil, err
		}
		options.profiles = cfg.Profiles
	}
	// ...
	
}
```

结构体 KubeSchedulerConfiguration
```go
type KubeSchedulerConfiguration struct {
    // ...
	// Profiles是kube-scheduler支持的调度配置，每个KubeSchedulerProfile对应一个独立的调度器，并有一个唯一的名字。
	Profiles []KubeSchedulerProfile `json:"profiles,omitempty"`
	// 调度扩展程序的配置列表 
	Extenders []Extender `json:"extenders,omitempty"`
}

// 随着群集中的工作负载变得越来越多样化(异构)，很自然它们有不同的调度需求。kube-scheduler运行不同的调度框架的插件配置，将其称为Profile，并关联一个调度器名字。通过设置Pod.Spec.SchedulerName可以选择特定配置来调度Pod。如果未指定调度器名字，则采用默认配置进行调度
type KubeSchedulerProfile struct {
	// 调度器名字
	SchedulerName *string `json:"schedulerName,omitempty"`

    // ...

	// 每个扩展点指定使能或禁用的插件集合
	Plugins *Plugins `json:"plugins,omitempty"`

	// PluginConfig是每个插件的一组可选的自定义插件参数
	PluginConfig []PluginConfig `json:"pluginConfig,omitempty"`
}
```


```go
// Plugins包括调度框架的全部扩展点的配置
type Plugins struct {
	// PreEnqueue is a list of plugins that should be invoked before adding pods to the scheduling queue.
	PreEnqueue PluginSet `json:"preEnqueue,omitempty"`

	// QueueSort is a list of plugins that should be invoked when sorting pods in the scheduling queue.
	QueueSort PluginSet `json:"queueSort,omitempty"`

	// PreFilter is a list of plugins that should be invoked at "PreFilter" extension point of the scheduling framework.
	PreFilter PluginSet `json:"preFilter,omitempty"`

	// Filter is a list of plugins that should be invoked when filtering out nodes that cannot run the Pod.
	Filter PluginSet `json:"filter,omitempty"`

	// PostFilter is a list of plugins that are invoked after filtering phase, but only when no feasible nodes were found for the pod.
	PostFilter PluginSet `json:"postFilter,omitempty"`

	// PreScore is a list of plugins that are invoked before scoring.
	PreScore PluginSet `json:"preScore,omitempty"`

	// Score is a list of plugins that should be invoked when ranking nodes that have passed the filtering phase.
	Score PluginSet `json:"score,omitempty"`

	// Reserve is a list of plugins invoked when reserving/unreserving resources
	// after a node is assigned to run the pod.
	Reserve PluginSet `json:"reserve,omitempty"`

	// Permit is a list of plugins that control binding of a Pod. These plugins can prevent or delay binding of a Pod.
	Permit PluginSet `json:"permit,omitempty"`

	// PreBind is a list of plugins that should be invoked before a pod is bound.
	PreBind PluginSet `json:"preBind,omitempty"`

	// Bind is a list of plugins that should be invoked at "Bind" extension point of the scheduling framework.
	// The scheduler call these plugins in order. Scheduler skips the rest of these plugins as soon as one returns success.
	Bind PluginSet `json:"bind,omitempty"`

	// PostBind is a list of plugins that should be invoked after a pod is successfully bound.
	PostBind PluginSet `json:"postBind,omitempty"`


	MultiPoint PluginSet `json:"multiPoint,omitempty"`
}
```




注册默认函数，API对象的设置默认值的函数是通过code-generator自动生成的。

```go
// https://github.com/kubernetes/kubernetes/blob/6b34fafdaf5998039c7e01fa33920a641b216d3e/pkg/scheduler/apis/config/v1/defaults.go
func RegisterDefaults(scheme *runtime.Scheme) error {
    // ...
	scheme.AddTypeDefaultingFunc(&v1.KubeSchedulerConfiguration{}, func(obj interface{}) {
		SetObjectDefaults_KubeSchedulerConfiguration(obj.(*v1.KubeSchedulerConfiguration))
	})
    // ...
	return nil
}



func SetObjectDefaults_KubeSchedulerConfiguration(in *v1.KubeSchedulerConfiguration) {
	SetDefaults_KubeSchedulerConfiguration(in)
}
```

```go
// SetDefaults_KubeSchedulerConfiguration sets additional defaults
func SetDefaults_KubeSchedulerConfiguration(obj *configv1.KubeSchedulerConfiguration) {
    // ...

	if len(obj.Profiles) == 0 {
		obj.Profiles = append(obj.Profiles, configv1.KubeSchedulerProfile{})
	}
	// 使用默认default-scheduler
	if len(obj.Profiles) == 1 && obj.Profiles[0].SchedulerName == nil {
		obj.Profiles[0].SchedulerName = pointer.String(v1.DefaultSchedulerName)
	}

	// Add the default set of plugins and apply the configuration.
	for i := range obj.Profiles {
		prof := &obj.Profiles[i]
		setDefaults_KubeSchedulerProfile(logger, prof)
	}


    // ..
}
```

```go
func setDefaults_KubeSchedulerProfile(logger klog.Logger, prof *configv1.KubeSchedulerProfile) {
	// 设置默认插件
	prof.Plugins = mergePlugins(logger, getDefaultPlugins(), prof.Plugins)
	// Set default plugin configs.
	scheme := GetPluginArgConversionScheme()
	existingConfigs := sets.NewString()
	for j := range prof.PluginConfig {
		existingConfigs.Insert(prof.PluginConfig[j].Name)
		args := prof.PluginConfig[j].Args.Object
		if _, isUnknown := args.(*runtime.Unknown); isUnknown {
			continue
		}
		scheme.Default(args)
	}

	// Append default configs for plugins that didn't have one explicitly set.
	for _, name := range pluginsNames(prof.Plugins) {
		if existingConfigs.Has(name) {
			continue
		}
		gvk := configv1.SchemeGroupVersion.WithKind(name + "Args")
		args, err := scheme.New(gvk)
		if err != nil {
			// This plugin is out-of-tree or doesn't require configuration.
			continue
		}
		scheme.Default(args)
		args.GetObjectKind().SetGroupVersionKind(gvk)
		prof.PluginConfig = append(prof.PluginConfig, configv1.PluginConfig{
			Name: name,
			Args: runtime.RawExtension{Object: args},
		})
	}
}
```

```go
// getDefaultPlugins returns the default set of plugins.
func getDefaultPlugins() *v1.Plugins {
	plugins := &v1.Plugins{
		MultiPoint: v1.PluginSet{
			Enabled: []v1.Plugin{
				{Name: names.PrioritySort},
				{Name: names.NodeUnschedulable},
				{Name: names.NodeName},
				{Name: names.TaintToleration, Weight: pointer.Int32(3)},
				{Name: names.NodeAffinity, Weight: pointer.Int32(2)},
				{Name: names.NodePorts},
				{Name: names.NodeResourcesFit, Weight: pointer.Int32(1)},
				{Name: names.VolumeRestrictions},
				{Name: names.EBSLimits},
				{Name: names.GCEPDLimits},
				{Name: names.NodeVolumeLimits},
				{Name: names.AzureDiskLimits},
				{Name: names.VolumeBinding},
				{Name: names.VolumeZone},
				{Name: names.PodTopologySpread, Weight: pointer.Int32(2)},
				{Name: names.InterPodAffinity, Weight: pointer.Int32(2)},
				{Name: names.DefaultPreemption},
				{Name: names.NodeResourcesBalancedAllocation, Weight: pointer.Int32(1)},
				{Name: names.ImageLocality, Weight: pointer.Int32(1)},
				{Name: names.DefaultBinder},
			},
		},
	}
	applyFeatureGates(plugins)

	return plugins
}

```


## k8s scheduler

要职责是为新创建的 pod 寻找一个最合适的 node 节点, 然后进行 bind node 绑定, 后面 kubelet 才会监听到并创建真正的 pod.


{{<figure src="./kube-scheduler-caller.png#center" width=800px >}}





### 调度流程

- findNodesThatFitPod：过滤（或称为预选)--> Filters the nodes to find the ones that fit the pod based on the framework  filter plugins and filter extenders.
- prioritizeNodes：打分（或称为优选）--> prioritizeNodes prioritizes the nodes by running the score plugins, which return a score for each node from the call to RunScorePlugins()

过滤阶段会将所有满足 Pod 调度需求的节点选出来。
在打分阶段，调度器会为 Pod 从所有可调度节点中选取一个最合适的节点。


最后，kube-scheduler 会将 Pod 调度到得分最高的节点上。 如果存在多个得分最高的节点，kube-scheduler 会从中随机选取一个



### 调度器性能

考虑一个问题, 当 k8s 的 node 节点特别多时, 这些节点都要参与预先的调度过程么 ?
比如大集群有 2500 个节点, 注册的插件有 10 个, 那么 筛选 Filter 和 打分 Score 过程需要进行 2500 * 10 * 2 = 50000 次计算, 最后选定一个最高分值的节点来绑定 pod. k8s scheduler 考虑到了这样的性能开销, 所以加入了百分比参数控制参与预选的节点数



```go
// https://github.com/kubernetes/kubernetes/blob/3e34da6e2a6d908922ad28bda84cb021d22e2b1e/pkg/scheduler/schedule_one.go
const (
    minFeasibleNodesToFind = 100
    minFeasibleNodesPercentageToFind = 5
)


func (sched *Scheduler) numFeasibleNodesToFind(percentageOfNodesToScore *int32, numAllNodes int32) (numNodes int32) {
	if numAllNodes < minFeasibleNodesToFind {
		//  当集群节点小于 100 时, 集群中的所有节点都参与预选
		return numAllNodes
	}

	// Use profile percentageOfNodesToScore if it's set. Otherwise, use global percentageOfNodesToScore.
	var percentage int32
	if percentageOfNodesToScore != nil {
		percentage = *percentageOfNodesToScore
	} else {
		// k8s scheduler 的 nodes 百分比默认为 0
		percentage = sched.percentageOfNodesToScore
	}

	if percentage == 0 {
		percentage = int32(50) - numAllNodes/125
		if percentage < minFeasibleNodesPercentageToFind {
            // 不能小于 5
			percentage = minFeasibleNodesPercentageToFind
		}
	}

	numNodes = numAllNodes * percentage / 100
	if numNodes < minFeasibleNodesToFind {
		return minFeasibleNodesToFind
	}

	return numNodes
}
```
如果你不指定阈值，Kubernetes 使用线性公式计算出一个比例，在大于 100 节点集群取 50%，在 5000 节点的集群取 10% ，随节点数增加，这个数组不停在减少。这个自动设置的参数的最低值是 5%.

```shell
numAllNodes * (50 - numAllNodes/125) / 100
```


### 初始化

```go
func Setup(ctx context.Context, opts *options.Options, outOfTreeRegistryOptions ...Option) (*schedulerserverconfig.CompletedConfig, *scheduler.Scheduler, error) {
	// 获取默认配置
	if cfg, err := latest.Default(); err != nil {
		return nil, nil, err
	} else {
		opts.ComponentConfig = cfg
	}
    
	// 验证 scheduler 的配置参数
	if errs := opts.Validate(); len(errs) > 0 {
		return nil, nil, utilerrors.NewAggregate(errs)
	}

	c, err := opts.Config(ctx)
	if err != nil {
		return nil, nil, err
	}

	// 配置中填充和调整
	cc := c.Complete()

	outOfTreeRegistry := make(runtime.Registry)
	for _, option := range outOfTreeRegistryOptions {
		if err := option(outOfTreeRegistry); err != nil {
			return nil, nil, err
		}
	}

	recorderFactory := getRecorderFactory(&cc)
	completedProfiles := make([]kubeschedulerconfig.KubeSchedulerProfile, 0)
	// 构建 scheduler 对象
	sched, err := scheduler.New(cc.Client,
		cc.InformerFactory,
		cc.DynInformerFactory,
		recorderFactory,
		ctx.Done(),
		scheduler.WithComponentConfigVersion(cc.ComponentConfig.TypeMeta.APIVersion),
		scheduler.WithKubeConfig(cc.KubeConfig),
		scheduler.WithProfiles(cc.ComponentConfig.Profiles...),
		scheduler.WithPercentageOfNodesToScore(cc.ComponentConfig.PercentageOfNodesToScore),
		scheduler.WithFrameworkOutOfTreeRegistry(outOfTreeRegistry),
		scheduler.WithPodMaxBackoffSeconds(cc.ComponentConfig.PodMaxBackoffSeconds),
		scheduler.WithPodInitialBackoffSeconds(cc.ComponentConfig.PodInitialBackoffSeconds),
		scheduler.WithPodMaxInUnschedulablePodsDuration(cc.PodMaxInUnschedulablePodsDuration),
		scheduler.WithExtenders(cc.ComponentConfig.Extenders...),
		scheduler.WithParallelism(cc.ComponentConfig.Parallelism),
		scheduler.WithBuildFrameworkCapturer(func(profile kubeschedulerconfig.KubeSchedulerProfile) {
			// Profiles are processed during Framework instantiation to set default plugins and configurations. Capturing them for logging
			completedProfiles = append(completedProfiles, profile)
		}),
	)
	if err != nil {
		return nil, nil, err
	}
	if err := options.LogOrWriteConfig(klog.FromContext(ctx), opts.WriteConfigTo, &cc.ComponentConfig, completedProfiles); err != nil {
		return nil, nil, err
	}

	return &cc, sched, nil
}
```


```go
func New(client clientset.Interface,
	informerFactory informers.SharedInformerFactory,
	dynInformerFactory dynamicinformer.DynamicSharedInformerFactory,
	recorderFactory profile.RecorderFactory,
	stopCh <-chan struct{},
	opts ...Option) (*Scheduler, error) {

    // ..

	options := defaultSchedulerOptions
	for _, opt := range opts {
		opt(&options)
	}

	if options.applyDefaultProfile {
		var versionedCfg configv1.KubeSchedulerConfiguration
		scheme.Scheme.Default(&versionedCfg)
		cfg := schedulerapi.KubeSchedulerConfiguration{}
		if err := scheme.Scheme.Convert(&versionedCfg, &cfg, nil); err != nil {
			return nil, err
		}
		options.profiles = cfg.Profiles
	}
    // 构建 registry 对象, 默认集成了一堆的插件
	registry := frameworkplugins.NewInTreeRegistry()
	// 第三方插件
	if err := registry.Merge(options.frameworkOutOfTreeRegistry); err != nil {
		return nil, err
	}
	
	extenders, err := buildExtenders(options.extenders, options.profiles)
	if err != nil {
		return nil, fmt.Errorf("couldn't build extenders: %w", err)
	}

	podLister := informerFactory.Core().V1().Pods().Lister()
	nodeLister := informerFactory.Core().V1().Nodes().Lister()

	snapshot := internalcache.NewEmptySnapshot()
	clusterEventMap := make(map[framework.ClusterEvent]sets.String)

	profiles, err := profile.NewMap(options.profiles, registry, recorderFactory, stopCh,
		frameworkruntime.WithComponentConfigVersion(options.componentConfigVersion),
		frameworkruntime.WithClientSet(client),
		frameworkruntime.WithKubeConfig(options.kubeConfig),
		frameworkruntime.WithInformerFactory(informerFactory),
		frameworkruntime.WithSnapshotSharedLister(snapshot),
		frameworkruntime.WithCaptureProfile(frameworkruntime.CaptureProfile(options.frameworkCapturer)),
		frameworkruntime.WithClusterEventMap(clusterEventMap),
		frameworkruntime.WithClusterEventMap(clusterEventMap),
		frameworkruntime.WithParallelism(int(options.parallelism)),
		frameworkruntime.WithExtenders(extenders),
		frameworkruntime.WithMetricsRecorder(metricsRecorder),
	)
    // ...

	preEnqueuePluginMap := make(map[string][]framework.PreEnqueuePlugin)
	for profileName, profile := range profiles {
		preEnqueuePluginMap[profileName] = profile.PreEnqueuePlugins()
	}
	// 实例化 queue, 该 queue 为 PriorityQueue
	podQueue := internalqueue.NewSchedulingQueue(
		profiles[options.profiles[0].SchedulerName].QueueSortFunc(),
		informerFactory,
		internalqueue.WithPodInitialBackoffDuration(time.Duration(options.podInitialBackoffSeconds)*time.Second),
		internalqueue.WithPodMaxBackoffDuration(time.Duration(options.podMaxBackoffSeconds)*time.Second),
		internalqueue.WithPodLister(podLister),
		internalqueue.WithClusterEventMap(clusterEventMap),
		internalqueue.WithPodMaxInUnschedulablePodsDuration(options.podMaxInUnschedulablePodsDuration),
		internalqueue.WithPreEnqueuePluginMap(preEnqueuePluginMap),
		internalqueue.WithPluginMetricsSamplePercent(pluginMetricsSamplePercent),
		internalqueue.WithMetricsRecorder(*metricsRecorder),
	)

	for _, fwk := range profiles {
		fwk.SetPodNominator(podQueue)
	}

	// 实例化 cache 缓存
	schedulerCache := internalcache.New(durationToExpireAssumedPod, stopEverything)

	// Setup cache debugger.
	debugger := cachedebugger.New(nodeLister, podLister, schedulerCache, podQueue)
	debugger.ListenForSignal(stopEverything)

	// 实例化 scheduler 对象
	sched := &Scheduler{
		Cache:                    schedulerCache,
		client:                   client,
		nodeInfoSnapshot:         snapshot,
		percentageOfNodesToScore: options.percentageOfNodesToScore,
		Extenders:                extenders,
		NextPod:                  internalqueue.MakeNextPodFunc(podQueue),
		StopEverything:           stopEverything,
		SchedulingQueue:          podQueue,
		Profiles:                 profiles,
	}
	sched.applyDefaultHandlers()

	// 在 informer 里注册自定义的事件处理方法
	addAllEventHandlers(sched, informerFactory, dynInformerFactory, unionedGVKs(clusterEventMap))

	return sched, nil
}

func (s *Scheduler) applyDefaultHandlers() {
	// 默认 pod 调度
	s.SchedulePod = s.schedulePod
	// 默认调度失败处理
	s.FailureHandler = s.handleSchedulingFailure
}
```

### 启动

```go
func (sched *Scheduler) Run(ctx context.Context) {
	// 队列相关
	sched.SchedulingQueue.Run()

    // 真正的逻辑
	go wait.UntilWithContext(ctx, sched.scheduleOne, 0)

	<-ctx.Done()
	sched.SchedulingQueue.Close()
}
```

关注的是整个 kubernetes scheduler 调度器只有一个协程处理主调度循环 scheduleOne, 虽然 kubernetes scheduler 可以启动多个实例, 但启动时需要 leaderelection 选举, 只有 leader 才可以处理调度, 其他节点作为 follower 等待 leader 失效. 也就是说整个 k8s 集群调度核心的并发度为 1 个.


### scheduleOne() 核心逻辑:拿出一个 pod 来进行调度

```go
func (sched *Scheduler) scheduleOne(ctx context.Context) {
	// 从 activeQ 中获取需要调度的 pod 数据
	podInfo := sched.NextPod()
	// pod could be nil when schedulerQueue is closed
	if podInfo == nil || podInfo.Pod == nil {
		return
	}
	pod := podInfo.Pod
	// 根据 SchedulerName 获取调度器
	fwk, err := sched.frameworkForPod(pod)
    // 。。
	// 检查 pod 是否需要跳过调度。1 处于正在被删除状态的 pod 跳过本次调度 2 pod 在 AssumedPod 缓存里面，也跳过调度
	if sched.skipPodSchedule(fwk, pod) {
		return
	}
	
	// Synchronously attempt to find a fit for the pod.
	start := time.Now()
	state := framework.NewCycleState()

	// Initialize an empty podsToActivate struct, which will be filled up by plugins or stay empty.
	podsToActivate := framework.NewPodsToActivate()
	state.Write(framework.PodsToActivateKey, podsToActivate)

	schedulingCycleCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 为 pod 选择最优的 node 节点
	scheduleResult, assumedPodInfo, status := sched.schedulingCycle(schedulingCycleCtx, state, fwk, podInfo, start, podsToActivate)
	if !status.IsSuccess() {
		sched.FailureHandler(schedulingCycleCtx, fwk, assumedPodInfo, status, scheduleResult.nominatingInfo, start)
		return
	}

	// bind the pod to its host asynchronously (we can do this b/c of the assumption step above).
	go func() {
        //...
		// apiserver 发起 pod -> node 绑定
		status := sched.bindingCycle(bindingCycleCtx, state, fwk, scheduleResult, assumedPodInfo, start, podsToActivate)
		if !status.IsSuccess() {
			sched.handleBindingCycleError(bindingCycleCtx, state, fwk, assumedPodInfo, start, scheduleResult, status)
		}
	}()
}
```

#### schedulingCycle 调度阶段
```go
func (sched *Scheduler) schedulingCycle(
	ctx context.Context,
	state *framework.CycleState,
	fwk framework.Framework,
	podInfo *framework.QueuedPodInfo,
	start time.Time,
	podsToActivate *framework.PodsToActivate,
) (ScheduleResult, *framework.QueuedPodInfo, *framework.Status) {
	pod := podInfo.Pod
	// 调度pod 
	scheduleResult, err := sched.SchedulePod(ctx, fwk, state, pod)
	if err != nil {
        // ..
	}

    // ...
	assumedPodInfo := podInfo.DeepCopy()
	assumedPod := assumedPodInfo.Pod
	// 告诉缓存，假设他已经绑定
	err = sched.assume(assumedPod, scheduleResult.SuggestedHost)
	if err != nil {
        // ...
	}

	// 预留资源
	if sts := fwk.RunReservePluginsReserve(ctx, state, assumedPod, scheduleResult.SuggestedHost); !sts.IsSuccess() {
        // 。。
	}

	// Run "permit" plugins.
	runPermitStatus := fwk.RunPermitPlugins(ctx, state, assumedPod, scheduleResult.SuggestedHost)
	if !runPermitStatus.IsWait() && !runPermitStatus.IsSuccess() {
        // 。。
	}

	// At the end of a successful scheduling cycle, pop and move up Pods if needed.
	if len(podsToActivate.Map) != 0 {
		sched.SchedulingQueue.Activate(podsToActivate.Map)
		// Clear the entries after activation.
		podsToActivate.Map = make(map[string]*v1.Pod)
	}

	return scheduleResult, assumedPodInfo, nil
}
```

SchedulePod 
```go

func (sched *Scheduler) schedulePod(ctx context.Context, fwk framework.Framework, state *framework.CycleState, pod *v1.Pod) (result ScheduleResult, err error) {
    // ..
	// 过滤出符合要求的预选节点
	feasibleNodes, diagnosis, err := sched.findNodesThatFitPod(ctx, fwk, state, pod)
	if err != nil {
		return result, err
	}
    // 优选:为预选出来的节点进行打分 score
	priorityList, err := prioritizeNodes(ctx, sched.Extenders, fwk, state, pod, feasibleNodes)
	if err != nil {
		return result, err
	}

	// 最后选择最合适的 node 节点
	host, err := selectHost(priorityList)

	return ScheduleResult{
		SuggestedHost:  host,
		EvaluatedNodes: len(feasibleNodes) + len(diagnosis.NodeToStatusMap),
		FeasibleNodes:  len(feasibleNodes),
	}, err
}

```

##### findNodesThatFitPod 预选

```go
func (sched *Scheduler) findNodesThatFitPod(ctx context.Context, fwk framework.Framework, state *framework.CycleState, pod *v1.Pod) ([]*v1.Node, framework.Diagnosis, error) {
    // ..

	// 获取所有的 node 信息
	allNodes, err := sched.nodeInfoSnapshot.NodeInfos().List()
	if err != nil {
		return nil, diagnosis, err
	}
	// 调用 framework 的 PreFilter 集合里的插件
	preRes, s := fwk.RunPreFilterPlugins(ctx, state, pod)
	if !s.IsSuccess() {
        // ..
	}

	// "NominatedNodeName" can potentially be set in a previous scheduling cycle as a result of preemption.
	// This node is likely the only candidate that will fit the pod, and hence we try it first before iterating over all nodes.
	if len(pod.Status.NominatedNodeName) > 0 {
		feasibleNodes, err := sched.evaluateNominatedNode(ctx, pod, fwk, state, diagnosis)
		if err != nil {
			klog.ErrorS(err, "Evaluation failed on nominated node", "pod", klog.KObj(pod), "node", pod.Status.NominatedNodeName)
		}
		// Nominated node passes all the filters, scheduler is good to assign this node to the pod.
		if len(feasibleNodes) != 0 {
			return feasibleNodes, diagnosis, nil
		}
	}

	nodes := allNodes
	if !preRes.AllNodes() {
		// 根据 prefilter 拿到的 node names 获取 node info 对象.
		nodes = make([]*framework.NodeInfo, 0, len(preRes.NodeNames))
		for nodeName := range preRes.NodeNames {

			if nodeInfo, err := sched.nodeInfoSnapshot.Get(nodeName); err == nil {
				nodes = append(nodes, nodeInfo)
			}
		}
	}
	// 运行 framework 的 filter 插件判断 node 是否可以运行新 pod.
	feasibleNodes, err := sched.findNodesThatPassFilters(ctx, fwk, state, pod, diagnosis, nodes)
	// always try to update the sched.nextStartNodeIndex regardless of whether an error has occurred
	// this is helpful to make sure that all the nodes have a chance to be searched
	processedNodes := len(feasibleNodes) + len(diagnosis.NodeToStatusMap)
	sched.nextStartNodeIndex = (sched.nextStartNodeIndex + processedNodes) % len(allNodes)
	if err != nil {
		return nil, diagnosis, err
	}

	// 调用额外的 extender 调度器来进行预选
	feasibleNodesAfterExtender, err := findNodesThatPassExtenders(sched.Extenders, pod, feasibleNodes, diagnosis.NodeToStatusMap)
	if err != nil {
		return nil, diagnosis, err
	}
	if len(feasibleNodesAfterExtender) != len(feasibleNodes) {
		// Extenders filtered out some nodes.
		//
		// Extender doesn't support any kind of requeueing feature like EnqueueExtensions in the scheduling framework.
		// When Extenders reject some Nodes and the pod ends up being unschedulable,
		// we put framework.ExtenderName to pInfo.UnschedulablePlugins.
		// This Pod will be requeued from unschedulable pod pool to activeQ/backoffQ
		// by any kind of cluster events.
		// https://github.com/kubernetes/kubernetes/issues/122019
		if diagnosis.UnschedulablePlugins == nil {
			diagnosis.UnschedulablePlugins = sets.NewString()
		}
		diagnosis.UnschedulablePlugins.Insert(framework.ExtenderName)
	}

	return feasibleNodesAfterExtender, diagnosis, nil
}

```

findNodesThatPassFilters 遍历执行 framework 里 Filter 插件集合的 Filter 方法

为了加快执行效率, 减少预选阶段的时延, framework 内部有个 Parallelizer 并发控制器, 启用 16 个协程并发调用插件的 Filter 方法. 
在大集群下 nodes 节点会很多, 为了避免遍历全量的 nodes 执行 Filter 和后续的插件逻辑, 这里通过 numFeasibleNodesToFind 方法来减少扫描计算的 nodes 数量.
```go
// findNodesThatPassFilters finds the nodes that fit the filter plugins.
func (sched *Scheduler) findNodesThatPassFilters(
	ctx context.Context,
	fwk framework.Framework,
	state *framework.CycleState,
	pod *v1.Pod,
	diagnosis framework.Diagnosis,
	nodes []*framework.NodeInfo) ([]*v1.Node, error) {
	numAllNodes := len(nodes)
	// 计算需要扫描的 nodes 数
	numNodesToFind := sched.numFeasibleNodesToFind(fwk.PercentageOfNodesToScore(), int32(numAllNodes))

	// Create feasible list with enough space to avoid growing it
	// and allow assigning.
	feasibleNodes := make([]*v1.Node, numNodesToFind)

	if !fwk.HasFilterPlugins() {
		for i := range feasibleNodes {
			feasibleNodes[i] = nodes[(sched.nextStartNodeIndex+i)%numAllNodes].Node()
		}
		return feasibleNodes, nil
	}

	// framework 内置并发控制器, 并发 16 个协程去请求插件的 Filter 方法.
	errCh := parallelize.NewErrorChannel()
	var statusesLock sync.Mutex
	var feasibleNodesLen int32
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	checkNode := func(i int) {
		// We check the nodes starting from where we left off in the previous scheduling cycle,
		// this is to make sure all nodes have the same chance of being examined across pods.
		nodeInfo := nodes[(sched.nextStartNodeIndex+i)%numAllNodes]
		status := fwk.RunFilterPluginsWithNominatedPods(ctx, state, pod, nodeInfo)
		if status.Code() == framework.Error {
			errCh.SendErrorWithCancel(status.AsError(), cancel)
			return
		}
		if status.IsSuccess() {
			length := atomic.AddInt32(&feasibleNodesLen, 1)
			if length > numNodesToFind {
				cancel()
				atomic.AddInt32(&feasibleNodesLen, -1)
			} else {
				feasibleNodes[length-1] = nodeInfo.Node()
			}
		} else {
			statusesLock.Lock()
			diagnosis.NodeToStatusMap[nodeInfo.Node().Name] = status
			diagnosis.UnschedulablePlugins.Insert(status.FailedPlugin())
			statusesLock.Unlock()
		}
	}

	beginCheckNode := time.Now()
	statusCode := framework.Success

	// // 并发调用 framework 的 Filter 插件的 Filter 方法.
	fwk.Parallelizer().Until(ctx, numAllNodes, checkNode, metrics.Filter)
	feasibleNodes = feasibleNodes[:feasibleNodesLen]
    
	return feasibleNodes, nil
}
```


##### prioritizeNodes 调度器的优选阶段

```go
func prioritizeNodes(
	ctx context.Context,
	extenders []framework.Extender,
	fwk framework.Framework,
	state *framework.CycleState,
	pod *v1.Pod,
	nodes []*v1.Node,
) ([]framework.NodePluginScores, error) {
	// ..

	//  在 framework 的 PreScore 插件集合里, 遍历执行插件的 PreSocre 方法
	preScoreStatus := fwk.RunPreScorePlugins(ctx, state, pod, nodes)
	if !preScoreStatus.IsSuccess() {
		return nil, preScoreStatus.AsError()
	}

	// 在 framework 的 Score 插件集合里, 遍历执行插件的 Socre 方法
	nodesScores, scoreStatus := fwk.RunScorePlugins(ctx, state, pod, nodes)
	if !scoreStatus.IsSuccess() {
		return nil, scoreStatus.AsError()
	}
	

	if len(extenders) != 0 && nodes != nil {
		// 当额外 extenders 调度器不为空时, 则需要计算分值.
		allNodeExtendersScores := make(map[string]*framework.NodePluginScores, len(nodes))
		var mu sync.Mutex
		var wg sync.WaitGroup
		for i := range extenders {
			if !extenders[i].IsInterested(pod) {
				continue
			}
			wg.Add(1)
			go func(extIndex int) {
				// ...
			}(i)
		}
		// wait for all go routines to finish
		wg.Wait()
		for i := range nodesScores {
			if score, ok := allNodeExtendersScores[nodes[i].Name]; ok {
				nodesScores[i].Scores = append(nodesScores[i].Scores, score.Scores...)
				nodesScores[i].TotalScore += score.TotalScore
			}
		}
	}

    // ..
	return nodesScores, nil
}
```
Score 扩展点分为两个阶段：

- 第一阶段称为“打分”，用于对已通过过滤阶段的节点进行排名。调度程序将为 Score 每个节点调用每个计分插件。
- 第二阶段是“归一化”，用于在调度程序计算节点的最终排名之前修改分数，可以不实现，但是需要保证 Score 插件的输出必须是 [MinNodeScore，MaxNodeScore]（[0-100]）范围内的整数。如果不是，则调度器会报错，你需要实现 NormalizeScore 来保证最后的得分范围。如果不实现 NormalizeScore，则 Score 的输出必须在此范围内。调度程序将根据配置的插件权重合并所有插件的节点分数。
```go
type ScorePlugin interface {
	Plugin
	// Score is called on each filtered node. It must return success and an integer
	// indicating the rank of the node. All scoring plugins must return success or
	// the pod will be rejected.
	Score(ctx context.Context, state *CycleState, p *v1.Pod, nodeName string) (int64, *Status)

	// ScoreExtensions returns a ScoreExtensions interface if it implements one, or nil if does not.
	ScoreExtensions() ScoreExtensions
}
```


##### selectHost 从优选的 nodes 集合里获取分值 score 最高的 node

当相近的两个 node 分值相同时, 则通过随机来选择 node, 目的使 k8s node 的负载更趋于均衡

```go
func selectHost(nodeScores []framework.NodePluginScores) (string, error) {
	if len(nodeScores) == 0 {
		return "", fmt.Errorf("empty priorityList")
	}
	maxScore := nodeScores[0].TotalScore
	selected := nodeScores[0].Name
	cntOfMaxScore := 1
	for _, ns := range nodeScores[1:] {
		if ns.TotalScore > maxScore {
			// 当前的分值更大, 则进行赋值
			maxScore = ns.TotalScore
			selected = ns.Name
			cntOfMaxScore = 1
		} else if ns.TotalScore == maxScore {
			// 当两个 node 的 分值相同时,
			// 使用随机算法来选择当前和上一个 node
			cntOfMaxScore++
			if rand.Intn(cntOfMaxScore) == 0 {
				// Replace the candidate with probability of 1/cntOfMaxScore
				selected = ns.Name
			}
		}
	}
	return selected, nil
}

```



#### bindingCycle 绑定阶段

```go
func (sched *Scheduler) bindingCycle(
	ctx context.Context,
	state *framework.CycleState,
	fwk framework.Framework,
	scheduleResult ScheduleResult,
	assumedPodInfo *framework.QueuedPodInfo,
	start time.Time,
	podsToActivate *framework.PodsToActivate) *framework.Status {

	assumedPod := assumedPodInfo.Pod

	// Run "permit" plugins.
	if status := fwk.WaitOnPermit(ctx, assumedPod); !status.IsSuccess() {
		return status
	}

	// // 执行插件的 prebind 逻辑
	if status := fwk.RunPreBindPlugins(ctx, state, assumedPod, scheduleResult.SuggestedHost); !status.IsSuccess() {
		return status
	}

	// 执行 bind 插件逻辑
	if status := sched.bind(ctx, fwk, assumedPod, scheduleResult.SuggestedHost, state); !status.IsSuccess() {
		return status
	}

	// Calculating nodeResourceString can be heavy. Avoid it if klog verbosity is below 2.
	if assumedPodInfo.InitialAttemptTimestamp != nil {
		metrics.PodSchedulingDuration.WithLabelValues(getAttemptsLabel(assumedPodInfo)).Observe(metrics.SinceInSeconds(*assumedPodInfo.InitialAttemptTimestamp))
	}
	// 在 bind 绑定后执行收尾操作
	fwk.RunPostBindPlugins(ctx, state, assumedPod, scheduleResult.SuggestedHost)

	// At the end of a successful binding cycle, move up Pods if needed.
	if len(podsToActivate.Map) != 0 {
		sched.SchedulingQueue.Activate(podsToActivate.Map)
		// Unlike the logic in schedulingCycle(), we don't bother deleting the entries
		// as `podsToActivate.Map` is no longer consumed.
	}

	return nil
}
```

## 插件案例

### 1 NodeResourcesFit
```go
noderesources.Name:                   runtime.FactoryAdapter(fts, noderesources.NewFit),
```

```go
// ScoringStrategyType the type of scoring strategy used in NodeResourcesFit plugin.
type ScoringStrategyType string

const (
	// 空闲资源多的分高 --使的node上的负载比较合理一点！
	LeastAllocated ScoringStrategyType = "LeastAllocated"
	// 空闲资源少的分高 – 可以退回Node资源！
	MostAllocated ScoringStrategyType = "MostAllocated"
	// RequestedToCapacityRatio strategy allows specifying a custom shape function
	// to score nodes based on the request to capacity ratio.
	RequestedToCapacityRatio ScoringStrategyType = "RequestedToCapacityRatio"
)

//  下面定义了三个 scorer 打分策略.
var nodeResourceStrategyTypeMap = map[config.ScoringStrategyType]scorer{
	config.LeastAllocated: func(args *config.NodeResourcesFitArgs) *resourceAllocationScorer {
		resources := args.ScoringStrategy.Resources
		return &resourceAllocationScorer{
			Name:      string(config.LeastAllocated),
			scorer:    leastResourceScorer(resources),
			resources: resources,
		}
	},
	config.MostAllocated: func(args *config.NodeResourcesFitArgs) *resourceAllocationScorer {
		resources := args.ScoringStrategy.Resources
		return &resourceAllocationScorer{
			Name:      string(config.MostAllocated),
			scorer:    mostResourceScorer(resources),
			resources: resources,
		}
	},
	config.RequestedToCapacityRatio: func(args *config.NodeResourcesFitArgs) *resourceAllocationScorer {
		resources := args.ScoringStrategy.Resources
		return &resourceAllocationScorer{
			Name:      string(config.RequestedToCapacityRatio),
			scorer:    requestedToCapacityRatioScorer(resources, args.ScoringStrategy.RequestedToCapacityRatio.Shape),
			resources: resources,
		}
	},
}
```

scheduler 对 resource 打分内置三种不同策略, 分别是 LeastAllocated / MostAllocated / RequestedToCapacityRatio.

- LeastAllocated 默认策略, 空闲资源多的分高, 优先调度到空闲资源多的节点上, 各个 node 节点负载均衡.
- MostAllocated 空闲资源少的分高, 优先调度到空闲资源较少的 node 上, 这样 pod 尽量集中起来方便后面资源回收.
- RequestedToCapacityRatio 请求 request 和 node 资源总量的比率低的分高.

过滤

```go
func (f *Fit) Filter(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
	// 获取在 preFilter 阶段写入的 preFilterState
	s, err := getPreFilterState(cycleState)
	if err != nil {
		return framework.AsStatus(err)
	}
    // 判断当前的 node 是否满足 pod 的资源请求需求
	insufficientResources := fitsRequest(s, nodeInfo, f.ignoredResources, f.ignoredResourceGroups)
	
	if len(insufficientResources) != 0 {// 存在不足资源
		// We will keep all failure reasons.
		failureReasons := make([]string, 0, len(insufficientResources))
		for i := range insufficientResources {
			failureReasons = append(failureReasons, insufficientResources[i].Reason)
		}
		return framework.NewStatus(framework.Unschedulable, failureReasons...)
	}
	return nil
}
```

打分

```go
func (f *Fit) Score(ctx context.Context, state *framework.CycleState, pod *v1.Pod, nodeName string) (int64, *framework.Status) {
	nodeInfo, err := f.handle.SnapshotSharedLister().NodeInfos().Get(nodeName)
	if err != nil {
		return 0, framework.AsStatus(fmt.Errorf("getting node %q from Snapshot: %w", nodeName, err))
	}

	s, err := getPreScoreState(state)
	if err != nil {
		s = &preScoreState{
			podRequests: f.calculatePodResourceRequestList(pod, f.resources),
		}
	}

	return f.score(pod, nodeInfo, s.podRequests)
}


func (r *resourceAllocationScorer) score(
	pod *v1.Pod,
	nodeInfo *framework.NodeInfo,
	podRequests []int64) (int64, *framework.Status) {
	node := nodeInfo.Node()
	if node == nil {
		return 0, framework.NewStatus(framework.Error, "node not found")
	}
	// resources not set, nothing scheduled,
	if len(r.resources) == 0 {
		return 0, framework.NewStatus(framework.Error, "resources not found")
	}

	requested := make([]int64, len(r.resources))
	allocatable := make([]int64, len(r.resources))
	// 遍历 resources 累加计算 allocatable 和 requested.
	for i := range r.resources {
		// allocatable 是 node 还可以分配的资源
		// req 是 pod 所需要的资源
		alloc, req := r.calculateResourceAllocatableRequest(nodeInfo, v1.ResourceName(r.resources[i].Name), podRequests[i])
		// Only fill the extended resource entry when it's non-zero.
		if alloc == 0 {
			continue
		}
		allocatable[i] = alloc
		requested[i] = req
	}

	score := r.scorer(requested, allocatable)

    // ...

	return score, nil
}
```


## 参考 

- [官方调度框架](https://kubernetes.io/zh-cn/docs/concepts/scheduling-eviction/scheduling-framework/)
- [scheduler 核心调度器的实现原理](https://github.com/rfyiamcool/notes/blob/main/kubernetes_scheduler_code.md)