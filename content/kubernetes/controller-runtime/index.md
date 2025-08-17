---
title: "Controller Runtime"
date: 2025-08-15T16:54:17+08:00
summary: 快速生成项目的脚手架
---




controller-runtime项目是一个用于快速构建k8s operator的工具包。
其中 github.com/kubernetes-sigs/kubebuilder 和 github.com/operator-framework/operator-sdk 项目都是通过controller-runtime项目来快速编写k8s operator的工具。

operator sdk在底层使用了kubebuilder.



controller-runtime 的核心是Manager 驱动 Controller 进而驱动 Reconciler。


## 整体设计


Manager 管理多个Controller 的运行，并提供 数据读（cache）写（client）等crudw基础能力，或者说 Manager 负责初始化cache、clients 等公共依赖，并提供个runnbale 使用。



operator代码框架的主体逻辑包括以下几个部分。

- manager：主要用来管理多个的controller，构建，注册，运行controller。

- controller：主要用来封装reconciler的控制器。

- reconciler：具体执行业务逻辑的函数。



### manager

接口
```go
// sigs.k8s.io/controller-runtime@v0.17.2/pkg/manager/manager.go
type Manager interface {
	// Cluster holds a variety of methods to interact with a cluster.
	cluster.Cluster

	// 通过Runnable接口将具体的controller注册到manager中。
	Add(Runnable) error

	// Elected is closed when this manager is elected leader of a group of
	// managers, either because it won a leader election or because no leader
	// election was configured.
	Elected() <-chan struct{}

	// AddHealthzCheck allows you to add Healthz checker
	AddHealthzCheck(name string, check healthz.Checker) error

	// AddReadyzCheck allows you to add Readyz checker
	AddReadyzCheck(name string, check healthz.Checker) error

	// 运行具体的逻辑
	Start(ctx context.Context) error

	// GetWebhookServer returns a webhook.Server
	GetWebhookServer() webhook.Server

	// GetLogger returns this manager's logger.
	GetLogger() logr.Logger

	// GetControllerOptions returns controller global configuration options.
	GetControllerOptions() config.Controller
}
```

初始化 controllerManager
 
```go
func New(config *rest.Config, options Options) (Manager, error) {
	if config == nil {
		return nil, errors.New("must specify Config")
	}
	// Set default values for options fields
	options = setOptionsDefaults(options)
	
	// 初始化与 k8s 交互的接口
	cluster, err := cluster.New(config, func(clusterOptions *cluster.Options) {
        clusterOptions.Scheme = options.Scheme
        clusterOptions.MapperProvider = options.MapperProvider
        clusterOptions.Logger = options.Logger
        clusterOptions.NewCache = options.NewCache
        clusterOptions.NewClient = options.NewClient
        clusterOptions.Cache = options.Cache
        clusterOptions.Client = options.Client
        clusterOptions.EventBroadcaster = options.EventBroadcaster //nolint:staticcheck
    })

    // ....

	errChan := make(chan error, 1)
	runnables := newRunnables(options.BaseContext, errChan)
	return &controllerManager{
		stopProcedureEngaged:          ptr.To(int64(0)),
		cluster:                       cluster,
		runnables:                     runnables,
		errChan:                       errChan,
		recorderProvider:              recorderProvider,
		resourceLock:                  resourceLock,
		metricsServer:                 metricsServer,
		controllerConfig:              options.Controller,
		logger:                        options.Logger,
		elected:                       make(chan struct{}),
		webhookServer:                 options.WebhookServer,
		leaderElectionID:              options.LeaderElectionID,
		leaseDuration:                 *options.LeaseDuration,
		renewDeadline:                 *options.RenewDeadline,
		retryPeriod:                   *options.RetryPeriod,
		healthProbeListener:           healthProbeListener,
		readinessEndpointName:         options.ReadinessEndpointName,
		livenessEndpointName:          options.LivenessEndpointName,
		pprofListener:                 pprofListener,
		gracefulShutdownTimeout:       *options.GracefulShutdownTimeout,
		internalProceduresStop:        make(chan struct{}),
		leaderElectionStopped:         make(chan struct{}),
		leaderElectionReleaseOnCancel: options.LeaderElectionReleaseOnCancel,
	}, nil
}
```


启动

```go
func (cm *controllerManager) Start(ctx context.Context) (err error) {
    // ...


	// Add the cluster runnable.
	if err := cm.add(cm.cluster); err != nil {
		return fmt.Errorf("failed to add cluster to runnables: %w", err)
	}

	// ...

	// 启动内部 http 服务,包括 health probes, metrics and profiling
	if err := cm.runnables.HTTPServers.Start(cm.internalCtx); err != nil {
		if err != nil {
			return fmt.Errorf("failed to start HTTP servers: %w", err)
		}
	}

	// 启动 webhook servers
	if err := cm.runnables.Webhooks.Start(cm.internalCtx); err != nil {
		if err != nil {
			return fmt.Errorf("failed to start webhooks: %w", err)
		}
	}

	// Start and wait for caches.
	if err := cm.runnables.Caches.Start(cm.internalCtx); err != nil {
		if err != nil {
			return fmt.Errorf("failed to start caches: %w", err)
		}
	}

	// Start the non-leaderelection Runnables after the cache has synced.
	if err := cm.runnables.Others.Start(cm.internalCtx); err != nil {
		if err != nil {
			return fmt.Errorf("failed to start other runnables: %w", err)
		}
	}

	// Start the leader election and all required runnables.
	{
		ctx, cancel := context.WithCancel(context.Background())
		cm.leaderElectionCancel = cancel
		go func() {
			if cm.resourceLock != nil {
				if err := cm.startLeaderElection(ctx); err != nil {
					cm.errChan <- err
				}
			} else {
				// Treat not having leader election enabled the same as being elected.
				if err := cm.startLeaderElectionRunnables(); err != nil {
					cm.errChan <- err
				}
				close(cm.elected)
			}
		}()
	}

	ready = true
	cm.Unlock()
	select {
	case <-ctx.Done():
		// We are done
		return nil
	case err := <-cm.errChan:
		// Error starting or running a runnable
		return err
	}
}

```


### controller

接口

```go
type Controller interface {
	// Reconciler is called to reconcile an object by Namespace/Name
	reconcile.Reconciler

	
	// 监听 Source ,通过 EventHandler 放入队列, 可以在EventHandler之前进行 Predicate
	Watch(src source.Source, eventhandler handler.EventHandler, predicates ...predicate.Predicate) error

	// Start starts the controller.  Start blocks until the context is closed or a
	// controller has an error starting.
	Start(ctx context.Context) error

	// GetLogger returns this controller logger prefilled with basic information.
	GetLogger() logr.Logger
}

```

初始化 Controller

```go
func New(name string, mgr manager.Manager, options Options) (Controller, error) {
	c, err := NewUnmanaged(name, mgr, options)
	if err != nil {
		return nil, err
	}

	// Add the controller as a Manager components
	return c, mgr.Add(c)
}

```

```go
func NewUnmanaged(name string, mgr manager.Manager, options Options) (Controller, error) {
    // ...

	// Create controller with dependencies set
	return &controller.Controller{
		Do: options.Reconciler,  // 将具体的reconciler函数传递到controller的reconciler。
		MakeQueue: func() workqueue.RateLimitingInterface {
			return workqueue.NewRateLimitingQueueWithConfig(options.RateLimiter, workqueue.RateLimitingQueueConfig{
				Name: name,
			})
		},  // 初始化任务队列
		MaxConcurrentReconciles: options.MaxConcurrentReconciles,  // 设置controller的并发数
		CacheSyncTimeout:        options.CacheSyncTimeout,
		Name:                    name,
		LogConstructor:          options.LogConstructor,
		RecoverPanic:            options.RecoverPanic,
		LeaderElected:           options.NeedLeaderElection,
	}, nil
}
```

添加监听

```go
func (c *Controller) Watch(src source.Source, evthdler handler.EventHandler, prct ...predicate.Predicate) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Controller hasn't started yet, store the watches locally and return.
	//
	// These watches are going to be held on the controller struct until the manager or user calls Start(...).
	if !c.Started { // 如果还没有启动
		c.startWatches = append(c.startWatches, watchDescription{src: src, handler: evthdler, predicates: prct})
		return nil
	}

	c.LogConstructor(nil).Info("Starting EventSource", "source", src)
	return src.Start(c.ctx, evthdler, c.Queue, prct...)
}

```

启动

```go
func (ks *Kind) Start(ctx context.Context, handler handler.EventHandler, queue workqueue.RateLimitingInterface,
	prct ...predicate.Predicate) error {
    // ...

	// cache.GetInformer will block until its context is cancelled if the cache was already started and it can not
	// sync that informer (most commonly due to RBAC issues).
	ctx, ks.startCancel = context.WithCancel(ctx)
	ks.started = make(chan error)
	go func() {
		var (
			i       cache.Informer
			lastErr error
		)

		// Tries to get an informer until it returns true,
		// an error or the specified context is cancelled or expired.
		if err := wait.PollUntilContextCancel(ctx, 10*time.Second, true, func(ctx context.Context) (bool, error) {
			// Lookup the Informer from the Cache and add an EventHandler which populates the Queue
			i, lastErr = ks.Cache.GetInformer(ctx, ks.Type)
			if lastErr != nil {
                // ...
			}
			return true, nil
		}); err != nil {
			if lastErr != nil {
				ks.started <- fmt.Errorf("failed to get informer from cache: %w", lastErr)
				return
			}
			ks.started <- err
			return
		}

		_, err := i.AddEventHandler(NewEventHandler(ctx, queue, handler, prct).HandlerFuncs())
		if err != nil {
			ks.started <- err
			return
		}
		if !ks.Cache.WaitForCacheSync(ctx) {
			// Would be great to return something more informative here
			ks.started <- errors.New("cache did not sync")
		}
		close(ks.started)
	}()

	return nil
}

```


## 请求分发：从cache中读取还是直连


```go
// sigs.k8s.io/controller-runtime@v0.17.2/pkg/client/client.go

func (c *client) Get(ctx context.Context, key ObjectKey, obj Object, opts ...GetOption) error {
	if isUncached, err := c.shouldBypassCache(obj); err != nil {
		return err
	} else if !isUncached { 
		// 缓存获取
		return c.cache.Get(ctx, key, obj, opts...)
	}

	// 直连 apiserver 取数据
	switch obj.(type) {
	case runtime.Unstructured:
		return c.unstructuredClient.Get(ctx, key, obj, opts...)
	case *metav1.PartialObjectMetadata:
		// Metadata only object should always preserve the GVK coming in from the caller.
		defer c.resetGroupVersionKind(obj, obj.GetObjectKind().GroupVersionKind())
		return c.metadataClient.Get(ctx, key, obj, opts...)
	default:
		return c.typedClient.Get(ctx, key, obj, opts...)
	}
}

```

## 第三方使用-->argo-event


```go
func Start(eventsOpts ArgoEventsControllerOpts) {
	// 初始化 logger
	logger := logging.NewArgoEventsLogger().Named(eventbus.ControllerName)
	config, err := reconciler.LoadConfig(func(err error) {
		logger.Errorw("Failed to reload global configuration file", zap.Error(err))
	})
	if err != nil {
		logger.Fatalw("Failed to load global configuration file", zap.Error(err))
	}

	// 校验配置
	if err = reconciler.ValidateConfig(config); err != nil {
		logger.Fatalw("Global configuration file validation failed", zap.Error(err))
	}

	imageName, defined := os.LookupEnv(imageEnvVar)
	if !defined {
		logger.Fatalf("required environment variable '%s' not defined", imageEnvVar)
	}
	// 初始化 controller 选项
	opts := ctrl.Options{
		Metrics: metricsserver.Options{
			BindAddress: fmt.Sprintf(":%d", eventsOpts.MetricsPort),
		},
		HealthProbeBindAddress: fmt.Sprintf(":%d", eventsOpts.HealthPort),
	}
	if eventsOpts.Namespaced {
		opts.Cache = cache.Options{
			DefaultNamespaces: map[string]cache.Config{
				eventsOpts.ManagedNamespace: {},
			},
		}
	}
	if eventsOpts.LeaderElection {
		opts.LeaderElection = true
		opts.LeaderElectionID = "argo-events-controller"
	}
	restConfig := ctrl.GetConfigOrDie()
	//  初始化 Manager，同时生成一个默认配置的 Cache
	mgr, err := ctrl.NewManager(restConfig, opts)
	if err != nil {
		logger.Fatalw("Unable to get a controller-runtime manager", zap.Error(err))
	}
	kubeClient := kubernetes.NewForConfigOrDie(restConfig)

	// Readyness probe
	if err := mgr.AddReadyzCheck("readiness", healthz.Ping); err != nil {
		logger.Fatalw("Unable add a readiness check", zap.Error(err))
	}

	// Liveness probe
	if err := mgr.AddHealthzCheck("liveness", healthz.Ping); err != nil {
		logger.Fatalw("Unable add a health check", zap.Error(err))
	}

	// 添加 argo event gvr
	if err := aev1.AddToScheme(mgr.GetScheme()); err != nil {
		logger.Fatalw("Unable to add scheme", zap.Error(err))
	}

	// 接下来就是 用 Reconciler 实现业务逻辑，并将其挂在 manager 上
	// EventBus controller
	eventBusController, err := controller.New(eventbus.ControllerName, mgr, controller.Options{
		Reconciler: eventbus.NewReconciler(mgr.GetClient(), kubeClient, mgr.GetScheme(), config, logger),
	})
	if err != nil {
		logger.Fatalw("Unable to set up EventBus controller", zap.Error(err))
	}

	// 监听 EventBus and enqueue EventBus object key
	if err := eventBusController.Watch(source.Kind(mgr.GetCache(), &aev1.EventBus{}), &handler.EnqueueRequestForObject{},
		predicate.Or(
			predicate.GenerationChangedPredicate{},
			predicate.LabelChangedPredicate{},
		)); err != nil {
		logger.Fatalw("Unable to watch EventBus", zap.Error(err))
	}
	

    // ...

	// EventSource controller
	eventSourceController, err := controller.New(eventsource.ControllerName, mgr, controller.Options{
		Reconciler: eventsource.NewReconciler(mgr.GetClient(), mgr.GetScheme(), imageName, logger),
	})
	if err != nil {
		logger.Fatalw("Unable to set up EventSource controller", zap.Error(err))
	}

	// Watch EventSource and enqueue EventSource object key
	if err := eventSourceController.Watch(source.Kind(mgr.GetCache(), &aev1.EventSource{}), &handler.EnqueueRequestForObject{},
		predicate.Or(
			predicate.GenerationChangedPredicate{},
			predicate.LabelChangedPredicate{},
		)); err != nil {
		logger.Fatalw("Unable to watch EventSources", zap.Error(err))
	}

    // ... watch 其他对象

	// Sensor controller
	sensorController, err := controller.New(sensor.ControllerName, mgr, controller.Options{
		Reconciler: sensor.NewReconciler(mgr.GetClient(), mgr.GetScheme(), imageName, logger),
	})
	if err != nil {
		logger.Fatalw("Unable to set up Sensor controller", zap.Error(err))
	}

	// Watch Sensor and enqueue Sensor object key
	if err := sensorController.Watch(source.Kind(mgr.GetCache(), &aev1.Sensor{}), &handler.EnqueueRequestForObject{},
		predicate.Or(
			predicate.GenerationChangedPredicate{},
			predicate.LabelChangedPredicate{},
		)); err != nil {
		logger.Fatalw("Unable to watch Sensors", zap.Error(err))
	}

	// Watch Deployments and enqueue owning Sensor key
	if err := sensorController.Watch(source.Kind(mgr.GetCache(), &appv1.Deployment{}),
		handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &aev1.Sensor{}, handler.OnlyControllerOwner()),
		predicate.GenerationChangedPredicate{}); err != nil {
		logger.Fatalw("Unable to watch Deployments", zap.Error(err))
	}

	logger.Infow("Starting controller manager", "version", argoevents.GetVersion())
	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		logger.Fatalw("Unable to start controller manager", zap.Error(err))
	}
}

```



## 参考

- [controller-runtime源码分析](https://qiankunli.github.io/2020/08/10/controller_runtime.html)
- [controller-runtime细节分析](https://qiankunli.github.io/2022/11/24/controller_runtime_detail.html)