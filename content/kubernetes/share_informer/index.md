---
title: "ShareInformer 模块"
summary: 共享 reflector 反射器. 
date: 2024-08-19T14:27:21+08:00
categories:
  - kubernetes

tags:
  - k8s
  - informer
  - 源码
---



# sharedIndexInformer

sharedIndexInformer 相比普通的 informer 来说, 可以共享 reflector 反射器, 业务代码可以注册多个 resourceEventHandler 方法, 无需重复创建 informer 做监听及事件注册.

如果相同资源实例化多个 informer, 那么每个 informer 都有一个 reflector 和 store. 不仅会有数据序列化的开销, 而且缓存 store 不能复用, 可能一个对象存在多个 informer 的 store 里.


## 使用

SharedInformerFactory 工厂相比 SharedIndexInformer 来说, 组合了多个 informer 对象.
在一个 SharedInformerFactory 工厂对象里可以放不同类型的 sharedInformer 对象, 每个资源类型有单独的一个 sharedIndexInformer, 相同资源类型的使用同一个 informer 对象即可.


```go
func main() {
	// ...

	// 实例化 informers 集合对象
	informers := informers.NewSharedInformerFactory(client, 0)

	// 获取 pod informer
	podInformer := informers.Core().V1().Pods().Informer()

	// 为 podInformer 注册 eventHandler
	podInformer.AddEventHandler(&cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*v1.Pod)
			t.Logf("pod added: %s/%s", pod.Namespace, pod.Name)
		},
	})

	// 启动 informers
	informers.Start(ctx.Done())

	// 等待同步数据到本地缓存
	cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced)
}
```


## 结构体

```go
type sharedInformerFactory struct {
	client           kubernetes.Interface
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	lock             sync.Mutex
	defaultResync    time.Duration
	customResync     map[reflect.Type]time.Duration

	informers map[reflect.Type]cache.SharedIndexInformer
	// startedInformers is used for tracking which informers have been started.
	// This allows Start() to be called multiple times safely.
	startedInformers map[reflect.Type]bool
	// wg tracks how many goroutines were started.
	wg sync.WaitGroup
	// shuttingDown is true when Shutdown has been called. It may still be running
	// because it needs to wait for goroutines.
	shuttingDown bool
}
```


## 初始化
```go
func NewSharedInformerFactoryWithOptions(client kubernetes.Interface, defaultResync time.Duration, options ...SharedInformerOption) SharedInformerFactory {
	factory := &sharedInformerFactory{
		client:           client,
		namespace:        v1.NamespaceAll,
		defaultResync:    defaultResync,
		informers:        make(map[reflect.Type]cache.SharedIndexInformer),
		startedInformers: make(map[reflect.Type]bool),
		customResync:     make(map[reflect.Type]time.Duration),
	}

	// Apply all options
	for _, opt := range options {
		factory = opt(factory)
	}

	return factory
}
```


## 注册资源 InformerFor

这里拿 podinformer 为例
```go
func NewFilteredPodInformer(client kubernetes.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			// 注册 listFunc 方法
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CoreV1().Pods(namespace).List(context.TODO(), options)
			},
			///注册 watchFunc 方法
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CoreV1().Pods(namespace).Watch(context.TODO(), options)
			},
		},
		&corev1.Pod{}, // 定义资源类型
		resyncPeriod, // 重新同步时长 
		indexers, // 定义索引函数, 这里索引函数一般为 namespace
	)
}

func (f *podInformer) defaultInformer(client kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredPodInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *podInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&corev1.Pod{}, f.defaultInformer)
}
```

开始注册 informer
```go
func (f *sharedInformerFactory) InformerFor(obj runtime.Object, newFunc internalinterfaces.NewInformerFunc) cache.SharedIndexInformer {
	f.lock.Lock()
	defer f.lock.Unlock()

	// 获取资源类型
	informerType := reflect.TypeOf(obj)
	// 如果已创建过则返回
	informer, exists := f.informers[informerType]
	if exists {
		return informer
	}
    // 配置 resyncPeriod 时长
	resyncPeriod, exists := f.customResync[informerType]
	if !exists {
		resyncPeriod = f.defaultResync
	}
    // 创建一个 sharedIndexInformer 对象, 其实就是调用 NewFilteredXXXInformer 方法.
	// xxx 为各个资源类型的名字, 函数代码在 informers/v1 的各个文件里.
	informer = newFunc(f.client, resyncPeriod)
	f.informers[informerType] = informer

	return informer
}
```

## 配置处理函数 eventHandler


根据传入的 handler 对象构建 listener 监听器. 然后把监听器加到 listeners 数组里, 并启动 run 和 pop 两个协程
```go
func (s *sharedIndexInformer) AddEventHandler(handler ResourceEventHandler) (ResourceEventHandlerRegistration, error) {
	return s.AddEventHandlerWithResyncPeriod(handler, s.defaultEventHandlerResyncPeriod)
}

func (s *sharedIndexInformer) AddEventHandlerWithResyncPeriod(handler ResourceEventHandler, resyncPeriod time.Duration) (ResourceEventHandlerRegistration, error) {
	s.startedLock.Lock()
	defer s.startedLock.Unlock()

    // ...
	// 实例化一个 listener 监听对象
	listener := newProcessListener(handler, resyncPeriod, determineResyncPeriod(resyncPeriod, s.resyncCheckPeriod), s.clock.Now(), initialBufferSize)

	if !s.started {// 如果还没有启动
		// 把构建的 listener 放到 processor 的 listeners 数组里,并启动两个协程处理 run 和 pop 方法.
		return s.processor.addListener(listener), nil
	}

	// in order to safely join, we have to
	// 1. stop sending add/update/delete notifications
	// 2. do a list against the store
	// 3. send synthetic "Add" events to the new handler
	// 4. unblock
	s.blockDeltas.Lock()
	defer s.blockDeltas.Unlock()

	handle := s.processor.addListener(listener)
	for _, item := range s.indexer.List() {
		// 增加通知
		listener.add(addNotification{newObj: item})
	}
	return handle, nil
}

```

```go
func (p *sharedProcessor) addListener(listener *processorListener) ResourceEventHandlerRegistration {
	p.listenersLock.Lock()
	defer p.listenersLock.Unlock()

	if p.listeners == nil {
		p.listeners = make(map[*processorListener]bool)
	}

	p.listeners[listener] = true

	if p.listenersStarted {
		p.wg.Start(listener.run)
		p.wg.Start(listener.pop)
	}

	return listener
}
```

## 启动 sharedIndexInformer
```go
func (s *sharedIndexInformer) Run(stopCh <-chan struct{}) {
    // .. 
	// 实例化 deltaFIFO 队列
	fifo := NewDeltaFIFOWithOptions(DeltaFIFOOptions{
		KnownObjects:          s.indexer,
		EmitDeltaTypeReplaced: true,
	})

	cfg := &Config{
		Queue:            fifo,
		ListerWatcher:    s.listerWatcher, // reflector 内部会依赖这个做 list/watch 操作
        // 。。
		Process:           s.HandleDeltas, // 主要关心这个 pop 后的处理，这个是 reflector 消费 deltafifo 触发的回调方法
	}

	func() {
		s.startedLock.Lock()
		defer s.startedLock.Unlock()

		s.controller = New(cfg)
		s.controller.(*controller).clock = s.clock
		s.started = true
	}()

	// Separate stop channel because Processor should be stopped strictly after controller
	processorStopCh := make(chan struct{})
	var wg wait.Group
	defer wg.Wait()              // Wait for Processor to stop
	defer close(processorStopCh) // Tell Processor to stop
	// 缓存变更检测
	wg.StartWithChannel(processorStopCh, s.cacheMutationDetector.Run)
	//  启动 sharedProcessor: 为了启动刚刚的 listener 
	wg.StartWithChannel(processorStopCh, s.processor.run)

	defer func() {
		s.startedLock.Lock()
		defer s.startedLock.Unlock()
		s.stopped = true // Don't want any new listeners
	}()
	// 启动 controller
	s.controller.Run(stopCh)
}
```


## HandleDeltas 核心处理函数

HandleDeltas 用来处理从 DeltaFIFO 拿到的 deltas 事件列表, 然后通知给所有的 lisenter 去处理.
```go
func (s *sharedIndexInformer) HandleDeltas(obj interface{}) error {
	s.blockDeltas.Lock()
	defer s.blockDeltas.Unlock()

	if deltas, ok := obj.(Deltas); ok {
		return processDeltas(s, s.indexer, s.transform, deltas)
	}
	return errors.New("object given as Process argument is not Deltas")
}
```

```go
func processDeltas(
	// Object which receives event notifications from the given deltas
	handler ResourceEventHandler,
	clientState Store,
	transformer TransformFunc,
	deltas Deltas,
) error {
	// from oldest to newest
	for _, d := range deltas {
		obj := d.Object
		if transformer != nil {
			var err error
			obj, err = transformer(obj)
			if err != nil {
				return err
			}
		}

		switch d.Type {
		case Sync, Replaced, Added, Updated:
			if old, exists, err := clientState.Get(obj); err == nil && exists {
				if err := clientState.Update(obj); err != nil {
					return err
				}
				handler.OnUpdate(old, obj)
			} else {
				if err := clientState.Add(obj); err != nil {
					return err
				}
				handler.OnAdd(obj)
			}
		case Deleted:
			if err := clientState.Delete(obj); err != nil {
				return err
			}
			handler.OnDelete(obj)
		}
	}
	return nil
}
```

这里需要关心 handler-->sharedIndexInformer.OnAdd OnDelete OnUpdate

其实就是调用 processor.distribute 实现的, 没有直接使用 delta 结构, 而是使用 Notification 结构体封装了下.


```go
// Conforms to ResourceEventHandler
func (s *sharedIndexInformer) OnUpdate(old, new interface{}) {
    // ...
	s.processor.distribute(updateNotification{oldObj: old, newObj: new}, isSync)
}

// Conforms to ResourceEventHandler
func (s *sharedIndexInformer) OnDelete(old interface{}) {
	// Invocation of this function is locked under s.blockDeltas, so it is
	// save to distribute the notification
	s.processor.distribute(deleteNotification{oldObj: old}, false)
}

// Conforms to ResourceEventHandler
func (s *sharedIndexInformer) OnAdd(obj interface{}) {
    // ...
	s.processor.distribute(addNotification{newObj: obj}, false)
}
```

### distribute 把事件通知给所有 listeners

distribute 收到变更的事件后, 遍历通知给所有的 listener 监听器, 这里的通知是把事件写到 listener 的 addCh 通道.
```go
func (p *sharedProcessor) distribute(obj interface{}, sync bool) {
	p.listenersLock.RLock()
	defer p.listenersLock.RUnlock()

	// 加锁, 遍历所有的 listeners 集合, 并未每个 listener 添加事件.
	for listener, isSyncing := range p.listeners {
		switch {
		case !sync:
			listener.add(obj)
		case isSyncing:
			listener.add(obj)
		default:
		}
	}
}

func (p *processorListener) add(notification interface{}) {
	// 把 obj 写到 listener 对应的 addCh 管道里.
	p.addCh <- notification
}
```

### processorListener 消费
p.addCh 的数据进行处理



两个协程去执行 pop() 和 run().
```go
// 对数据的搬运 addCh -> pendingNotifications -> nextCh
func (p *processorListener) pop() {
	defer utilruntime.HandleCrash()
	defer close(p.nextCh) // Tell .run() to stop

	// addCh 和 nextCh 都是无缓冲的管道, 在这里只是用来做通知
	var nextCh chan<- interface{}
	var notification interface{}
	for {
		select {
		case nextCh <- notification: // 把从 addCh 获取的对象扔到 nextCh 里
			// Notification dispatched
			var ok bool
			notification, ok = p.pendingNotifications.ReadOne()
			if !ok { // Nothing to pop
				nextCh = nil // Disable this select case
			}
		case notificationToAdd, ok := <-p.addCh:
			if !ok {
				return
			}
			if notification == nil { // No notification to pop (and pendingNotifications is empty)
				// 当 notification 为空时, 给 nextCh 一个能用的 channel.
				// Optimize the case - skip adding to pendingNotifications
				notification = notificationToAdd
				nextCh = p.nextCh
			} else { // There is already a notification waiting to be dispatched
				// 从 addCh 获取对象, 如果上一次的 notification 还未扔到 nextCh 里, 那么之后的对象扔到 buffer 里
				p.pendingNotifications.WriteOne(notificationToAdd)
			}
		}
	}
}
```

```go
func (p *processorListener) run() {
	// this call blocks until the channel is closed.  When a panic happens during the notification
	// we will catch it, **the offending item will be skipped!**, and after a short delay (one second)
	// the next notification will be attempted.  This is usually better than the alternative of never
	// delivering again.
	stopCh := make(chan struct{})
	wait.Until(func() {
		for next := range p.nextCh {
			switch notification := next.(type) {
			case updateNotification:
				p.handler.OnUpdate(notification.oldObj, notification.newObj)
			case addNotification:
				p.handler.OnAdd(notification.newObj)
			case deleteNotification:
				p.handler.OnDelete(notification.oldObj)
			default:
				utilruntime.HandleError(fmt.Errorf("unrecognized notification: %T", next))
			}
		}
		// the only way to get here is if the p.nextCh is empty and closed
		close(stopCh)
	}, 1*time.Second, stopCh)
}

```


## 启动 sharedInformerFactory

启动当前 informers 里的所有 informer.

```go
func (f *sharedInformerFactory) Start(stopCh <-chan struct{}) {
	f.lock.Lock()
	defer f.lock.Unlock()


	for informerType, informer := range f.informers {
		if !f.startedInformers[informerType] {
			f.wg.Add(1)
			informer := informer
			go func() {
				defer f.wg.Done()
				informer.Run(stopCh)
			}()
			f.startedInformers[informerType] = true
		}
	}
}
```



## 获取数据
```go
func main() {
	// 实例化 informers 集合对象
	informers := informers.NewSharedInformerFactory(client, 0)

	// 获取 pod informer
	podInformer := informers.Core().V1().Pods().Informer()

	// 获取 pod lister 实例
	podLister := informers.Core().V1().Pods().Lister()

	// 从缓存中获取 pods
	podLister.List(labels.Everything())
}
```


传参 informer indexer 存储创建 podLister 对象,这里的indexer 底层就是 threadSafeMap
```go
func (f *podInformer) Lister() v1.PodLister {
	return v1.NewPodLister(f.Informer().GetIndexer())
}
```

```go
// List lists all Pods in the indexer.
func (s *podLister) List(selector labels.Selector) (ret []*v1.Pod, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
        // 把符合条件的 pod 放到 ret 里
		ret = append(ret, m.(*v1.Pod))
	})
	return ret, err
}

func ListAll(store Store, selector labels.Selector, appendFn AppendFunc) error {
	selectAll := selector.Empty()
	for _, m := range store.List() {
		if selectAll {
			// 空的 selector
			appendFn(m)
			continue
		}
		metadata, err := meta.Accessor(m)
		if err != nil {
			return err
		}
		// label 过滤
		if selector.Matches(labels.Set(metadata.GetLabels())) {
			appendFn(m)
		}
	}
	return nil
}

```

## 参考