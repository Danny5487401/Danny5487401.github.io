---
title: "Workqueue"
date: 2024-08-20T13:43:28+08:00
summary: workqueue 三大实现及源码分析
---

# workqueue


在 kubernetes 中，使用 go 的 channel 无法满足 kubernetes 的应用场景，如延迟、限速等；



主要功能在于标记和去重，并支持如下特性。


* 有序：按照添加顺序处理元素（item）。
* 去重：相同元素在同一时间不会被重复处理，例如一个元素在处理之前被添加了多次，它只会被处理一次。
* 并发性：多生产者和多消费者。
* 标记机制：支持标记功能，标记一个元素是否被处理，也允许元素在处理时重新排队。
* 通知机制：ShutDown 方法通过信号量通知队列不再接收新的元素，并通知 metric goroutine 退出。
* 延迟：支持延迟队列，延迟一段时间后再将元素存入队列。
* 限速：支持限速队列，元素存入队列时进行速率限制。限制一个元素被重新排队（Reenqueued）的次数。
* Metric：支持 metric 监控指标，可用于 Prometheus 监控。


## 需求


**为什么队列需要去重功能 ?**

当一个资源对象被频繁变更, 然而同一个对象还未被消费, 没必要在在队列中存多份, 经过去重后只需要处理一次即可.

**为什么需要 delay 延迟入队功能 ?**

有些 k8s controller 是需要延迟队列功能的, 比如像 cronjob 依赖延迟队列实现定时功能. 另外也可以实现延迟 backoff 时长后重入队.

**为什么需要限频功能 ?**

避免过多事件并发入队, 使用限频策略对入队的事件个数进行控制. k8s 中的 controller 大把的使用限频.

**informer 中的 deltafifo 跟 workqueue 区别?**

deltafifo 虽然名为 fifo 队列, 但他的 fifo 不是全局事件, 而只是针对某资源对象的事件进行内部 fifo 排列. 比如某个 deployment 频繁做变更, 那么 deltafifo 逻辑是把后续收到的相关事件放在一起.

## WorkQueue 分类

WorkQueue 支持 3 种队列，并提供了 3 种接口，不同队列实现可应对不同的使用场景，分别介绍如下。


Interface：FIFO 队列接口，先进先出队列，并支持去重机制。

DelayingInterface：延迟队列接口，基于 Interface 接口封装，延迟一段时间后再将元素存入队列。

RateLimitingInterface：限速队列接口，基于 DelayingInterface 接口封装，支持元素存入队列时进行速率限制

### FIFO 队列

#### 流程 
{{<figure src="./fifo_process.png#center" width=800px >}}

通过 Add 方法往 FIFO 队列中分别插入 1、2、3 这 3 个元素，此时队列中的 queue 和 dirty 字段分别存有 1、2、3 元素，processing 字段为空。
然后通过 Get 方法获取最先进入的元素（也就是 1 元素），此时队列中的 queue 和 dirty 字段分别存有 2、3 元素，而 1 元素会被放入 processing 字段中，表示该元素正在被处理。
最后，当我们处理完 1 元素时，通过 Done 方法标记该元素已经被处理完成，此时队列中的 processing 字段中的 1 元素会被删除。

#### 结构体 

```go

// Type is a work queue (see the package comment).
type Type struct {

	queue []t

	dirty set
	
	processing set

    // ...
}

type empty struct{}
type t interface{}
type set map[t]empty
```
- queue 字段是实际存储元素的地方，它是 slice 结构的，用于保证元素有序；
- dirty 字段非常关键，除了能保证去重，还能保证在处理一个元素之前哪怕其被添加了多次（并发情况下），但也只会被处理一次；
- processing 字段用于标记机制，标记一个元素是否正在被处理。


#### 并发场景描述及源码解释





deployment controller 处理元素
```go
func (dc *DeploymentController) processNextWorkItem(ctx context.Context) bool {
	// 拿元素
	key, quit := dc.queue.Get()
	if quit {
		return false
	}
	// defer 标记结束
	defer dc.queue.Done(key)

	err := dc.syncHandler(ctx, key.(string))
	dc.handleErr(ctx, err, key)

	return true
}
```

{{<figure src="./fifo-concurency.png#center" width=800px >}}

1. 在并发场景下，假设 goroutine A 通过 Get 方法获取 1 元素，1 元素被添加到 processing 字段中，同一时间，goroutine B 通过 Add 方法插入另一个 1 元素，此时在 processing 字段中已经存在相同的元素，所以后面的 1 元素并不会被直接添加到 queue 字段中，当前 FIFO 队列中的 dirty 字段中存有 1、2、3 元素，processing 字段存有 1 元素。
2. 在 goroutine A 通过 Done 方法标记处理完成后，如果 dirty 字段中存有 1 元素，则将 1 元素追加到 queue 字段中的尾部。

```go
// Add marks item as needing processing.
func (q *Type) Add(item interface{}) {
	q.cond.L.Lock()
	defer q.cond.L.Unlock()
	if q.shuttingDown {
		return
	}
	if q.dirty.has(item) {
        // 判断 dirty 是否存在该元素, 如存在则直接跳出, 其目的是为了实现待处理元素的去重效果.
		return
	}

	q.metrics.add(item)

	q.dirty.insert(item) // 在 dirty 里添加元素
	if q.processing.has(item) {
		// 判断 processing 集合是否存在元素, 如果存在则跳出. 其目的是为了防止同一个元素被并发处理.
		return
	}
    // 把元素放到队列里
	q.queue = append(q.queue, item)
	q.cond.Signal()
}
```

```go
// Done() 用来标记某元素已经处理完,
func (q *Type) Done(item interface{}) {
	q.cond.L.Lock()
	defer q.cond.L.Unlock()

	q.metrics.done(item)

	q.processing.delete(item)
	if q.dirty.has(item) {
		// 会把 dirty 的任务重新入队, 起到了排队的效果.
		q.queue = append(q.queue, item)
		q.cond.Signal()
	} else if q.processing.len() == 0 {
		q.cond.Signal()
	}
}
```



### 延迟队列 DelayingInterface
{{<figure src="delaying-interface.png#center" width=800px >}}

```go
type DelayingInterface interface {
	// 继承 Queue Interface 的基本功能
	Interface

	// 添加定时功能
	AddAfter(item interface{}, duration time.Duration)
}
```



#### 数据结构定义

```go
type delayingType struct {
	// 继承 Queue Interface 队列基本功能
	Interface

	// 对比的时间 ，包含一些定时器的功能
	clock clock.Clock

	// 退出通道
	stopCh chan struct{}
	stopOnce sync.Once

	// 周期性检测队列是否有对象到期
	heartbeat clock.Ticker

	// 新的定时元素会推到该管道中, 等待 loop 处理.
	waitingForAddCh chan *waitFor

	// 用来 metrics 统计
	metrics retryMetrics
}
```

delay queue 使用了 heap 做延迟队列。


{{<figure src="delaying-interface-waittingloop.png#center" width=800px >}}
```go
// 心跳的时长
const maxWait = 10 * time.Second

// 构建定时器队列对象方法
func NewDelayingQueueWithCustomClock(clock clock.WithTicker, name string) DelayingInterface {
	// clock 为 k8s 内部封装的时间对象
	// NewNamed 用来生成 Queue.
	return newDelayingQueue(clock, NewNamed(name), name)
}

// 真正的构建定时器队列对象方法
func newDelayingQueue(clock clock.WithTicker, q Interface, name string) *delayingType {
	ret := &delayingType{
		Interface:       q,
		clock:           clock,
		heartbeat:       clock.NewTicker(maxWait),
		stopCh:          make(chan struct{}),
		waitingForAddCh: make(chan *waitFor, 1000),
		metrics:         newRetryMetrics(name),
	}

	go ret.waitingLoop()
	return ret
}

func (q *delayingType) waitingLoop() {
	never := make(<-chan time.Time)
	var nextReadyAtTimer clock.Timer

	// 初始化 min heap 小顶堆
	waitingForQueue := &waitForPriorityQueue{}
	heap.Init(waitingForQueue)

	waitingEntryByData := map[t]*waitFor{}

	for {
		// 如果 queue 已经被关闭, 则退出该 loop 协程.
		if q.Interface.ShuttingDown() {
			return
		}

		now := q.clock.Now()

		for waitingForQueue.Len() > 0 {
			// 如果延迟 heap 不为空, 则获取堆顶的元素.
			entry := waitingForQueue.Peek().(*waitFor)
			// 如果大于当前时间, 则没有到期, 则跳出.
			if entry.readyAt.After(now) {
				break
			}

			// 如果小于当前时间, 则 pop 出元素, 然后扔到 queue 队里中.
			entry = heap.Pop(waitingForQueue).(*waitFor)
			q.Add(entry.data)
			delete(waitingEntryByData, entry.data)
		}

		// 如果小顶堆为空, 则使用 never 做无限时长定时器
		nextReadyAt := never

		// 如果 minheap 小顶堆不为空, 设置最近元素的时间为定时器的时间.
		if waitingForQueue.Len() > 0 {
			if nextReadyAtTimer != nil {
				nextReadyAtTimer.Stop()
			}

			// 从堆顶获取最近的元素
			entry := waitingForQueue.Peek().(*waitFor)

			// 实例化 timer 定时器
			nextReadyAtTimer = q.clock.NewTimer(entry.readyAt.Sub(now))
			nextReadyAt = nextReadyAtTimer.C()
		}

		select {
		case <-q.stopCh:
			return

		case <-q.heartbeat.C():
			// 触发 10s 心跳超时后, 重新进行选择最近的定时任务.

		case <-nextReadyAt:
			// 上次计算的最近元素的定时器已到期, 进行下次循环. 期间会处理该到期任务. 

		case waitEntry := <-q.waitingForAddCh:
			// 收到新添加的定时器

			// 如果新对象还未到期, 则把定时对象放到 heap 定时堆里.
			if waitEntry.readyAt.After(q.clock.Now()) {
				insert(waitingForQueue, waitingEntryByData, waitEntry)
			} else {
				// 如果该定时任务已到期, 则调用继承的 queue 的 add 方法.把元素添加到队列中.
				q.Add(waitEntry.data)
			}

			// drain 为取尽的设计, 是一个性能优化点.
			// 尽量在该单次循环中把 chan 读空, 避免留存后 select 阶段总是被唤醒.
			drained := false
			for !drained {
				select {
				case waitEntry := <-q.waitingForAddCh:
					if waitEntry.readyAt.After(q.clock.Now()) {
						insert(waitingForQueue, waitingEntryByData, waitEntry)
					} else {
						q.Add(waitEntry.data)
					}
				default:
					drained = true
				}
			}
		}
	}
}

// 调用方使用 AddAfter 添加定时任务
func (q *delayingType) AddAfter(item interface{}, duration time.Duration) {
	// 如果关闭, 则退出
	if q.ShuttingDown() {
		return
	}

	// 进行统计
	q.metrics.retry()

	// 时间不合理, 直接入队列, 不走堆逻辑
	if duration <= 0 {
		q.Add(item)
		return
	}

	select {
	case <-q.stopCh:
		// 等待退出
	case q.waitingForAddCh <- &waitFor{data: item, readyAt: q.clock.Now().Add(duration)}:
		// 创建一个定时对象, 然后推到 waitingForAddCh 管道中, 等待 waitingLoop 协程处理.
	}
}
```

### 限速队列

```go
type RateLimitingInterface interface {
	// 继承了 DelayingInterface 延迟队列
	DelayingInterface
	
	// 使用对应的限频算法求出需要 delay 的时长, 然后添加到 delay 队列中.
	AddRateLimited(item interface{})

	// 在 rateLimiter 中取消某对象的追踪记录.
	Forget(item interface{})

	// 从 rateLimiter 中获取计数.
	NumRequeues(item interface{}) int
}
```

```go
type rateLimitingType struct {
	// 继承延迟队列
	DelayingInterface

	// 限速组件
	rateLimiter RateLimiter
}
```


```go
// AddRateLimited AddAfter's the item based on the time when the rate limiter says it's ok
func (q *rateLimitingType) AddRateLimited(item interface{}) {
	q.DelayingInterface.AddAfter(item, q.rateLimiter.When(item))
}
// 获取该对象的计数信息.
func (q *rateLimitingType) NumRequeues(item interface{}) int {
	return q.rateLimiter.NumRequeues(item)
}
// 删除该对象的记录的信息
func (q *rateLimitingType) Forget(item interface{}) {
	q.rateLimiter.Forget(item)
}

```

#### RateLimiter 的具体的实现

```go
type RateLimiter interface {
	// 获取该元素需要等待多久才能入队.
	When(item interface{}) time.Duration

	// 删除该元素的追踪记录, 有些 rateLimiter 记录了该对象的次数.
	Forget(item interface{})

	// 该对象记录的次数
	NumRequeues(item interface{}) int
}
```



抽象限速器的实现，有 BucketRateLimiter , ItemBucketRateLimiter , ItemExponentialFailureRateLimiter , ItemFastSlowRateLimiter ,  MaxOfRateLimiter 混合模式



## 参考

- [Kubernetes 架构之 workqueue 原理解析](https://mp.weixin.qq.com/s/pkyBuTLtmKKWCBHSQ82d9g)
- [深入浅出 kubernetes 之 WorkQueue 详解](https://xie.infoq.cn/article/63258ead84821bc3e276de1f7)