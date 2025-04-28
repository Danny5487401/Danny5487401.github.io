---
title: "Linux cgroups"
date: 2024-10-23T22:24:23+08:00
summary: " Cgroup（control group 控制组群）是内核提供的一种资源隔离的机制，可以实现对进程所使用的cpu、内存物理资源、及网络带宽等进行限制。还可以通过分配的CPU时间片数量及磁盘IO宽带大小控制任务运行的优先"
categories:
  - kubernetes
  - cgroup
tags:
  - cgroup
---

cgroups（Control Groups）最初叫 Process Container，由 Google 工程师（Paul Menage 和 Rohit Seth）于 2006 年提出，后来因为 Container 有多重含义容易引起误解，就在 2007 年更名为 Control Groups，并被整合进 Linux 内核。
顾名思义就是把进程放到一个组里面统一加以控制.

cgroup 是一种以 hierarchical（树形层级）方式组织进程的机制（a mechanism to organize processes hierarchically），以及在层级中以受控和 可配置的方式（controlled and configurable manner）分发系统资源 （distribute system resources）


## 基本概念
- 任务（task）： 在cgroup中，任务相当于是一个进程，可以属于不同的cgroup组，但是所属的cgroup不能同属一层级
- 任务/控制组： 资源控制是以控制组的方式实现的，进程可以加入到指定的控制组中，类似于Linux中user和group的关系。控制组为树状结构的上下父子关系，子节点控制组会继承父节点控制组的属性，如资源配额等
- 层级（hierarchy）： 一个大的控制组群树，归属于一个层级中，不同的控制组以层级区分开
- 子系统（subsystem）： 一个的资源控制器，比如cpu子系统可以控制进程的cpu使用率，子系统需要附加（attach）到某个层级，然后该层级的所有控制组，均受到该子系统的控制

## 组成


cgroup 主要由两部分组成：

- 核心（core）：主要负责层级化地组织进程；
- 控制器（controllers）：大部分控制器负责 cgroup 层级中 特定类型的系统资源的分配，少部分 utility 控制器用于其他目的。

### 常见的子系统（subsystem）
```shell
ubuntu@VM-16-12-ubuntu:/sys/fs/cgroup$ ls
blkio  cpu  cpuacct  cpu,cpuacct  cpuset  devices  freezer  hugetlb  memory  net_cls  net_cls,net_prio  net_prio  perf_event  pids  rdma  systemd  unified
```
- cpu 子系统： 主要限制进程的 cpu 使用率。
- cpuacct 子系统： 可以统计 cgroups 中的进程的 cpu 使用报告。
- cpuset 子系统： 为cgroups中的进程分配单独的cpu节点或者内存节点。
- memory 子系统： 可以限制进程的 memory 使用量。
- blkio 子系统： 可以限制进程的块设备 io。比如物理驱动设备（包括磁盘、固态硬盘、USB 等）
- devices 子系统： 可以控制进程能够访问某些设备。
- net_cls 子系统： 可以标记cgroups 中进程的网络数据包，然后可以使用 tc 模块（traffic control）对数据包进行控制。
- freezer 子系统： 可以挂起或者恢复 cgroups 中的进程。
- ns 子系统： 可以使不同 cgroups 下面的进程使用不同的 namespace。
- freezer subsystem: 可以挂起或恢复 cgroup 中的 task
- perf_event subsystem :使用后使得 cgroup 中的 task 可以进行统一的性能测试


## 四大功能


1)资源限制：cgroups可以对进程组使用的资源总额进行限制。如设定应用运行时使用内存的上限，一旦超过这个配额就发出OOM（Out of Memory）。

cgroup 主要限制的资源是：

- CPU
- 内存
- 网络
- 磁盘 I/O

2)优先级分配：通过分配的CPU时间片数量及硬盘IO带宽大小，实际上就相当于控制了进程运行的优先级。

3)资源统计：cgroups可以统计系统的资源使用量，如CPU使用时长、内存用量等等，这个功能非常适用于计费。

4)进程控制：cgroups可以对进程组执行挂起、恢复等操作




## cgroup 子资源参数详解

### blkio: 限制设备 IO 访问

{{<figure src="./page_cache_io.png#center" width=800px >}}

blkio是cgroup中的一个子系统，可以用于限制及监控磁盘读写io
blkio控制子系统可以限制进程读写的 IOPS 和吞吐量，但它只能对 Direct I/O 的文件读写进行限速，对 Buffered I/O 的文件读写无法限制
Buffered I/O 指会经过 PageCache 然后再写入到存储设备中。


限制磁盘 IO 有两种方式：权重（weight）和上限（limit）。权重是给不同的应用（或者 cgroup）一个权重值，各个应用按照百分比来使用 IO 资源；上限是直接写死应用读写速率的最大值。

1. 设置 cgroup 访问设备的权重
2. 设置 cgroup 访问设备的限制

```shell
root@node197:~# ll /sys/fs/cgroup/blkio/
-rw-r--r--   1 root root   0 Mar  4 03:00 blkio.throttle.read_bps_device
-rw-r--r--   1 root root   0 Mar  4 03:00 blkio.throttle.read_iops_device
-rw-r--r--   1 root root   0 Mar  4 06:21 blkio.throttle.write_bps_device
-rw-r--r--   1 root root   0 Mar  4 03:00 blkio.throttle.write_iops_device

```
```shell
# 通用格式
echo "<disk-number> <io-value>"  > /sys/fs/cgroup/blkio/<io-type>

# 查看sdb磁盘对应编号为8:16
[root@node189 ~]# ll /dev/block/ | grep sdb
lrwxrwxrwx 1 root root 6 Mar  4 14:29 8:16 -> ../sdb

# 限制sdb磁盘写入带宽为1MB/s
echo "8:16 1048576" >> /sys/fs/cgroup/blkio/blkio.throttle.write_bps_device
# 解除sdb磁盘写入限制
echo "8:16 0" >> /sys/fs/cgroup/blkio/blkio.throttle.write_bps_device

```
- disk-number：指定需要限制的磁盘编号，可通过ll /dev/block/ | grep sdb查看对应磁盘编号，如8:16
- io-value：指定需要限制的io数值（数值为0表示不限制），当指定的文件名称为blkio.throttle.write_bps_device，则表示限制写入带宽，单位为B/s
- io-type：指定需要限制的io类型
- blkio.throttle.write_bps_device：磁盘写入带宽限制
- blkio.throttle.write_iops_device：磁盘写入IOPS限制
- blkio.throttle.read_bps_device：磁盘读取带宽限制
- blkio.throttle.read_iops_device：磁盘读取IOPS限制

```go
// github.com/openebs/lib-csi@v0.8.2/pkg/device/iolimit/utils.go
func SetIOLimits(request *Request) error {
	if !helpers.DirExists(baseCgroupPath) {
		return errors.New(baseCgroupPath + " does not exist")
	}
	// 确认是 cgroup V2
	if err := checkCgroupV2(); err != nil {
		return err
	}
	validRequest, err := validate(request)
	if err != nil {
		return err
	}
	err = setIOLimits(validRequest)
	return err
}


func getIOLimitsStr(deviceNumber *DeviceNumber, ioMax *IOMax) string {
	line := strconv.FormatUint(deviceNumber.Major, 10) + ":" + strconv.FormatUint(deviceNumber.Minor, 10)
	if ioMax.Riops != 0 {
		line += " riops=" + strconv.FormatUint(ioMax.Riops, 10)
	}
	if ioMax.Wiops != 0 {
		line += " wiops=" + strconv.FormatUint(ioMax.Wiops, 10)
	}
	if ioMax.Rbps != 0 {
		line += " rbps=" + strconv.FormatUint(ioMax.Rbps, 10)
	}
	if ioMax.Wbps != 0 {
		line += " wbps=" + strconv.FormatUint(ioMax.Wbps, 10)
	}
	return line
}

func setIOLimits(request *ValidRequest) error {
	line := getIOLimitsStr(request.DeviceNumber, request.IOMax)
	err := os.WriteFile(request.FilePath, []byte(line), 0600)
	return err
}


func validate(request *Request) (*ValidRequest, error) {
	if !helpers.IsValidUUID(request.PodUid) {
		return nil, errors.New("Expected PodUid in UUID format, Got " + request.PodUid)
	}
	podCGPath, err := getPodCGroupPath(request.PodUid, request.ContainerRuntime)
	if err != nil {
		return nil, err
	}
	// io限制路径
	ioMaxFile := podCGPath + "/io.max"
	if !helpers.FileExists(ioMaxFile) {
		return nil, errors.New("io.max file is not present in pod CGroup")
	}
	deviceNumber, err := getDeviceNumber(request.DeviceName)
	if err != nil {
		return nil, errors.New("Device Major:Minor numbers could not be obtained")
	}
	return &ValidRequest{
		FilePath:     ioMaxFile,
		DeviceNumber: deviceNumber,
		IOMax:        request.IOLimit,
	}, nil
}
```

### cpu：限制进程组 CPU 使用

任务使用 CPU 资源有两种调度方式：完全公平调度（CFS，Completely Fair Scheduler）和 实时调度（RT，Real-Time Scheduler）。
前者可以根据权重为任务分配响应的 CPU 时间片，后者能够限制使用 CPU 的核数。

```go
// https://github.com/koordinator-sh/koordinator/blob/632ef287e881ea0a2097e04cef108e46f290258e/pkg/koordlet/util/system/cgroup_resource.go
const (
	CFSBasePeriodValue int64 = 100000
	CFSQuotaMinValue   int64 = 1000 // min value except `-1`
	CPUSharesMinValue  int64 = 2
	CPUSharesMaxValue  int64 = 262144
	CPUWeightMinValue  int64 = 1
	CPUWeightMaxValue  int64 = 10000

	CPUStatName      = "cpu.stat" // CPU 使用的统计数据
	CPUSharesName    = "cpu.shares" // cgroup 使用 CPU 时间的权重值
	CPUCFSQuotaName  = "cpu.cfs_quota_us"
	CPUCFSPeriodName = "cpu.cfs_period_us"
	CPUBVTWarpNsName = "cpu.bvt_warp_ns"
	CPUBurstName     = "cpu.cfs_burst_us"
	CPUTasksName     = "tasks"
	CPUProcsName     = "cgroup.procs"
	CPUThreadsName   = "cgroup.threads"
	CPUMaxName       = "cpu.max"
	CPUMaxBurstName  = "cpu.max.burst"
	CPUWeightName    = "cpu.weight"
	CPUIdleName      = "cpu.idle"

	CPUSetCPUSName          = "cpuset.cpus"
	CPUSetCPUSEffectiveName = "cpuset.cpus.effective"

	CPUAcctStatName           = "cpuacct.stat"
	CPUAcctUsageName          = "cpuacct.usage"
	CPUAcctCPUPressureName    = "cpu.pressure"
	CPUAcctMemoryPressureName = "memory.pressure"
	CPUAcctIOPressureName     = "io.pressure"
)
```

#### CFS 调优参数

设置 CPU 数字的单位都是微秒（microsecond），用 us 表示
```go
// https://github.com/kubernetes/kubernetes/blob/07af1bab707c16c7fde936dca6579002405159ac/vendor/github.com/opencontainers/runc/libcontainer/cgroups/fs/cpu.go

// cgroup v1 接口
func (s *CpuGroup) Set(path string, r *configs.Resources) error {
	if r.CpuShares != 0 {
		shares := r.CpuShares
		if err := cgroups.WriteFile(path, "cpu.shares", strconv.FormatUint(shares, 10)); err != nil {
			return err
		}
		// read it back
		sharesRead, err := fscommon.GetCgroupParamUint(path, "cpu.shares")
		if err != nil {
			return err
		}
		// ... and check
		if shares > sharesRead {
			return fmt.Errorf("the maximum allowed cpu-shares is %d", sharesRead)
		} else if shares < sharesRead {
			return fmt.Errorf("the minimum allowed cpu-shares is %d", sharesRead)
		}
	}

	var period string
	if r.CpuPeriod != 0 {
		period = strconv.FormatUint(r.CpuPeriod, 10)
		if err := cgroups.WriteFile(path, "cpu.cfs_period_us", period); err != nil {
			// Sometimes when the period to be set is smaller
			// than the current one, it is rejected by the kernel
			// (EINVAL) as old_quota/new_period exceeds the parent
			// cgroup quota limit. If this happens and the quota is
			// going to be set, ignore the error for now and retry
			// after setting the quota.
			if !errors.Is(err, unix.EINVAL) || r.CpuQuota == 0 {
				return err
			}
		} else {
			period = ""
		}
	}
	if r.CpuQuota != 0 {
		if err := cgroups.WriteFile(path, "cpu.cfs_quota_us", strconv.FormatInt(r.CpuQuota, 10)); err != nil {
			return err
		}
		if period != "" {
			if err := cgroups.WriteFile(path, "cpu.cfs_period_us", period); err != nil {
				return err
			}
		}
	}
	return s.SetRtSched(path, r)
}
```
- cpu.cfs_quota_us：每个周期 cgroup 中所有任务能使用的 CPU 时间，默认为 -1，表示不限制 CPU 使用。需要配合 cpu.cfs_period_us 一起使用，一般设置为 100000（docker 中设置的值）
- cpu.cfs_period_us：每个周期中 cgroup 任务可以使用的时间周期，如果想要限制 cgroup 任务每秒钟使用 0.5 秒 CPU，可以在 cpu.cfs_quota_us 为 100000 的情况下把它设置为 50000。如果它的值比 cfs_quota_us 大，表明进程可以使用多个核 CPU，比如 200000 表示进程能够使用 2.0 核


- cpu.stat：CPU 使用的统计数据，nr_periods 表示已经过去的时间周期；nr_throttled 表示 cgroup 中任务被限制使用 CPU 的次数（因为超过了规定的上限）；throttled_time 表示被限制的总时间

```go
// https://github.com/kubernetes/kubernetes/blob/07af1bab707c16c7fde936dca6579002405159ac/vendor/github.com/opencontainers/runc/libcontainer/cgroups/fs/cpu.go

// cgroup v1 
func (s *CpuGroup) GetStats(path string, stats *cgroups.Stats) error {
	const file = "cpu.stat"
	f, err := cgroups.OpenFile(path, file, os.O_RDONLY)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		t, v, err := fscommon.ParseKeyValue(sc.Text())
		if err != nil {
			return &parseError{Path: path, File: file, Err: err}
		}
		switch t {
		case "nr_periods":
			stats.CpuStats.ThrottlingData.Periods = v

		case "nr_throttled":
			stats.CpuStats.ThrottlingData.ThrottledPeriods = v

		case "throttled_time":
			stats.CpuStats.ThrottlingData.ThrottledTime = v
		}
	}
	return nil
}
```
```go
// https://github.com/kubernetes/kubernetes/blob/07af1bab707c16c7fde936dca6579002405159ac/vendor/github.com/opencontainers/runc/libcontainer/cgroups/fs2/cpu.go

// cgroup v2 案例统计
func statCpu(dirPath string, stats *cgroups.Stats) error {
	const file = "cpu.stat"
	f, err := cgroups.OpenFile(dirPath, file, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		t, v, err := fscommon.ParseKeyValue(sc.Text())
		if err != nil {
			return &parseError{Path: dirPath, File: file, Err: err}
		}
		switch t {
		case "usage_usec":
			stats.CpuStats.CpuUsage.TotalUsage = v * 1000

		case "user_usec":
			stats.CpuStats.CpuUsage.UsageInUsermode = v * 1000

		case "system_usec":
			stats.CpuStats.CpuUsage.UsageInKernelmode = v * 1000

		case "nr_periods":
			stats.CpuStats.ThrottlingData.Periods = v

		case "nr_throttled":
			stats.CpuStats.ThrottlingData.ThrottledPeriods = v

		case "throttled_usec":
			stats.CpuStats.ThrottlingData.ThrottledTime = v * 1000
		}
	}
	if err := sc.Err(); err != nil {
		return &parseError{Path: dirPath, File: file, Err: err}
	}
	return nil
}
```
- cpu.shares：cgroup 使用 CPU 时间的权重值。如果两个 cgroup 的权重都设置为 100，那么它们里面的任务同时运行时，使用 CPU 的时间应该是一样的；如果把其中一个权重改为 200，那么它能使用的 CPU 时间将是对方的两倍


#### RT 调度模式下的参数

- cpu.rt_period_us：设置一个周期时间，表示多久 cgroup 能够重新分配 CPU 资源
- cpu.rt_runtime_us：设置运行时间，表示在周期时间内 cgroup 中任务能访问 CPU 的时间。这个限制是针对单个 CPU 核数的，如果是多核，需要乘以对应的核数


#### cpu 监控

```go
// https://github.com/kubernetes/kubernetes/blob/761dd3640e4e11741c342fcf5fc869e09901cdb1/vendor/github.com/google/cadvisor/metrics/prometheus.go
func NewPrometheusCollector(i infoProvider, f ContainerLabelsFunc, includedMetrics container.MetricSet, now clock.Clock, opts v2.RequestOptions) *PrometheusCollector {
	if f == nil {
		f = DefaultContainerLabels
	}
	c := &PrometheusCollector{
		infoProvider:        i,
		containerLabelsFunc: f,
		errors: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "container",
			Name:      "scrape_error",
			Help:      "1 if there was an error while getting container metrics, 0 otherwise",
		}),
		containerMetrics: []containerMetric{
			{
				name:      "container_last_seen",
				help:      "Last time a container was seen by the exporter",
				valueType: prometheus.GaugeValue,
				getValues: func(s *info.ContainerStats) metricValues {
					return metricValues{{
						value:     float64(now.Now().Unix()),
						timestamp: now.Now(),
					}}
				},
			},
		},
		includedMetrics: includedMetrics,
		opts:            opts,
	}
	if includedMetrics.Has(container.CpuUsageMetrics) {
		c.containerMetrics = append(c.containerMetrics, []containerMetric{
			{
				name:      "container_cpu_user_seconds_total",
				help:      "Cumulative user cpu time consumed in seconds.",
				valueType: prometheus.CounterValue,
				getValues: func(s *info.ContainerStats) metricValues {
					return metricValues{
						{
							value:     float64(s.Cpu.Usage.User) / float64(time.Second),
							timestamp: s.Timestamp,
						},
					}
				},
			}, {
				name:      "container_cpu_system_seconds_total",
				help:      "Cumulative system cpu time consumed in seconds.",
				valueType: prometheus.CounterValue,
				getValues: func(s *info.ContainerStats) metricValues {
					return metricValues{
						{
							value:     float64(s.Cpu.Usage.System) / float64(time.Second),
							timestamp: s.Timestamp,
						},
					}
				},
			}, {
				name:        "container_cpu_usage_seconds_total",
				help:        "Cumulative cpu time consumed in seconds.",
				valueType:   prometheus.CounterValue,
				extraLabels: []string{"cpu"},
				getValues: func(s *info.ContainerStats) metricValues {
					if len(s.Cpu.Usage.PerCpu) == 0 {
						if s.Cpu.Usage.Total > 0 {
							return metricValues{{
								value:     float64(s.Cpu.Usage.Total) / float64(time.Second),
								labels:    []string{"total"},
								timestamp: s.Timestamp,
							}}
						}
					}
					values := make(metricValues, 0, len(s.Cpu.Usage.PerCpu))
					for i, value := range s.Cpu.Usage.PerCpu {
						if value > 0 {
							values = append(values, metricValue{
								value:     float64(value) / float64(time.Second),
								labels:    []string{fmt.Sprintf("cpu%02d", i)},
								timestamp: s.Timestamp,
							})
						}
					}
					return values
				},
			}, {
				name:      "container_cpu_cfs_periods_total",
				help:      "Number of elapsed enforcement period intervals.",
				valueType: prometheus.CounterValue,
				condition: func(s info.ContainerSpec) bool { return s.Cpu.Quota != 0 },
				getValues: func(s *info.ContainerStats) metricValues {
					return metricValues{
						{
							value:     float64(s.Cpu.CFS.Periods),
							timestamp: s.Timestamp,
						}}
				},
			}, {
				name:      "container_cpu_cfs_throttled_periods_total",
				help:      "Number of throttled period intervals.",
				valueType: prometheus.CounterValue,
				condition: func(s info.ContainerSpec) bool { return s.Cpu.Quota != 0 },
				getValues: func(s *info.ContainerStats) metricValues {
					return metricValues{
						{
							value:     float64(s.Cpu.CFS.ThrottledPeriods),
							timestamp: s.Timestamp,
						}}
				},
			}, {
				name:      "container_cpu_cfs_throttled_seconds_total",
				help:      "Total time duration the container has been throttled.",
				valueType: prometheus.CounterValue,
				condition: func(s info.ContainerSpec) bool { return s.Cpu.Quota != 0 },
				getValues: func(s *info.ContainerStats) metricValues {
					return metricValues{
						{
							value:     float64(s.Cpu.CFS.ThrottledTime) / float64(time.Second),
							timestamp: s.Timestamp,
						}}
				},
			},
		}...)
	}
	
    // ...
	
	return c
}

```

container_cpu_cfs_throttled_periods_total 通过这指标排查.


举个例子，假设一个API服务在响应请求时需要使用A, B两个线程（2个核），分别使用60ms和80ms，其中B线程晚触发20ms，我们看到API服务在100ms后可给出响应：
{{<figure src="./without_cpu_limit.png#center" width=800px >}}


如果CPU limit被设为0.8核，即每100ms内最多使用80ms CPU时间，API服务的线程B会受到一次限流（灰色部分），服务在140ms后响应：
{{<figure src="./limit_0.8_core.png#center" width=800px >}}



如果CPU limit被设为0.6核，即每100ms内最多使用60ms CPU时间，API服务的线程A会受到一次限流（灰色部分），线程B受到两次限流，服务在220ms后响应：
{{<figure src="./limit_0.6_core.png#center" width=800px >}}


### memory：限制内存使用

- memory.limit_in_bytes：cgroup 能使用的内存上限值，默认为字节；也可以添加 k/K、m/M 和 g/G 单位后缀。往文件中写入 -1 来移除设置的上限，表示不对内存做限制
- memory.memsw.limit_in_bytes：cgroup 能使用的内存加 swap 上限，用法和上面一样。写入 -1 来移除上限
- memory.failcnt：任务使用内存量达到 limit_in_bytes 上限的次数
- memory.memsw.failcnt：任务使用内存加 swap 量达到 memsw.limit_in_bytes 上限的次数
- memory.soft_limit_in_bytes：设置内存软上限。如果内存充足， cgroup 中的任务可以用到 memory.limit_in_bytes 设定的内存上限；当时当内存资源不足时，内核会让任务使用的内存不超过 soft_limit_in_bytes 中的值。文件内容的格式和 limit_in_bytes 一样
- memory.swappiness：设置内核 swap out 进程内存（而不是从 page cache 中回收页） 的倾向。默认值为 60，低于 60 表示降低倾向，高于 60 表示增加倾向；如果值高于 100，表示允许内核 swap out 进程地址空间的页。如果值为 0 表示倾向很低，而不是禁止该行为

### net_cls：为网络报文分类
net_cls 子资源能够给网络报文打上一个标记（classid），这样内核的 tc（traffic control）模块就能根据这个标记做流量控制。

net_cls.classid：包含一个整数值。从文件中读取是的十进制，写入的时候需要是十六进制。比如，0x100001 写入到文件中，读取的将是 1048577， ip 命令操作的形式为 10:1。

这个值的格式为 0xAAAABBBB，一共 32 位，分成前后两个部分，前置的 0 可以忽略，因此 0x10001 和 0x00010001 一样，表示为 1:1

## 容器中映射关系
### docker 中资源的表示
```shell
➜  ~ docker run --rm -d  --cpus=2 --memory=2g --name=2c2g redis:alpine 
e420a97835d9692df5b90b47e7951bc3fad48269eb2c8b1fa782527e0ae91c8e
➜  ~ cat /sys/fs/cgroup/system.slice/docker-`docker ps -lq --no-trunc`.scope/cpu.max
200000 100000
➜  ~ cat /sys/fs/cgroup/system.slice/docker-`docker ps -lq --no-trunc`.scope/memory.max
2147483648
➜  ~ 
➜  ~ docker run --rm -d  --cpus=0.5 --memory=0.5g --name=0.5c0.5g redis:alpine
8b82790fe0da9d00ab07aac7d6e4ef2f5871d5f3d7d06a5cdb56daaf9f5bc48e
➜  ~ cat /sys/fs/cgroup/system.slice/docker-`docker ps -lq --no-trunc`.scope/cpu.max       
50000 100000
➜  ~ cat /sys/fs/cgroup/system.slice/docker-`docker ps -lq --no-trunc`.scope/memory.max
536870912
```


### kubernetes 资源的表示
对于CPU
- resource.requests 经过转换之后会写入 cpu.share， 表示这个 cgroups最少可以使用的 CPU,在Kubernetes中一个CPU线程相当于1024 share
- resource.limits 则通过 cpu.cfs_quota_us和cpu.cfs_period_us 两个文件来控制，表示cgroups最多可以使用的 CPU。如果 cgroups 中任务在每 1 秒内有 0.2 秒，可对单独 CPU 进行存取，可以将 cpu.cfs_quota_us 设定为 200000，cpu.cfs_period_us 设定为 1000000。



对于内存

```shell
$ ls -l /sys/fs/cgroup/memory/kubepods/burstable/podfbc202d3-da21-11e8-ab5e-42010a80014b/0a1b22ec1361a97c3511db37a4bae932d41b22264e5b97611748f8b662312574
...
-rw-r--r-- 1 root root 0 Oct 27 19:53 memory.limit_in_bytes
-rw-r--r-- 1 root root 0 Oct 27 19:53 memory.soft_limit_in_bytes
```


```go
// https://github.com/kubernetes/kubernetes/blob/4096c9209cbf20c51d184e83ab6ffa3853bd2ee6/pkg/kubelet/cm/helpers_linux.go

func ResourceConfigForPod(pod *v1.Pod, enforceCPULimits bool, cpuPeriod uint64, enforceMemoryQoS bool) *ResourceConfig {
    // ...

	cpuRequests := int64(0)
	cpuLimits := int64(0)
	memoryLimits := int64(0)
	if request, found := reqs[v1.ResourceCPU]; found {
		cpuRequests = request.MilliValue()
	}
	if limit, found := limits[v1.ResourceCPU]; found {
		cpuLimits = limit.MilliValue()
	}
	if limit, found := limits[v1.ResourceMemory]; found {
		memoryLimits = limit.Value()
	}

	// convert to CFS values
	cpuShares := MilliCPUToShares(cpuRequests)
	cpuQuota := MilliCPUToQuota(cpuLimits, int64(cpuPeriod))

	// quota is not capped when cfs quota is disabled
	if !enforceCPULimits {
		cpuQuota = int64(-1)
	}

	// determine the qos class
	qosClass := v1qos.GetPodQOS(pod)

	// build the result
	result := &ResourceConfig{}
	if qosClass == v1.PodQOSGuaranteed {
		result.CPUShares = &cpuShares
		result.CPUQuota = &cpuQuota
		result.CPUPeriod = &cpuPeriod
		result.Memory = &memoryLimits
	} else if qosClass == v1.PodQOSBurstable {
		result.CPUShares = &cpuShares
		if cpuLimitsDeclared {
			result.CPUQuota = &cpuQuota
			result.CPUPeriod = &cpuPeriod
		}
		if memoryLimitsDeclared {
			result.Memory = &memoryLimits
		}
	} else {
		shares := uint64(MinShares)
		result.CPUShares = &shares
	}
	result.HugePageLimit = hugePageLimits

	if enforceMemoryQoS {
		memoryMin := int64(0)
		if request, found := reqs[v1.ResourceMemory]; found {
			memoryMin = request.Value()
		}
		if memoryMin > 0 {
			result.Unified = map[string]string{
				MemoryMin: strconv.FormatInt(memoryMin, 10),
			}
		}
	}

	return result
}


const (
    // These limits are defined in the kernel:
    // https://github.com/torvalds/linux/blob/0bddd227f3dc55975e2b8dfa7fc6f959b062a2c7/kernel/sched/sched.h#L427-L428
    MinShares = 2
    MaxShares = 262144
    
    SharesPerCPU  = 1024
    MilliCPUToCPU = 1000
    
    // 100000 microseconds is equivalent to 100ms
    QuotaPeriod = 100000
    // 1000 microseconds is equivalent to 1ms
    // defined here:
    // https://github.com/torvalds/linux/blob/cac03ac368fabff0122853de2422d4e17a32de08/kernel/sched/core.c#L10546
    MinQuotaPeriod = 1000
)



// cpu 转换
// MilliCPUToShares converts the milliCPU to CFS shares.
func MilliCPUToShares(milliCPU int64) uint64 {
	if milliCPU == 0 {
		// Docker converts zero milliCPU to unset, which maps to kernel default
		// for unset: 1024. Return 2 here to really match kernel default for
		// zero milliCPU.
		return MinShares
	}
	// Conceptually (milliCPU / milliCPUToCPU) * sharesPerCPU, but factored to improve rounding.
	shares := (milliCPU * SharesPerCPU) / MilliCPUToCPU
	if shares < MinShares {
		return MinShares
	}
	if shares > MaxShares {
		return MaxShares
	}
	return uint64(shares)
}

```



## cgroup v1 与 cgroup v2

最初 cgroups 的版本被称为 v1，这个版本的 cgroups 设计并不友好，理解起来非常困难。
后续的开发工作由 Tejun Heo 接管，他重新设计并重写了 cgroups，新版本被称为 v2，并首次出现在 kernel 4.5 版本。

[cgroup v1与cgroup v2 子系统的区别](https://www.alibabacloud.com/help/zh/alinux/support/differences-between-cgroup-v1-and-cgroup-v2#921d08df2c654)

```shell
# 系统同时挂载了 cgroup 和 cgroup2
ubuntu@VM-16-12-ubuntu:/sys/fs/cgroup$ mount |grep cgroup
tmpfs on /sys/fs/cgroup type tmpfs (ro,nosuid,nodev,noexec,mode=755)
cgroup2 on /sys/fs/cgroup/unified type cgroup2 (rw,nosuid,nodev,noexec,relatime,nsdelegate)
cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
cgroup on /sys/fs/cgroup/hugetlb type cgroup (rw,nosuid,nodev,noexec,relatime,hugetlb)
cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,perf_event)
cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (rw,nosuid,nodev,noexec,relatime,cpu,cpuacct)
cgroup on /sys/fs/cgroup/pids type cgroup (rw,nosuid,nodev,noexec,relatime,pids)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,net_cls,net_prio)
cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,blkio)
cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,freezer)
cgroup on /sys/fs/cgroup/memory type cgroup (rw,nosuid,nodev,noexec,relatime,memory)
cgroup on /sys/fs/cgroup/rdma type cgroup (rw,nosuid,nodev,noexec,relatime,rdma)

# 只有 cpu/io/memory 等少量控制器（大部分还在 cgroup v1 中，系统默认使用 v1）
$ ls -ahlp /sys/fs/cgroup/unified/
total 0
-r--r--r--   1 root root   0 cgroup.controllers
-rw-r--r--   1 root root   0 cgroup.max.depth
-rw-r--r--   1 root root   0 cgroup.max.descendants
-rw-r--r--   1 root root   0 cgroup.procs
-r--r--r--   1 root root   0 cgroup.stat
-rw-r--r--   1 root root   0 cgroup.subtree_control
-rw-r--r--   1 root root   0 cgroup.threads
-rw-r--r--   1 root root   0 cpu.pressure
-r--r--r--   1 root root   0 cpu.stat
drwxr-xr-x   2 root root   0 init.scope/
-rw-r--r--   1 root root   0 io.pressure
-rw-r--r--   1 root root   0 memory.pressure
drwxr-xr-x 121 root root   0 system.slice/
drwxr-xr-x   3 root root   0 user.slice/
```
- cgroup v2 是单一层级树，因此只有一个挂载点（第二行）/sys/fs/cgroup/unified
- cgroup v1 根据控制器类型（cpuset/cpu,cpuacct/hugetlb/...），挂载到不同位置

内核提供了 cgroup_no_v1=allows 配置， 可完全禁用 v1 控制器（强制使用 v2）

Kubernetes 自 v1.25 起 cgroup2 特性正式 stable.


```go
// https://github.com/kubernetes/kubernetes/blob/e599722bc59280bc5899b32957ff088ef97c33fa/vendor/github.com/opencontainers/runc/libcontainer/cgroups/utils.go

const (
    CgroupProcesses   = "cgroup.procs"
    unifiedMountpoint = "/sys/fs/cgroup"
    hybridMountpoint  = "/sys/fs/cgroup/unified"
)


// 判断是否是 cgroup2
func IsCgroup2UnifiedMode() bool {
	isUnifiedOnce.Do(func() {
		var st unix.Statfs_t
		err := unix.Statfs(unifiedMountpoint, &st)
		if err != nil {
			if os.IsNotExist(err) && userns.RunningInUserNS() {
				// ignore the "not found" error if running in userns
				logrus.WithError(err).Debugf("%s missing, assuming cgroup v1", unifiedMountpoint)
				isUnified = false
				return
			}
			panic(fmt.Sprintf("cannot statfs cgroup root: %s", err))
		}
		isUnified = st.Type == unix.CGROUP2_SUPER_MAGIC
	})
	return isUnified
}
```


## 工具

```shell
$ sudo apt-get install cgroup-tools
```
- 查看所有的 cgroup：lscgroup
- 查看所有支持的子系统：lssubsys -a
- 查看所有子系统挂载的位置： lssubsys –m
- 查看单个子系统（如 memory）挂载位置：lssubsys –m memory


## 参考

- https://www.kernel.org/doc/html/v5.10/admin-guide/cgroup-v2.html
- [一篇搞懂容器技术的基石: cgroup](https://zhuanlan.zhihu.com/p/434731896)
- [docker 容器基础技术：linux cgroup 简介](https://cizixs.com/2017/08/25/linux-cgroup/)
- [详解Cgroup V2](https://zorrozou.github.io/docs/%E8%AF%A6%E8%A7%A3Cgroup%20V2.html)
- [k8s CPU limit和throttling的迷思](https://zhuanlan.zhihu.com/p/433065108)
- [Pod的Qos类](https://blog.csdn.net/weixin_43539320/article/details/137913942)