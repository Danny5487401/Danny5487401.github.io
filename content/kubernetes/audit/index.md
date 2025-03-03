---
title: "Audit"
date: 2025-02-11T10:32:34+08:00
summary: "审计及实现原理"
categories:
  - kubernetes
  - audit
tags:
  - audit
---

审计（Auditing） 功能提供了与安全相关的、按时间顺序排列的记录集， 记录每个用户、使用 Kubernetes API 的应用以及控制面自身引发的活动（所有访问kube-apiserver服务的客户端）


审计功能使得集群管理员能够回答以下问题：

- 发生了什么？
- 什么时候发生的？
- 谁触发的？
- 活动发生在哪个（些）对象上？
- 在哪观察到的？
- 它从哪触发的？
- 活动的后续处理行为是什么？
  
每个请求在不同执行阶段都会生成审计事件；这些审计事件会根据特定策略被预处理并写入后端。策略确定要记录的内容，当前的后端支持日志文件和 webhook。


## 审计策略配置

```shell
$ cat /etc/kubernetes/audit/audit-policy.yaml
apiVersion: audit.k8s.io/v1 # 这是必填项。
kind: Policy
# 不要在 RequestReceived 阶段为任何请求生成审计事件。
omitStages:
  - "RequestReceived"
rules:
  # 在日志中用 RequestResponse 级别记录 Pod 变化。
  - level: RequestResponse
    resources:
    - group: ""
      # 资源 "pods" 不匹配对任何 Pod 子资源的请求，
      # 这与 RBAC 策略一致。
      resources: ["pods"]
  # 在日志中按 Metadata 级别记录 "pods/log"、"pods/status" 请求
  - level: Metadata
    resources:
    - group: ""
      resources: ["pods/log", "pods/status"]
 
  # 不要在日志中记录对名为 "controller-leader" 的 configmap 的请求。
  - level: None
    resources:
    - group: ""
      resources: ["configmaps"]
      resourceNames: ["controller-leader"]
 
  # 不要在日志中记录由 "system:kube-proxy" 发出的对端点或服务的监测请求。
  - level: None
    users: ["system:kube-proxy"]
    verbs: ["watch"]
    resources:
    - group: "" # core API 组
      resources: ["endpoints", "services"]
 
  # 不要在日志中记录对某些非资源 URL 路径的已认证请求。
  - level: None
    userGroups: ["system:authenticated"]
    nonResourceURLs:
    - "/api*" # 通配符匹配。
    - "/version"
 
  # 在日志中记录 kube-system 中 configmap 变更的请求消息体。
  - level: Request
    resources:
    - group: "" # core API 组
      resources: ["configmaps"]
    # 这个规则仅适用于 "kube-system" 名字空间中的资源。
    # 空字符串 "" 可用于选择非名字空间作用域的资源。
    namespaces: ["kube-system"]
 
  # 在日志中用 Metadata 级别记录所有其他名字空间中的 configmap 和 secret 变更。
  - level: Metadata
    resources:
    - group: "" # core API 组
      resources: ["secrets", "configmaps"]
 
  # 在日志中以 Request 级别记录所有其他 core 和 extensions 组中的资源操作。
  - level: Request
    resources:
    - group: "" # core API 组
    - group: "extensions" # 不应包括在内的组版本。
 
  # 一个抓取所有的规则，将在日志中以 Metadata 级别记录所有其他请求。
  - level: Metadata
    # 符合此规则的 watch 等长时间运行的请求将不会
    # 在 RequestReceived 阶段生成审计事件。
    omitStages:
      - "RequestReceived"
```

审计策略定义了关于应记录哪些事件以及应包含哪些数据的规则。 审计策略对象结构定义在 audit.k8s.io API 组。 处理事件时，将按顺序与规则列表进行比较。第一个匹配规则设置事件的审计级别（Audit Level）。已定义的审计级别有：
```go
// Level defines the amount of information logged during auditing
type Level string

// Valid audit levels
const (
	// 符合这条规则的日志将不会记录
	LevelNone Level = "None"
	//  记录请求的元数据（请求的用户、时间戳、资源、动词等等）， 但是不记录请求或者响应的消息体。
	LevelMetadata Level = "Metadata"
	// 记录事件的元数据和请求的消息体，但是不记录响应的消息体。 这不适用于非资源类型的请求。
	LevelRequest Level = "Request"
	// 记录事件的元数据，请求和响应的消息体。这不适用于非资源类型的请求。
	LevelRequestResponse Level = "RequestResponse"
)

```


"level": "Request" 案例
```json

{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "Request",
  "auditID": "a0476a61-8a54-4013-b150-98dcc007a449",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/kube-system/pods?limit=500",
  "verb": "list",
  "user": {
    "username": "admin",
    "groups": [
      "system:masters",
      "system:authenticated"
    ]
  },
  "sourceIPs": [
    "172.16.7.30"
  ],
  "userAgent": "kubectl/v1.31.2 (linux/amd64) kubernetes/5864a46",
  "objectRef": {
    "resource": "pods",
    "namespace": "kube-system",
    "apiVersion": "v1"
  },
  "responseStatus": {
    "metadata": {

    },
    "code": 200
  },
  "requestReceivedTimestamp": "2025-02-28T09:30:30.462366Z",
  "stageTimestamp": "2025-02-28T09:30:30.468161Z",
  "annotations": {
    "authorization.k8s.io/decision": "allow",
    "authorization.k8s.io/reason": ""
  }
}
```
"level": "Metadata"  例子
```json
{
    "kind": "Event",
    "apiVersion": "audit.k8s.io/v1",
    "level": "Metadata",
    "auditID": "9a70bf05-fd9a-4fd6-bbc7-2b2e863b2c82",
    "stage": "ResponseComplete",
    "requestURI": "/api/v1/namespaces/kube-system/pods/kubernetes-dashboard-5945846449-rrb2r/log?container=kubernetes-dashboard",
    "verb": "get",
    "user": {
        "username": "admin",
        "groups": [
            "system:masters",
            "system:authenticated"
        ]
    },
    "sourceIPs": [
        "172.16.7.30"
    ],
    "userAgent": "kubectl/v1.31.2 (linux/amd64) kubernetes/5864a46",
    "objectRef": {
        "resource": "pods",
        "namespace": "kube-system",
        "name": "kubernetes-dashboard-5945846449-rrb2r",
        "apiVersion": "v1",
        "subresource": "log"
    },
    "responseStatus": {
        "metadata": {

        },
        "code": 200
    },
    "requestReceivedTimestamp": "2025-02-28T09:33:23.359308Z",
    "stageTimestamp": "2025-02-28T09:33:23.387632Z",
    "annotations": {
        "authorization.k8s.io/decision": "allow",
        "authorization.k8s.io/reason": ""
    }
}
```



每个请求都可被记录其相关的阶段（stage）。已定义的阶段有：
```go
// https://github.com/kubernetes/kubernetes/blob/3fa086bcded1dfb7c4889ee28b95535d056b3408/staging/src/k8s.io/apiserver/pkg/apis/audit/types.go

// Stage defines the stages in request handling that audit events may be generated.
type Stage string

// Valid audit stages.
const (
	// 此阶段对应审计处理器接收到请求后，并且在委托给处理器处理之前生成的事件。
	StageRequestReceived Stage = "RequestReceived"
	// 在响应消息的头部发送后，响应消息体发送前生成的事件。 只有长时间运行的请求（例如 watch）才会生成这个阶段。
	StageResponseStarted Stage = "ResponseStarted"
	// 当响应消息体完成并且没有更多数据需要传输的时候。
	StageResponseComplete Stage = "ResponseComplete"
	// 当 panic 发生时生成。
	StagePanic Stage = "Panic"
)

```


```go
func DefaultBuildHandlerChain(apiHandler http.Handler, c *Config) http.Handler {
	// ...
	
	handler = filterlatency.TrackCompleted(handler)
	handler = genericapifilters.WithAudit(handler, c.AuditBackend, c.AuditPolicyRuleEvaluator, c.LongRunningFunc)
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "audit")

	// 只拦截身份验证失败的请求
	failedHandler := genericapifilters.Unauthorized(c.Serializer)
	failedHandler = genericapifilters.WithFailedAuthenticationAudit(failedHandler, c.AuditBackend, c.AuditPolicyRuleEvaluator)

    failedHandler = filterlatency.TrackCompleted(failedHandler)
    handler = filterlatency.TrackCompleted(handler)
    handler = genericapifilters.WithAuthentication(handler, c.Authentication.Authenticator, failedHandler, c.Authentication.APIAudiences, c.Authentication.RequestHeaderConfig)
	// ...
}
```


处理流程
```go
func WithAudit(handler http.Handler, sink audit.Sink, policy audit.PolicyRuleEvaluator, longRunningCheck request.LongRunningRequestCheck) http.Handler {
	// 开启k8s原生审计功能必须配置审计策略和审计后端否则不会执行审计过滤器逻辑
	if sink == nil || policy == nil {
		return handler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// 从审计策略文件中获取当前请求的审计策略级别、创建审计事件对象并将审计事件对象放到context中
		ac, err := evaluatePolicyAndCreateAuditEvent(req, policy)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("failed to create audit event: %v", err))
			responsewriters.InternalError(w, req, errors.New("failed to create audit event"))
			return
		}

		// 如果当前请求的审计策略为None，则不需要审计
		if ac == nil || ac.Event == nil {
			handler.ServeHTTP(w, req)
			return
		}
		ev := ac.Event

		ctx := req.Context()
		omitStages := ac.RequestAuditConfig.OmitStages
        // RequestReceived阶段：此阶段对应审计处理器接收到请求后，并且在委托给处理器处理之前生成的事件。
		ev.Stage = auditinternal.StageRequestReceived
		if processed := processAuditEvent(ctx, sink, ev, omitStages); !processed { // 生成审计事件并输出到对应后端
			audit.ApiserverAuditDroppedCounter.WithContext(ctx).Inc()
			responsewriters.InternalError(w, req, errors.New("failed to store audit event"))
			return
		}

		// intercept the status code
		var longRunningSink audit.Sink
		if longRunningCheck != nil {
			ri, _ := request.RequestInfoFrom(ctx)
			if longRunningCheck(req, ri) {
				longRunningSink = sink
			}
		}
		respWriter := decorateResponseWriter(ctx, w, ev, longRunningSink, omitStages)

		// send audit event when we leave this func, either via a panic or cleanly. In the case of long
		// running requests, this will be the second audit event.
		defer func() {
            // ...
			
			// ResponseStarted阶段： 在响应消息的头部发送后，响应消息体发送前生成的事件。 只有长时间运行的请求（例如 watch）才会生成这个阶段。
			if ev.ResponseStatus == nil && longRunningSink != nil {
                ev.ResponseStatus = fakedSuccessStatus
                ev.Stage = auditinternal.StageResponseStarted
                processAuditEvent(ctx, longRunningSink, ev, omitStages)
            }
			// ResponseComplete阶段： 当响应消息体完成并且没有更多数据需要传输的时候。
			ev.Stage = auditinternal.StageResponseComplete
			
			// 生成审计事件并输出到对应后端
			processAuditEvent(ctx, sink, ev, omitStages)
		}()
		handler.ServeHTTP(respWriter, req)
	})
}

```

```go
func evaluatePolicyAndCreateAuditEvent(req *http.Request, policy audit.PolicyRuleEvaluator) (*audit.AuditContext, error) {
	ctx := req.Context()
	ac := audit.AuditContextFrom(ctx)
	if ac == nil {
		// Auditing not enabled.
		return nil, nil
	}

	// 基于requestInfo组织AttributesRecord结构体对象存放当前请求信息
	attribs, err := GetAuthorizerAttributes(ctx)
	if err != nil {
		return ac, fmt.Errorf("failed to GetAuthorizerAttributes: %v", err)
	}

	rac := policy.EvaluatePolicyRule(attribs)
	audit.ObservePolicyLevel(ctx, rac.Level)
	ac.RequestAuditConfig = rac
	if rac.Level == auditinternal.LevelNone {
		// 如果当前请求的审计策略为None，则不需要审计
		return ac, nil
	}

	requestReceivedTimestamp, ok := request.ReceivedTimestampFrom(ctx)
	if !ok {
		requestReceivedTimestamp = time.Now()
	}
	ev, err := audit.NewEventFromRequest(req, requestReceivedTimestamp, rac.Level, attribs)
	if err != nil {
		return nil, fmt.Errorf("failed to complete audit event from request: %v", err)
	}

	ac.Event = ev

	return ac, nil
}

```

匹配
```go
func (p *policyRuleEvaluator) EvaluatePolicyRule(attrs authorizer.Attributes) auditinternal.RequestAuditConfig {
	for _, rule := range p.Rules {
		if ruleMatches(&rule, attrs) {
			return auditinternal.RequestAuditConfig{
				Level:             rule.Level,
				OmitStages:        rule.OmitStages,
				OmitManagedFields: isOmitManagedFields(&rule, p.OmitManagedFields),
			}
		}
	}

	return auditinternal.RequestAuditConfig{
		Level:             DefaultAuditLevel,
		OmitStages:        p.OmitStages,
		OmitManagedFields: p.OmitManagedFields,
	}
}
```


1. 开启k8s原生审计功能必须配置审计策略和审计后端否则不会执行审计过滤器逻辑。
2. 审计过滤器会过滤客户端的每一个请求，通过当前请求信息组织AttributesRecord结构体对象，然后基于AttributesRecord结构体对象和审计策略配置文件中的规则做比对，返回当前请求的审计策略级别。如果审计策略配置文件中没有当前请求对应的规则的话，或者当前请求的策略级别为None话，则当前请求不需要审计。
3. 基于请求信息、审计策略、AttributesRecord结构体对象等信息生成审计事件对象，并将审计事件对象放到context中。
4. 基于审计策略配置文件中的omitStages配置（不配置omitStages的话默认RequestReceived、ResponseStarted、ResponseComplete这三个阶段都会产生审计事件），在保留的审计阶段生成审计事件并输出到对应后端


audit 选项初始化 
```go
func NewAuditOptions() *AuditOptions {
	return &AuditOptions{
		WebhookOptions: AuditWebhookOptions{
			InitialBackoff: pluginwebhook.DefaultInitialBackoffDelay,
			BatchOptions: AuditBatchOptions{
				Mode:        ModeBatch,
				BatchConfig: defaultWebhookBatchConfig(),
			},
			TruncateOptions:    NewAuditTruncateOptions(),
			GroupVersionString: "audit.k8s.io/v1",
		},
		LogOptions: AuditLogOptions{
			Format: pluginlog.FormatJson,
			BatchOptions: AuditBatchOptions{
				Mode:        ModeBlocking,
				BatchConfig: defaultLogBatchConfig(),
			},
			TruncateOptions:    NewAuditTruncateOptions(),
			GroupVersionString: "audit.k8s.io/v1",
		},
	}
}
```
添加配置选项
```go
func (o *AuditOptions) AddFlags(fs *pflag.FlagSet) {
	if o == nil {
		return
	}

	fs.StringVar(&o.PolicyFile, "audit-policy-file", o.PolicyFile,
		"Path to the file that defines the audit policy configuration.")

	// 添加log 后端flag
	o.LogOptions.AddFlags(fs)
	o.LogOptions.BatchOptions.AddFlags(pluginlog.PluginName, fs)
	o.LogOptions.TruncateOptions.AddFlags(pluginlog.PluginName, fs)
	
	// 添加webhook 后端 flag
	o.WebhookOptions.AddFlags(fs)
	o.WebhookOptions.BatchOptions.AddFlags(pluginwebhook.PluginName, fs)
	o.WebhookOptions.TruncateOptions.AddFlags(pluginwebhook.PluginName, fs)
}


```


```go
func (o *AuditOptions) ApplyTo(
	c *server.Config,
) error {
	if o == nil {
		return nil
	}
	if c == nil {
		return fmt.Errorf("server config must be non-nil")
	}

	// 1. 构建 policy 解析器
	evaluator, err := o.newPolicyRuleEvaluator()
	if err != nil {
		return err
	}

	// 2. 构建 log backend, 基于 lumberjack 实现
	var logBackend audit.Backend
	w, err := o.LogOptions.getWriter()


	// 3. Build webhook backend
	var webhookBackend audit.Backend
	if o.WebhookOptions.enabled() {
		if evaluator == nil {
			klog.V(2).Info("No audit policy file provided, no events will be recorded for webhook backend")
		} else {
			if c.EgressSelector != nil {
				var egressDialer utilnet.DialFunc
				egressDialer, err = c.EgressSelector.Lookup(egressselector.ControlPlane.AsNetworkContext())
				if err != nil {
					return err
				}
				webhookBackend, err = o.WebhookOptions.newUntruncatedBackend(egressDialer)
			} else {
				webhookBackend, err = o.WebhookOptions.newUntruncatedBackend(nil)
			}
			if err != nil {
				return err
			}
		}
	}

	groupVersion, err := schema.ParseGroupVersion(o.WebhookOptions.GroupVersionString)
	if err != nil {
		return err
	}

	// 4. Apply dynamic options.
	var dynamicBackend audit.Backend
	if webhookBackend != nil {
		// if only webhook is enabled wrap it in the truncate options
		dynamicBackend = o.WebhookOptions.TruncateOptions.wrapBackend(webhookBackend, groupVersion)
	}

	// 5. Set the policy rule evaluator
	c.AuditPolicyRuleEvaluator = evaluator

	// 6. Join the log backend with the webhooks
	c.AuditBackend = appendBackend(logBackend, dynamicBackend)

	if c.AuditBackend != nil {
		klog.V(2).Infof("Using audit backend: %s", c.AuditBackend)
	}
	return nil
}
```

## 审计后端
审计后端实现将审计事件导出到外部存储。Kube-apiserver 默认提供两个后端：

- Log 后端: 将事件以 JSONlines 格式的文件事件写入到文件系统
- Webhook 后端: 将事件发送到外部 HTTP API





### 方式一: 事件写入到文件系统,然后再用 filebeat 收集
```shell
# 在spec.containers.command 最后新增
    # 配置审计日志策略的文件路径
    - --audit-policy-file=/etc/kubernetes/audit/audit-policy.yaml
    # 指定审计日志最长的保存周期，为7天
    - --audit-log-maxage=7
    # 指定单个审计日志的最大内存容量，为100 MB
    - --audit-log-maxsize=100
    # 指定审计日志的输出路径
    - --audit-log-path=/var/log/apiserver/audit.log
```

```go
func (o *AuditLogOptions) AddFlags(fs *pflag.FlagSet) {
	// 指定审计日志的输出路径
	fs.StringVar(&o.Path, "audit-log-path", o.Path,
		"If set, all requests coming to the apiserver will be logged to this file.  '-' means standard out.")
	// 指定历史审计日志的最大保存天数，以日志文件名中的时间戳为准。
	fs.IntVar(&o.MaxAge, "audit-log-maxage", o.MaxAge,
		"The maximum number of days to retain old audit log files based on the timestamp encoded in their filename.")
	// 指定历史审计日志的最大保存数量
	fs.IntVar(&o.MaxBackups, "audit-log-maxbackup", o.MaxBackups,
		"The maximum number of old audit log files to retain. Setting a value of 0 will mean there's no restriction on the number of files.")
	
	// 指定审计日志流转前的最大大小（单位：MB）。
	fs.IntVar(&o.MaxSize, "audit-log-maxsize", o.MaxSize,
		"The maximum size in megabytes of the audit log file before it gets rotated.")
	
	// 指定存储审计日志的格式。legacy 表示每个事件记录 1 行文本；json 表示以结构化 json 格式记录。目前仅支持 legacy 和 json（默认值：json）
	fs.StringVar(&o.Format, "audit-log-format", o.Format,
		"Format of saved audits. \"legacy\" indicates 1-line text format for each event."+
			" \"json\" indicates structured json format. Known formats are "+
			strings.Join(pluginlog.AllowedFormats, ",")+".")
	fs.StringVar(&o.GroupVersionString, "audit-log-version", o.GroupVersionString,
		"API group and version used for serializing audit events written to log.")
	
	// 是否用gzip压缩
	fs.BoolVar(&o.Compress, "audit-log-compress", o.Compress, "If set, the rotated log files will be compressed using gzip.")
}
```

下面批处理和日志条目截断相关两种后端都有的选项
```go
// 批处理相关 
func (o *AuditBatchOptions) AddFlags(pluginName string, fs *pflag.FlagSet) {
	// 指定发送审计事件的策略。blocking 表示发送事件时阻塞服务器响应；batch 表示在后端异步缓冲和写入事件。目前仅支持 batch 和 blocking（默认值：blocking）。
	fs.StringVar(&o.Mode, fmt.Sprintf("audit-%s-mode", pluginName), o.Mode,
		"Strategy for sending audit events. Blocking indicates sending events should block"+
			" server responses. Batch causes the backend to buffer and write events"+
			" asynchronously. Known modes are "+strings.Join(AllowedModes, ",")+".")
	// 指定存储批处理和写入事件的缓冲区字节数（默认值：10000）。只在批处理模式下使用。
	fs.IntVar(&o.BatchConfig.BufferSize, fmt.Sprintf("audit-%s-batch-buffer-size", pluginName),
		o.BatchConfig.BufferSize, "The size of the buffer to store events before "+
			"batching and writing. Only used in batch mode.")
	// 指定一个批处理的最大长度（默认值：1）。只在批处理模式下使用。
	fs.IntVar(&o.BatchConfig.MaxBatchSize, fmt.Sprintf("audit-%s-batch-max-size", pluginName),
		o.BatchConfig.MaxBatchSize, "The maximum size of a batch. Only used in batch mode.")
	// 指定尚未达到最大值的批处理的强制写入等待时间。只在批处理模式下使用。
	fs.DurationVar(&o.BatchConfig.MaxBatchWait, fmt.Sprintf("audit-%s-batch-max-wait", pluginName),
		o.BatchConfig.MaxBatchWait, "The amount of time to wait before force writing the "+
			"batch that hadn't reached the max size. Only used in batch mode.")
	// 指定是否启用 batching throttling。只在批处理模式下使用。
	fs.BoolVar(&o.BatchConfig.ThrottleEnable, fmt.Sprintf("audit-%s-batch-throttle-enable", pluginName),
		o.BatchConfig.ThrottleEnable, "Whether batching throttling is enabled. Only used in batch mode.")
	// 设定每秒内可执行的批处理的最大平均数。只在批处理模式下使用。
	fs.Float32Var(&o.BatchConfig.ThrottleQPS, fmt.Sprintf("audit-%s-batch-throttle-qps", pluginName),
		o.BatchConfig.ThrottleQPS, "Maximum average number of batches per second. "+
			"Only used in batch mode.")
	// 指定在未使用 ThrottleQPS 时同时发送请求的最大数量。只在批处理模式下使用。
	fs.IntVar(&o.BatchConfig.ThrottleBurst, fmt.Sprintf("audit-%s-batch-throttle-burst", pluginName),
		o.BatchConfig.ThrottleBurst, "Maximum number of requests sent at the same "+
			"moment if ThrottleQPS was not utilized before. Only used in batch mode.")
}

// 日志条目截断相关
func (o *AuditTruncateOptions) AddFlags(pluginName string, fs *pflag.FlagSet) {
	// 是否弃用事件和批次的截断处理。
	fs.BoolVar(&o.Enabled, fmt.Sprintf("audit-%s-truncate-enabled", pluginName),
		o.Enabled, "Whether event and batch truncating is enabled.")
	// 向下层后端发送的各批次的最大字节数。
	fs.Int64Var(&o.TruncateConfig.MaxBatchSize, fmt.Sprintf("audit-%s-truncate-max-batch-size", pluginName),
		o.TruncateConfig.MaxBatchSize, "Maximum size of the batch sent to the underlying backend. "+
			"Actual serialized size can be several hundreds of bytes greater. If a batch exceeds this limit, "+
			"it is split into several batches of smaller size.")
	// 向下层后端发送的审计事件的最大字节数。
	fs.Int64Var(&o.TruncateConfig.MaxEventSize, fmt.Sprintf("audit-%s-truncate-max-event-size", pluginName),
		o.TruncateConfig.MaxEventSize, "Maximum size of the audit event sent to the underlying backend. "+
			"If the size of an event is greater than this number, first request and response are removed, and "+
			"if this doesn't reduce the size enough, event is discarded.")
}
```


### 方式二: wewhook 后端
```shell
--audit-policy-file=/etc/kubernetes/audit-policy.yaml   #审计策略文件
--audit-webhook-config-file=/etc/kubernetes/audit/audit-webhook.yaml    #审计配置文件
```

```shell
$ cat  /etc/kubernetes/audit/audit-webhook.yaml
apiVersion: v1
kind: Config
clusters:
- name: kube-auditing
  cluster:
    server: https://{ip}:443/audit/webhook/event      #指定webhook服务端地址
    insecure-skip-tls-verify: true
contexts:
- context:
    cluster: kube-auditing
    user: ""
  name: default-context
current-context: default-context
preferences: {}
users: []
```


```go
func (o *AuditWebhookOptions) AddFlags(fs *pflag.FlagSet) {
	// 指定 kubeconfig 格式的配置文件的路径。该文件设定了审计 webhook 配置
	fs.StringVar(&o.ConfigFile, "audit-webhook-config-file", o.ConfigFile,
		"Path to a kubeconfig formatted file that defines the audit webhook configuration.")
	// 指定重试第一个失败请求之前等待的时间（默认值：10s）。
	fs.DurationVar(&o.InitialBackoff, "audit-webhook-initial-backoff",
		o.InitialBackoff, "The amount of time to wait before retrying the first failed request.")
	fs.DurationVar(&o.InitialBackoff, "audit-webhook-batch-initial-backoff",
		o.InitialBackoff, "The amount of time to wait before retrying the first failed request.")
	fs.MarkDeprecated("audit-webhook-batch-initial-backoff",
		"Deprecated, use --audit-webhook-initial-backoff instead.")
	fs.StringVar(&o.GroupVersionString, "audit-webhook-version", o.GroupVersionString,
		"API group and version used for serializing audit events written to webhook.")
}

```

发送流程

```go
// https://github.com/kubernetes/kubernetes/blob/788b3c3bc3694ae1b28aac31616bd53464e460a1/staging/src/k8s.io/apiserver/plugin/pkg/audit/webhook/webhook.go
func (b *backend) ProcessEvents(ev ...*auditinternal.Event) bool {
	if err := b.processEvents(ev...); err != nil {
		audit.HandlePluginError(b.String(), err, ev...)
		return false
	}
	return true
}

func (b *backend) processEvents(ev ...*auditinternal.Event) error {
	var list auditinternal.EventList
	for _, e := range ev {
		list.Items = append(list.Items, *e)
	}
	return b.w.WithExponentialBackoff(context.Background(), func() rest.Result {
		ctx, span := tracing.Start(context.Background(), "Call Audit Events webhook",
			attribute.String("name", b.name),
			attribute.Int("event-count", len(list.Items)),
		)
		// Only log audit webhook traces that exceed a 25ms per object limit plus a 50ms
		// request overhead allowance. The high per object limit used here is primarily to
		// allow enough time for the serialization/deserialization of audit events, which
		// contain nested request and response objects plus additional event fields.
		defer span.End(time.Duration(50+25*len(list.Items)) * time.Millisecond)
		return b.w.RestClient.Post().Body(&list).Do(ctx)
	}).Error()
}
```




## 监控及调整

- apiserver_audit_event_total 包含所有暴露的审计事件数量的指标。
- apiserver_audit_error_total 在暴露时由于发生错误而被丢弃的事件的数量

### 参数调整
需要设置参数以适应 API 服务器上的负载。
上线前通过指标 sum(irate(apiserver_request_total[$interval])) 查看 qps .
如果 kube-apiserver 每秒收到 1000 个请求，并且每个请求仅在 ResponseStarted 和 ResponseComplete 阶段进行审计，则应该考虑每秒生成约 2000 个审计事件.

## 应用
- 示例1：对容器执行命令时告警: kubectl exec 进入到容器内部执行的命令的审计


## 参考
- [官方 zh 文档](https://kubernetes.io/zh-cn/docs/tasks/debug/debug-cluster/audit/)
- [Kubernetes 审计（Auditing）功能详解](https://www.cnblogs.com/zhangmingcheng/p/16539514.html)