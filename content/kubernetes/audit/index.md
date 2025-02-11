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

```yaml
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
	// ..
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


启动设置初始化 
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

	// 2. 构建 log backend , 基于 lumberjack 实现
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

- Log 后端，将事件写入到文件系统
- Webhook 后端，将事件发送到外部 HTTP API



## 参考
- [Kubernetes 审计（Auditing）功能详解](https://www.cnblogs.com/zhangmingcheng/p/16539514.html)