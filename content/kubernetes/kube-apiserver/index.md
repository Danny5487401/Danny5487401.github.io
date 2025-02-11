---
title: "Kube ApiServer"
date: 2024-09-16T13:33:22+08:00
summary: "kube api-server 核心功能是提供了kubernetes各类资源对象（pod、RC 、service等）的增、删、改、查以及watch等HTTP Rest接口."
categories:
  - kubernetes
authors:
  - Danny

tags:
  - k8s
  - kube-apiserver
  - 源码
---


apiserver 核心职责

- 提供Kubernetes API
- 代理集群组件，比如Kubernetes dashboard、流式日志、kubectl exec 会话
- 缓存etcd 数据


Kubernetes API是一个HTTP形式的API，JSON格式是它主要的序列化架构。同时它也支持协议缓冲区（Protocol  Buffers）的形式，这种形式主要是用在集群内通信中。

出于可扩展性原因考虑，Kubernetes可支持多个API版本，通过不同的API路径的方式区分。比如/api/v1 和 /apis/extensions/v1beta1，不同的API版本代表了这个API处于不同的版本稳定性阶段。


```shell
# 起一个免认证代理
✗ kubectl proxy                                                  
Starting to serve on 127.0.0.1:8001
✗ curl  http://127.0.0.1:8001/apis/batch/v1   
{
  "kind": "APIResourceList",
  "apiVersion": "v1",
  "groupVersion": "batch/v1",
  "resources": [
    {
      "name": "cronjobs",
      "singularName": "",
      "namespaced": true,
      "kind": "CronJob",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "shortNames": [
        "cj"
      ],
      "categories": [
        "all"
      ],
      "storageVersionHash": "sd5LIXh4Fjs="
    },
    {
      "name": "cronjobs/status",
      "singularName": "",
      "namespaced": true,
      "kind": "CronJob",
      "verbs": [
        "get",
        "patch",
        "update"
      ]
    },
    {
      "name": "jobs",
      "singularName": "",
      "namespaced": true,
      "kind": "Job",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "categories": [
        "all"
      ],
      "storageVersionHash": "mudhfqk/qZY="
    },
    {
      "name": "jobs/status",
      "singularName": "",
      "namespaced": true,
      "kind": "Job",
      "verbs": [
        "get",
        "patch",
        "update"
      ]
    }
  ]
}
```


## 架构解析

{{<figure src="./apiserver-structure.png#center" width=800px >}}

Kubernetes API Server 从上到下可以分为四层：接口层，访问控制层，注册表层和数据库层。

### API请求流过程


当API Server接收到一个HTTP的Kubernetes API请求时，它主要处理流程如下所示：

{{<figure src="./api-procedure.png#center" width=800px >}}

1. HTTP 请求通过一组定义在DefaultBuildHandlerChain()（config.go）函数中的过滤处理函数处理，并进行相关操作。
这些过滤处理函数将HTTP请求处理后存到中ctx.RequestInfo，比如用户的相关认证信息，或者相应的HTTP请求返回码。
```go
func DefaultBuildHandlerChain(apiHandler http.Handler, c *Config) http.Handler {
	handler := filterlatency.TrackCompleted(apiHandler)
	handler = genericapifilters.WithAuthorization(handler, c.Authorization.Authorizer, c.Serializer)
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "authorization")

	if c.FlowControl != nil {
		workEstimatorCfg := flowcontrolrequest.DefaultWorkEstimatorConfig()
		requestWorkEstimator := flowcontrolrequest.NewWorkEstimator(
			c.StorageObjectCountTracker.Get, c.FlowControl.GetInterestedWatchCount, workEstimatorCfg, c.FlowControl.GetMaxSeats)
		handler = filterlatency.TrackCompleted(handler)
		handler = genericfilters.WithPriorityAndFairness(handler, c.LongRunningFunc, c.FlowControl, requestWorkEstimator)
		handler = filterlatency.TrackStarted(handler, c.TracerProvider, "priorityandfairness")
	} else {
		handler = genericfilters.WithMaxInFlightLimit(handler, c.MaxRequestsInFlight, c.MaxMutatingRequestsInFlight, c.LongRunningFunc)
	}

	handler = filterlatency.TrackCompleted(handler)
	handler = genericapifilters.WithImpersonation(handler, c.Authorization.Authorizer, c.Serializer)
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "impersonation")

	handler = filterlatency.TrackCompleted(handler)
	handler = genericapifilters.WithAudit(handler, c.AuditBackend, c.AuditPolicyRuleEvaluator, c.LongRunningFunc)
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "audit")

	failedHandler := genericapifilters.Unauthorized(c.Serializer)
	failedHandler = genericapifilters.WithFailedAuthenticationAudit(failedHandler, c.AuditBackend, c.AuditPolicyRuleEvaluator)

	failedHandler = filterlatency.TrackCompleted(failedHandler)
	handler = filterlatency.TrackCompleted(handler)
	handler = genericapifilters.WithAuthentication(handler, c.Authentication.Authenticator, failedHandler, c.Authentication.APIAudiences, c.Authentication.RequestHeaderConfig)
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "authentication")

	handler = genericfilters.WithCORS(handler, c.CorsAllowedOriginList, nil, nil, nil, "true")

	// WithTimeoutForNonLongRunningRequests will call the rest of the request handling in a go-routine with the
	// context with deadline. The go-routine can keep running, while the timeout logic will return a timeout to the client.
	handler = genericfilters.WithTimeoutForNonLongRunningRequests(handler, c.LongRunningFunc)

	handler = genericapifilters.WithRequestDeadline(handler, c.AuditBackend, c.AuditPolicyRuleEvaluator,
		c.LongRunningFunc, c.Serializer, c.RequestTimeout)
	handler = genericfilters.WithWaitGroup(handler, c.LongRunningFunc, c.NonLongRunningRequestWaitGroup)
	if c.ShutdownWatchTerminationGracePeriod > 0 {
		handler = genericfilters.WithWatchTerminationDuringShutdown(handler, c.lifecycleSignals, c.WatchRequestWaitGroup)
	}
	if c.SecureServing != nil && !c.SecureServing.DisableHTTP2 && c.GoawayChance > 0 {
		handler = genericfilters.WithProbabilisticGoaway(handler, c.GoawayChance)
	}
	handler = genericapifilters.WithWarningRecorder(handler)
	handler = genericapifilters.WithCacheControl(handler)
	handler = genericfilters.WithHSTS(handler, c.HSTSDirectives)
	if c.ShutdownSendRetryAfter {
		handler = genericfilters.WithRetryAfter(handler, c.lifecycleSignals.NotAcceptingNewRequest.Signaled())
	}
	handler = genericfilters.WithHTTPLogging(handler)
	if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.APIServerTracing) {
		handler = genericapifilters.WithTracing(handler, c.TracerProvider)
	}
	handler = genericapifilters.WithLatencyTrackers(handler)
	handler = genericapifilters.WithRequestInfo(handler, c.RequestInfoResolver)
	handler = genericapifilters.WithRequestReceivedTimestamp(handler)
	handler = genericapifilters.WithMuxAndDiscoveryComplete(handler, c.lifecycleSignals.MuxAndDiscoveryComplete.Signaled())
	handler = genericfilters.WithPanicRecovery(handler, c.RequestInfoResolver)
	handler = genericapifilters.WithAuditInit(handler)
	return handler
}
```

2. 接着multiplexer （container.go）基于HTTP路径会将HTTP请求发给对应的各自的处理handlers。

3. routes （在routes/*定义）路由将HTTP路径与handlers处理器关联。

4. 根据每个API Group注册的处理程序获取HTTP请求相关内容对象（比如用户，权限等），并将请求的内容对象存入存储中


## GenericAPIServer 通用配置

```go
func CreateKubeAPIServerConfig(s completedServerRunOptions) (
	*controlplane.Config,
	aggregatorapiserver.ServiceResolver,
	[]admission.PluginInitializer,
	error,
) {
	proxyTransport := CreateProxyTransport()
    // 1、构建 genericConfig
	genericConfig, versionedInformers, serviceResolver, pluginInitializers, admissionPostStartHook, storageFactory, err := buildGenericConfig(s.ServerRunOptions, proxyTransport)
	if err != nil {
		return nil, nil, nil, err
	}
    // 2、初始化所支持的 capabilities
	capabilities.Setup(s.AllowPrivileged, s.MaxConnectionBytesPerSec)

    // ...
    
	config := &controlplane.Config{
		GenericConfig: genericConfig, // 通用配置
		// 额外配置
		ExtraConfig: controlplane.ExtraConfig{
			APIResourceConfigSource: storageFactory.APIResourceConfigSource,
			StorageFactory:          storageFactory,
			EventTTL:                s.EventTTL,
			KubeletClientConfig:     s.KubeletConfig,
			EnableLogsSupport:       s.EnableLogsHandler,
			ProxyTransport:          proxyTransport,

			ServiceIPRange:          s.PrimaryServiceClusterIPRange,// service ip range
			APIServerServiceIP:      s.APIServerServiceIP, //  api server service IP
			SecondaryServiceIPRange: s.SecondaryServiceClusterIPRange,

			APIServerServicePort: 443,

			ServiceNodePortRange:      s.ServiceNodePortRange,
			KubernetesServiceNodePort: s.KubernetesServiceNodePort,

			EndpointReconcilerType: reconcilers.Type(s.EndpointReconcilerType),
			MasterCount:            s.MasterCount,

			ServiceAccountIssuer:        s.ServiceAccountIssuer,
			ServiceAccountMaxExpiration: s.ServiceAccountTokenMaxExpiration,
			ExtendExpiration:            s.Authentication.ServiceAccounts.ExtendExpiration,

			VersionedInformers: versionedInformers,
		},
	}

	// ...


	return config, serviceResolver, pluginInitializers, nil
}
```

生成默认的 genericConfig，genericConfig 中主要配置了 DefaultBuildHandlerChain，DefaultBuildHandlerChain 中包含了认证、鉴权等一系列 http filter chain；
```go
func buildGenericConfig(
	s *options.ServerRunOptions,
	proxyTransport *http.Transport,
) (
	genericConfig *genericapiserver.Config,
	versionedInformers clientgoinformers.SharedInformerFactory,
	serviceResolver aggregatorapiserver.ServiceResolver,
	pluginInitializers []admission.PluginInitializer,
	admissionPostStartHook genericapiserver.PostStartHookFunc,
	storageFactory *serverstorage.DefaultStorageFactory,
	lastErr error,
) {
	genericConfig = genericapiserver.NewConfig(legacyscheme.Codecs)
	// 启用、禁用默认的GV及其之下Resource
	genericConfig.MergedResourceConfig = controlplane.DefaultAPIResourceConfigSource()

	if lastErr = s.GenericServerRunOptions.ApplyTo(genericConfig); lastErr != nil {
		return
	}

    // ...
	// 对外提供的API文档
	getOpenAPIDefinitions := openapi.GetOpenAPIDefinitionsWithoutDisabledFeatures(generatedopenapi.GetOpenAPIDefinitions)
	namer := openapinamer.NewDefinitionNamer(legacyscheme.Scheme, extensionsapiserver.Scheme, aggregatorscheme.Scheme)
	genericConfig.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(getOpenAPIDefinitions, namer)
	genericConfig.OpenAPIConfig.Info.Title = "Kubernetes"
	genericConfig.OpenAPIV3Config = genericapiserver.DefaultOpenAPIV3Config(getOpenAPIDefinitions, namer)
	genericConfig.OpenAPIV3Config.Info.Title = "Kubernetes"
	
    // ...

	// storageFactory的实例化，可以看到采用的是etcd作为存储方案
	storageFactoryConfig := kubeapiserver.NewStorageFactoryConfig()
	storageFactoryConfig.APIResourceConfig = genericConfig.MergedResourceConfig
	storageFactory, lastErr = storageFactoryConfig.Complete(s.Etcd).New()
	if lastErr != nil {
		return
	}
	if lastErr = s.Etcd.ApplyWithStorageFactoryTo(storageFactory, genericConfig); lastErr != nil {
		return
	}

    // ...

	// 认证配置
    // 内部调用 authenticatorConfig.New()
    // k8s提供9种认证机制，每种认证机制被实例化后都成为认证器
	if lastErr = s.Authentication.ApplyTo(&genericConfig.Authentication, genericConfig.SecureServing, genericConfig.EgressSelector, genericConfig.OpenAPIConfig, genericConfig.OpenAPIV3Config, clientgoExternalClient, versionedInformers); lastErr != nil {
		return
	}
	
    // 授权配置
    // k8e提供6种授权机制，每种授权机制被实例化后都成为授权器
	genericConfig.Authorization.Authorizer, genericConfig.RuleResolver, err = BuildAuthorizer(s, genericConfig.EgressSelector, versionedInformers)
    // ...

	// 审计相关
	lastErr = s.Audit.ApplyTo(genericConfig)
	if lastErr != nil {
		return
	}

    // ... 
    // 准入器admission配置
    // k8s资源在认证和授权通过，被持久化到etcd之前进入准入控制逻辑
    // 准入控制包括：对请求的资源进行自定义操作（校验、修改、拒绝）
    // k8s支持31 种准入控制
    // 准入控制器通过Plugins数据结构统一注册、存放、管理
	err = s.Admission.ApplyTo(
		genericConfig,
		versionedInformers,
		kubeClientConfig,
		utilfeature.DefaultFeatureGate,
		pluginInitializers...)
	if err != nil {
		lastErr = fmt.Errorf("failed to initialize admission: %v", err)
		return
	}
	

	return
}
```



### Authentication 认证

```go
func (o *BuiltInAuthenticationOptions) ApplyTo(authInfo *genericapiserver.AuthenticationInfo, secureServing *genericapiserver.SecureServingInfo, egressSelector *egressselector.EgressSelector, openAPIConfig *openapicommon.Config, openAPIV3Config *openapicommon.Config, extclient kubernetes.Interface, versionedInformer informers.SharedInformerFactory) error {
    // ..
    // 相关参数设置
	
	authenticatorConfig, err := o.ToAuthenticationConfig()
    // ...

	authInfo.Authenticator, openAPIConfig.SecurityDefinitions, err = authenticatorConfig.New()

	// .. 

	return nil
}
```

{{<figure src="./authentication.png#center" width=800px >}}
```go
func (config Config) New() (authenticator.Request, *spec.SecurityDefinitions, error) {
	var authenticators []authenticator.Request
	var tokenAuthenticators []authenticator.Token
	securityDefinitions := spec.SecurityDefinitions{}

	// front-proxy, BasicAuth methods, local first, then remote
	// Add the front proxy authenticator if requested
	// 1. 添加requestHeader
	if config.RequestHeaderConfig != nil {
		requestHeaderAuthenticator := headerrequest.NewDynamicVerifyOptionsSecure(
			config.RequestHeaderConfig.CAContentProvider.VerifyOptions,
			config.RequestHeaderConfig.AllowedClientNames,
			config.RequestHeaderConfig.UsernameHeaders,
			config.RequestHeaderConfig.GroupHeaders,
			config.RequestHeaderConfig.ExtraHeaderPrefixes,
		)
		authenticators = append(authenticators, authenticator.WrapAudienceAgnosticRequest(config.APIAudiences, requestHeaderAuthenticator))
	}

	// X509 methods
	// 2. 添加ClientCA
	if config.ClientCAContentProvider != nil {
		certAuth := x509.NewDynamic(config.ClientCAContentProvider.VerifyOptions, x509.CommonNameUserConversion)
		authenticators = append(authenticators, certAuth)
	}

	// Bearer token methods, local first, then remote
	// 3. token 添加 tokenfile
	if len(config.TokenAuthFile) > 0 {
		tokenAuth, err := newAuthenticatorFromTokenFile(config.TokenAuthFile)
		if err != nil {
			return nil, nil, err
		}
		tokenAuthenticators = append(tokenAuthenticators, authenticator.WrapAudienceAgnosticToken(config.APIAudiences, tokenAuth))
	}
	// 4 ServiceAccountAuth认证器
	if len(config.ServiceAccountKeyFiles) > 0 {
		serviceAccountAuth, err := newLegacyServiceAccountAuthenticator(config.ServiceAccountKeyFiles, config.ServiceAccountLookup, config.APIAudiences, config.ServiceAccountTokenGetter, config.SecretsWriter)
		if err != nil {
			return nil, nil, err
		}
		tokenAuthenticators = append(tokenAuthenticators, serviceAccountAuth)
	}
	if len(config.ServiceAccountIssuers) > 0 {
		serviceAccountAuth, err := newServiceAccountAuthenticator(config.ServiceAccountIssuers, config.ServiceAccountKeyFiles, config.APIAudiences, config.ServiceAccountTokenGetter)
		if err != nil {
			return nil, nil, err
		}
		tokenAuthenticators = append(tokenAuthenticators, serviceAccountAuth)
	}
	// 5 BootstrapToken认证器  用于集群初始化阶段
	if config.BootstrapToken {
		if config.BootstrapTokenAuthenticator != nil {
			// TODO: This can sometimes be nil because of
			tokenAuthenticators = append(tokenAuthenticators, authenticator.WrapAudienceAgnosticToken(config.APIAudiences, config.BootstrapTokenAuthenticator))
		}
	}
    // 6 添加 oidc OAuth2 认证
	if len(config.OIDCIssuerURL) > 0 && len(config.OIDCClientID) > 0 {
		// TODO(enj): wire up the Notifier and ControllerRunner bits when OIDC supports CA reload
		var oidcCAContent oidc.CAContentProvider
		if len(config.OIDCCAFile) != 0 {
			var oidcCAErr error
			oidcCAContent, oidcCAErr = staticCAContentProviderFromFile("oidc-authenticator", config.OIDCCAFile)
			if oidcCAErr != nil {
				return nil, nil, oidcCAErr
			}
		}

		oidcAuth, err := newAuthenticatorFromOIDCIssuerURL(oidc.Options{
			IssuerURL:            config.OIDCIssuerURL,
			ClientID:             config.OIDCClientID,
			CAContentProvider:    oidcCAContent,
			UsernameClaim:        config.OIDCUsernameClaim,
			UsernamePrefix:       config.OIDCUsernamePrefix,
			GroupsClaim:          config.OIDCGroupsClaim,
			GroupsPrefix:         config.OIDCGroupsPrefix,
			SupportedSigningAlgs: config.OIDCSigningAlgs,
			RequiredClaims:       config.OIDCRequiredClaims,
		})
		if err != nil {
			return nil, nil, err
		}
		tokenAuthenticators = append(tokenAuthenticators, authenticator.WrapAudienceAgnosticToken(config.APIAudiences, oidcAuth))
	}
	// 7 WebhookTokenAuth认证器
	if len(config.WebhookTokenAuthnConfigFile) > 0 {
		webhookTokenAuth, err := newWebhookTokenAuthenticator(config)
		if err != nil {
			return nil, nil, err
		}

		tokenAuthenticators = append(tokenAuthenticators, webhookTokenAuth)
	}

	// 8 tokenAuthenticators
	if len(tokenAuthenticators) > 0 {
		// Union the token authenticators
		tokenAuth := tokenunion.New(tokenAuthenticators...)
		// Optionally cache authentication results
		if config.TokenSuccessCacheTTL > 0 || config.TokenFailureCacheTTL > 0 {
			tokenAuth = tokencache.New(tokenAuth, true, config.TokenSuccessCacheTTL, config.TokenFailureCacheTTL)
		}
		authenticators = append(authenticators, bearertoken.New(tokenAuth), websocket.NewProtocolAuthenticator(tokenAuth))
		securityDefinitions["BearerToken"] = &spec.SecurityScheme{
			SecuritySchemeProps: spec.SecuritySchemeProps{
				Type:        "apiKey",
				Name:        "authorization",
				In:          "header",
				Description: "Bearer Token authentication",
			},
		}
	}

	if len(authenticators) == 0 {
        // 9 匿名认证器
		if config.Anonymous {
			return anonymous.NewAuthenticator(), &securityDefinitions, nil
		}
		return nil, &securityDefinitions, nil
	}

	// 聚合 authenticators
	authenticator := union.New(authenticators...)

	authenticator = group.NewAuthenticatedGroupAdder(authenticator)

	if config.Anonymous {
		// If the authenticator chain returns an error, return an error (don't consider a bad bearer token
		// or invalid username/password combination anonymous).
		authenticator = union.NewFailOnError(authenticator, anonymous.NewAuthenticator())
	}

	return authenticator, &securityDefinitions, nil
}
```

校验中间件
```go
// https://github.com/kubernetes/kubernetes/blob/c883ca7f035ad2b9c3126d113d234f632e1c7b83/staging/src/k8s.io/apiserver/pkg/endpoints/filters/authentication.go
func WithAuthentication(handler http.Handler, auth authenticator.Request, failed http.Handler, apiAuds authenticator.Audiences, requestHeaderConfig *authenticatorfactory.RequestHeaderConfig) http.Handler {
	return withAuthentication(handler, auth, failed, apiAuds, requestHeaderConfig, recordAuthMetrics)
}

func withAuthentication(handler http.Handler, auth authenticator.Request, failed http.Handler, apiAuds authenticator.Audiences, requestHeaderConfig *authenticatorfactory.RequestHeaderConfig, metrics recordMetrics) http.Handler {
	if auth == nil {
		klog.Warning("Authentication is disabled")
		return handler
	}
	standardRequestHeaderConfig := &authenticatorfactory.RequestHeaderConfig{
		UsernameHeaders:     headerrequest.StaticStringSlice{"X-Remote-User"},
		GroupHeaders:        headerrequest.StaticStringSlice{"X-Remote-Group"},
		ExtraHeaderPrefixes: headerrequest.StaticStringSlice{"X-Remote-Extra-"},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authenticationStart := time.Now()

		if len(apiAuds) > 0 {
			req = req.WithContext(authenticator.WithAudiences(req.Context(), apiAuds))
		}
		resp, ok, err := auth.AuthenticateRequest(req)
		// 。。

		req = req.WithContext(genericapirequest.WithUser(req.Context(), resp.User))
		handler.ServeHTTP(w, req)
	})
}
```

依次逐个来看看每一种Authenticator对应的AuthenticateRequest方法。
```go
func (authHandler *unionAuthRequestHandler) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	var errlist []error
	for _, currAuthRequestHandler := range authHandler.Handlers {
		resp, ok, err := currAuthRequestHandler.AuthenticateRequest(req)
        // ..

		if ok {
			return resp, ok, err
		}
	}

	return nil, false, utilerrors.NewAggregate(errlist)
}
```

### Authorization 授权模块

配置初始化
```go
func BuildAuthorizer(s *options.ServerRunOptions, EgressSelector *egressselector.EgressSelector, versionedInformers clientgoinformers.SharedInformerFactory) (authorizer.Authorizer, authorizer.RuleResolver, error) {
	authorizationConfig := s.Authorization.ToAuthorizationConfig(versionedInformers)

    // ..

	return authorizationConfig.New()
}
```
```go
func (config Config) New() (authorizer.Authorizer, authorizer.RuleResolver, error) {
    // ..

	var (
		// 鉴权器
		authorizers   []authorizer.Authorizer
		// 规则解析器可以根据认证之后所得到的用户信息，获取该用户对应的资源对象的操作权限
		ruleResolvers []authorizer.RuleResolver
	)

	// Add SystemPrivilegedGroup as an authorizing group
	superuserAuthorizer := authorizerfactory.NewPrivilegedGroups(user.SystemPrivilegedGroup)
	authorizers = append(authorizers, superuserAuthorizer)

	for _, authorizationMode := range config.AuthorizationModes {
		// Keep cases in sync with constant list in k8s.io/kubernetes/pkg/kubeapiserver/authorizer/modes/modes.go.
		switch authorizationMode {
		case modes.ModeNode: // Node授权器
			node.RegisterMetrics()
			graph := node.NewGraph()
			node.AddGraphEventHandlers(
				graph,
				config.VersionedInformerFactory.Core().V1().Nodes(),
				config.VersionedInformerFactory.Core().V1().Pods(),
				config.VersionedInformerFactory.Core().V1().PersistentVolumes(),
				config.VersionedInformerFactory.Storage().V1().VolumeAttachments(),
			)
			nodeAuthorizer := node.NewAuthorizer(graph, nodeidentifier.NewDefaultNodeIdentifier(), bootstrappolicy.NodeRules())
			authorizers = append(authorizers, nodeAuthorizer)
			ruleResolvers = append(ruleResolvers, nodeAuthorizer)

		case modes.ModeAlwaysAllow: // AlwaysAllow授权器
			alwaysAllowAuthorizer := authorizerfactory.NewAlwaysAllowAuthorizer()
			authorizers = append(authorizers, alwaysAllowAuthorizer)
			ruleResolvers = append(ruleResolvers, alwaysAllowAuthorizer)
		case modes.ModeAlwaysDeny: // AlwaysDeny授权器
			alwaysDenyAuthorizer := authorizerfactory.NewAlwaysDenyAuthorizer()
			authorizers = append(authorizers, alwaysDenyAuthorizer)
			ruleResolvers = append(ruleResolvers, alwaysDenyAuthorizer)
		case modes.ModeABAC: // ABAC
			
			abacAuthorizer, err := abac.NewFromFile(config.PolicyFile)
			if err != nil {
				return nil, nil, err
			}
			authorizers = append(authorizers, abacAuthorizer)
			ruleResolvers = append(ruleResolvers, abacAuthorizer)
		case modes.ModeWebhook: // Webhook授权器
			if config.WebhookRetryBackoff == nil {
				return nil, nil, errors.New("retry backoff parameters for authorization webhook has not been specified")
			}
			clientConfig, err := webhookutil.LoadKubeconfig(config.WebhookConfigFile, config.CustomDial)
			if err != nil {
				return nil, nil, err
			}
			webhookAuthorizer, err := webhook.New(clientConfig,
				config.WebhookVersion,
				config.WebhookCacheAuthorizedTTL,
				config.WebhookCacheUnauthorizedTTL,
				*config.WebhookRetryBackoff,
			)
			if err != nil {
				return nil, nil, err
			}
			authorizers = append(authorizers, webhookAuthorizer)
			ruleResolvers = append(ruleResolvers, webhookAuthorizer)
		case modes.ModeRBAC: // RBAC
			
			rbacAuthorizer := rbac.New(
				&rbac.RoleGetter{Lister: config.VersionedInformerFactory.Rbac().V1().Roles().Lister()},
				&rbac.RoleBindingLister{Lister: config.VersionedInformerFactory.Rbac().V1().RoleBindings().Lister()},
				&rbac.ClusterRoleGetter{Lister: config.VersionedInformerFactory.Rbac().V1().ClusterRoles().Lister()},
				&rbac.ClusterRoleBindingLister{Lister: config.VersionedInformerFactory.Rbac().V1().ClusterRoleBindings().Lister()},
			)
			authorizers = append(authorizers, rbacAuthorizer)
			ruleResolvers = append(ruleResolvers, rbacAuthorizer)
		default:
			return nil, nil, fmt.Errorf("unknown authorization mode %s specified", authorizationMode)
		}
	}
    // 组合 authorizers 
	return union.New(authorizers...), union.NewRuleResolvers(ruleResolvers...), nil
}
```

6 种鉴权机制
```go

const (
	// 总是允许
	ModeAlwaysAllow string = "AlwaysAllow"
	// 总是拒绝
	ModeAlwaysDeny string = "AlwaysDeny"
	// ModeABAC is the mode to use Attribute Based Access Control to authorize
	ModeABAC string = "ABAC"
	// 基于 webhook 的一种 HTTP 回调机制，可以进行远程鉴权管理
	ModeWebhook string = "Webhook"
	// ModeRBAC is the mode to use Role Based Access Control to authorize
	ModeRBAC string = "RBAC"
	// ModeNode is an authorization mode that authorizes API requests made by kubelets.
	ModeNode string = "Node"
)

```

目前支持6种鉴权策略，每种鉴权策略对应一个鉴权器,使用的鉴权策略需要在APIServer启动时以参数--authorization-mode的形式指定，多种策略同时指定时使用','号连接：

策略分类有：

* --authorization-mode=ABAC 基于属性的访问控制（ABAC）模式允许你 使用本地文件配置策略。
* --authorization-mode=RBAC 基于角色的访问控制（RBAC）模式允许你使用 Kubernetes API 创建和存储策略。
* --authorization-mode=Webhook WebHook 是一种 HTTP 回调模式，允许你使用远程 REST 端点管理鉴权。
* --authorization-mode=Node 节点鉴权是一种特殊用途的鉴权模式，专门对 kubelet 发出的 API 请求执行鉴权。
* --authorization-mode=AlwaysDeny 该标志阻止所有请求。仅将此标志用于测试。
* --authorization-mode=AlwaysAllow 此标志允许所有请求。仅在你不需要 API 请求 的鉴权时才使用此标志

鉴权中有三个概念：

- Decision：决策状态
```go
type Decision int

const (
	// DecisionDeny means that an authorizer decided to deny the action.
	DecisionDeny Decision = iota
	// 允许该操作
	DecisionAllow
	// 表示无明显意见允许或拒绝，继续执行下一个鉴权模块
    DecisionNoOpinion
)

```
- Authorizer：鉴权接口
```go
type Authorizer interface {
	// Attributes 是决定鉴权模块从 HTTP 请求中获取鉴权信息方法的参数，它是一个方法集合的接口， 例如 GetUser、GetVerb、GetNamespace、GetResource 等鉴权信息方法。
	Authorize(ctx context.Context, a Attributes) (authorized Decision, reason string, err error)
}
```
- RuleResolver：规则解析器


#### RBAC鉴权器
基于角色（Role）的访问控制（RBAC）是一种基于组织中用户的角色来调节控制对 计算机或网络资源的访问的方法。

通过创建Role 或 ClusterRole来描述具体的资源授权策略，再通过创建RoleBinding/ClusterRoleBinding将策略绑定到用户/群组/服务上。

```go
// https://github.com/kubernetes/kubernetes/blob/edffc700a43e610f641907290a5152ca593bad79/plugin/pkg/auth/authorizer/rbac/rbac.go
func New(roles rbacregistryvalidation.RoleGetter, roleBindings rbacregistryvalidation.RoleBindingLister, clusterRoles rbacregistryvalidation.ClusterRoleGetter, clusterRoleBindings rbacregistryvalidation.ClusterRoleBindingLister) *RBACAuthorizer {
	authorizer := &RBACAuthorizer{
		authorizationRuleResolver: rbacregistryvalidation.NewDefaultRuleResolver(
			roles, roleBindings, clusterRoles, clusterRoleBindings,
		),
	}
	return authorizer
}

```


鉴权
```go
func (r *RBACAuthorizer) Authorize(ctx context.Context, requestAttributes authorizer.Attributes) (authorizer.Decision, string, error) {
	ruleCheckingVisitor := &authorizingVisitor{requestAttributes: requestAttributes}

	r.authorizationRuleResolver.VisitRulesFor(requestAttributes.GetUser(), requestAttributes.GetNamespace(), ruleCheckingVisitor.visit)
	if ruleCheckingVisitor.allowed {
		return authorizer.DecisionAllow, ruleCheckingVisitor.reason, nil
	}

    // ..

	reason := ""
	if len(ruleCheckingVisitor.errors) > 0 {
		reason = fmt.Sprintf("RBAC: %v", utilerrors.NewAggregate(ruleCheckingVisitor.errors))
	}
	return authorizer.DecisionNoOpinion, reason, nil
}

```


rbac鉴权过程如下:

1. 取到所有的clusterRoleBinding/roleBindings资源对象，遍历它们对比请求用户
2. 对比roleBindings/clusterRoleBinding指向的用户(主体)与请求用户，相同则选中，不相同continue
3. 对比规则与请求属性，符合则提前结束鉴权
```go
func (r *DefaultRuleResolver) VisitRulesFor(user user.Info, namespace string, visitor func(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool) {
	// 先拿到所有的ClusterRoleBinding对象
	if clusterRoleBindings, err := r.clusterRoleBindingLister.ListClusterRoleBindings(); err != nil {
		if !visitor(nil, nil, err) {
			return
		}
	} else {
		sourceDescriber := &clusterRoleBindingDescriber{}
		for _, clusterRoleBinding := range clusterRoleBindings {
			subjectIndex, applies := appliesTo(user, clusterRoleBinding.Subjects, "")
			if !applies {
				continue
			}
			rules, err := r.GetRoleReferenceRules(clusterRoleBinding.RoleRef, "")
			if err != nil {
				if !visitor(nil, nil, err) {
					return
				}
				continue
			}
			sourceDescriber.binding = clusterRoleBinding
			sourceDescriber.subject = &clusterRoleBinding.Subjects[subjectIndex]
			for i := range rules {
				if !visitor(sourceDescriber, &rules[i], nil) {
					return
				}
			}
		}
	}
    // 如果指定了namespace，再取命名空间级别的roleBinding资源对象，重复一次上面的过程
	if len(namespace) > 0 {
		if roleBindings, err := r.roleBindingLister.ListRoleBindings(namespace); err != nil {
			if !visitor(nil, nil, err) {
				return
			}
		} else {
			sourceDescriber := &roleBindingDescriber{}
			for _, roleBinding := range roleBindings {
				subjectIndex, applies := appliesTo(user, roleBinding.Subjects, namespace)
				if !applies {
					continue
				}
				rules, err := r.GetRoleReferenceRules(roleBinding.RoleRef, namespace)
				if err != nil {
					if !visitor(nil, nil, err) {
						return
					}
					continue
				}
				sourceDescriber.binding = roleBinding
				sourceDescriber.subject = &roleBinding.Subjects[subjectIndex]
				for i := range rules {
					if !visitor(sourceDescriber, &rules[i], nil) {
						return
					}
				}
			}
		}
	}
}
```

```go
// 对比规则和请求属性，返回true or false的visit方法
func (v *authorizingVisitor) visit(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool {
	if rule != nil && RuleAllows(v.requestAttributes, rule) {
		v.allowed = true
		v.reason = fmt.Sprintf("RBAC: allowed by %s", source.String())
		return false
	}
	if err != nil {
		v.errors = append(v.errors, err)
	}
	return true
}
```

### admission 准入机制: 提供回调钩子，资源持久化前对资源的值做改动或者验证等操作
准入控制器是kubernetes 的API Server上的一个链式Filter，它根据一定的规则决定是否允许当前的请求生效，并且有可能会改写资源声明

{{<figure src="./apiserver_admission_register.png#center" width=800px >}}

{{<figure src="./admission_process.png#center" width=800px >}}



```go
func NewAdmissionOptions() *AdmissionOptions {
	options := genericoptions.NewAdmissionOptions()
	// 注册 all admission plugins
	RegisterAllAdmissionPlugins(options.Plugins)
	// set RecommendedPluginOrder
	options.RecommendedPluginOrder = AllOrderedPlugins
	// set DefaultOffPlugins
	options.DefaultOffPlugins = DefaultOffAdmissionPlugins()

	return &AdmissionOptions{
		GenericAdmission: options,
	}
}
```
默认的插件
```go
// AllOrderedPlugins is the list of all the plugins in order.
var AllOrderedPlugins = []string{
	admit.PluginName,                        // AlwaysAdmit
	autoprovision.PluginName,                // NamespaceAutoProvision
	lifecycle.PluginName,                    // NamespaceLifecycle
	exists.PluginName,                       // NamespaceExists
	scdeny.PluginName,                       // SecurityContextDeny
	antiaffinity.PluginName,                 // LimitPodHardAntiAffinityTopology
	limitranger.PluginName,                  // LimitRanger
	serviceaccount.PluginName,               // ServiceAccount
	noderestriction.PluginName,              // NodeRestriction
	nodetaint.PluginName,                    // TaintNodesByCondition
	alwayspullimages.PluginName,             // AlwaysPullImages
	imagepolicy.PluginName,                  // ImagePolicyWebhook
	podsecurity.PluginName,                  // PodSecurity
	podnodeselector.PluginName,              // PodNodeSelector
	podpriority.PluginName,                  // Priority
	defaulttolerationseconds.PluginName,     // DefaultTolerationSeconds
	podtolerationrestriction.PluginName,     // PodTolerationRestriction
	eventratelimit.PluginName,               // EventRateLimit
	extendedresourcetoleration.PluginName,   // ExtendedResourceToleration
	label.PluginName,                        // PersistentVolumeLabel
	setdefault.PluginName,                   // DefaultStorageClass
	storageobjectinuseprotection.PluginName, // StorageObjectInUseProtection
	gc.PluginName,                           // OwnerReferencesPermissionEnforcement
	resize.PluginName,                       // PersistentVolumeClaimResize
	runtimeclass.PluginName,                 // RuntimeClass
	certapproval.PluginName,                 // CertificateApproval
	certsigning.PluginName,                  // CertificateSigning
	ctbattest.PluginName,                    // ClusterTrustBundleAttest
	certsubjectrestriction.PluginName,       // CertificateSubjectRestriction
	defaultingressclass.PluginName,          // DefaultIngressClass
	denyserviceexternalips.PluginName,       // DenyServiceExternalIPs

	// new admission plugins should generally be inserted above here
	// webhook, resourcequota, and deny plugins must go at the end

	mutatingwebhook.PluginName,           // MutatingAdmissionWebhook
	validatingadmissionpolicy.PluginName, // ValidatingAdmissionPolicy
	validatingwebhook.PluginName,         // ValidatingAdmissionWebhook
	resourcequota.PluginName,             // ResourceQuota
	deny.PluginName,                      // AlwaysDeny
}

```
根据准入控制器执行的操作类型，它可以分为 3 种类型：


Mutating：这种控制器可以解析请求，并在请求向下发送之前对请求进行更改（变更请求）。 例如：AlwaysPullImages

Validating：这种控制器可以解析请求并根据特定数据进行验证。 例如：NamespaceExists

Both：这种控制器可以执行变更和验证两种操作。 例如：CertificateSigning


其中有三个特殊的Admission Plugin：ImagePolicyWebhook、MutatingAdmissionWebhook、ValidatingAdmissionWebhook，它们会根据设置去调用使用者自己写的Web服务，传入请求的目标Object，让该服务判断是否需要拒绝、允许或进行修改


初始化
```go
//	genericconfig.Authorizer
func (a *AdmissionOptions) ApplyTo(
	c *server.Config,
	informers informers.SharedInformerFactory,
	kubeAPIServerClientConfig *rest.Config,
	features featuregate.FeatureGate,
	pluginInitializers ...admission.PluginInitializer,
) error {
    // ...
    
	// 初始化链
	admissionChain, err := a.Plugins.NewFromPlugins(pluginNames, pluginsConfigProvider, initializersChain, a.Decorators)
	if err != nil {
		return err
	}

	c.AdmissionControl = admissionmetrics.WithStepMetrics(admissionChain)
	return nil
}
```

```go
func (ps *Plugins) NewFromPlugins(pluginNames []string, configProvider ConfigProvider, pluginInitializer PluginInitializer, decorator Decorator) (Interface, error) {
	handlers := []Interface{}
	mutationPlugins := []string{}
	validationPlugins := []string{}
	for _, pluginName := range pluginNames {
		pluginConfig, err := configProvider.ConfigFor(pluginName)
		if err != nil {
			return nil, err
		}
        // 1. 初始化插件
		plugin, err := ps.InitPlugin(pluginName, pluginConfig, pluginInitializer)
		if err != nil {
			return nil, err
		}
		if plugin != nil {
			if decorator != nil {
				// 如果有装饰器，则添加经过装饰的admission.Interface
				handlers = append(handlers, decorator.Decorate(plugin, pluginName))
			} else {
				handlers = append(handlers, plugin)
			}

			// 收集mutation plugin
			if _, ok := plugin.(MutationInterface); ok {
				mutationPlugins = append(mutationPlugins, pluginName)
			}
			// 收集validation plugin
			if _, ok := plugin.(ValidationInterface); ok {
				validationPlugins = append(validationPlugins, pluginName)
			}
		}
	}
    // ...
	return newReinvocationHandler(chainAdmissionHandler(handlers)), nil
}

```



接口
```go
// staging/src/k8s.io/apiserver/pkg/admission/interfaces.go

// Interface is an abstract, pluggable interface for Admission Control decisions.
type Interface interface {
	// Handles returns true if this admission controller can handle the given operation
	// where operation can be one of CREATE, UPDATE, DELETE, or CONNECT
	Handles(operation Operation) bool
}

type MutationInterface interface {
	Interface

	// Admit makes an admission decision based on the request attributes.
	// Context is used only for timeout/deadline/cancellation and tracing information.
	Admit(ctx context.Context, a Attributes, o ObjectInterfaces) (err error)
}

// ValidationInterface is an abstract, pluggable interface for Admission Control decisions.
type ValidationInterface interface {
	Interface

	// 对提交上来的资源进行验证
	Validate(ctx context.Context, a Attributes, o ObjectInterfaces) (err error)
}
```

处理时
```go
// https://github.com/kubernetes/kubernetes/blob/5e5b3029f3bbfc93c3569f07ad300a5c6057fc58/staging/src/k8s.io/apiserver/pkg/admission/metrics/metrics.go

// Admit performs a mutating admission control check and emit metrics.
func (p pluginHandlerWithMetrics) Admit(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	mutatingHandler, ok := p.Interface.(admission.MutationInterface)
	if !ok {
		return nil
	}

	start := time.Now()
	err := mutatingHandler.Admit(ctx, a, o)
	p.observer(ctx, time.Since(start), err != nil, a, stepAdmit, p.extraLabels...)
	return err
}

// Validate performs a non-mutating admission control check and emits metrics.
func (p pluginHandlerWithMetrics) Validate(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	validatingHandler, ok := p.Interface.(admission.ValidationInterface)
	if !ok {
		return nil
	}

	start := time.Now()
	err := validatingHandler.Validate(ctx, a, o)
	p.observer(ctx, time.Since(start), err != nil, a, stepValidate, p.extraLabels...)
	return err
}
```



请求 post 校验过程
```go
func (a *APIInstaller) registerResourceHandlers(path string, storage rest.Storage, ws *restful.WebService) (*metav1.APIResource, *storageversion.ResourceInfo, error) {
	admit := a.group.Admit

    // ..

	for _, action := range actions {
        // ..

		switch action.Verb {
        // ...
		case "POST": // Create a resource.
			var handler restful.RouteFunction
			if isNamedCreater {
				handler = restfulCreateNamedResource(namedCreater, reqScope, admit)
			} else {
				handler = restfulCreateResource(creater, reqScope, admit)
			}
			// 可观测处理
			handler = metrics.InstrumentRouteFunc(action.Verb, group, version, resource, subresource, requestScope, metrics.APIServerComponent, deprecated, removedRelease, handler)
			handler = utilwarning.AddWarningsHandler(handler, warnings)
			article := GetArticleForNoun(kind, " ")
			doc := "create" + article + kind
			if isSubresource {
				doc = "create " + subresource + " of" + article + kind
			}
			route := ws.POST(action.Path).To(handler).
				Doc(doc).
				Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed.")).
				Operation("create"+namespaced+kind+strings.Title(subresource)+operationSuffix).
				Produces(append(storageMeta.ProducesMIMETypes(action.Verb), mediaTypes...)...).
				Returns(http.StatusOK, "OK", producedObject).
				// TODO: in some cases, the API may return a v1.Status instead of the versioned object
				// but currently go-restful can't handle multiple different objects being returned.
				Returns(http.StatusCreated, "Created", producedObject).
				Returns(http.StatusAccepted, "Accepted", producedObject).
				Reads(defaultVersionedObject).
				Writes(producedObject)
			if err := AddObjectParams(ws, route, versionedCreateOptions); err != nil {
				return nil, nil, err
			}
			addParams(route, action.Params)
			routes = append(routes, route)

        // ..
		default:
			return nil, nil, fmt.Errorf("unrecognized action verb: %s", action.Verb)
		}
		for _, route := range routes {
			route.Metadata(ROUTE_META_GVK, metav1.GroupVersionKind{
				Group:   reqScope.Kind.Group,
				Version: reqScope.Kind.Version,
				Kind:    reqScope.Kind.Kind,
			})
			route.Metadata(ROUTE_META_ACTION, strings.ToLower(action.Verb))
			ws.Route(route)
		}
		// Note: update GetAuthorizerAttributes() when adding a custom handler.
	}

    // ....
	return &apiResource, resourceInfo, nil
}

```

最终调用
```go
func createHandler(r rest.NamedCreater, scope *RequestScope, admit admission.Interface, includeName bool) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
        // ...

		requestFunc := func() (runtime.Object, error) {
			return r.Create(
				ctx,
				name,
				obj,
				rest.AdmissionToValidateObjectFunc(admit, admissionAttributes, scope),  // 校验
				options,
			)
		}
		// Dedup owner references before updating managed fields
		dedupOwnerReferencesAndAddWarning(obj, req.Context(), false)
		result, err := finisher.FinishRequest(ctx, func() (runtime.Object, error) {
			liveObj, err := scope.Creater.New(scope.Kind)
			if err != nil {
				return nil, fmt.Errorf("failed to create new object (Create for %v): %v", scope.Kind, err)
			}
			obj = scope.FieldManager.UpdateNoErrors(liveObj, obj, managerOrUserAgent(options.FieldManager, req.UserAgent()))
			admit = fieldmanager.NewManagedFieldsValidatingAdmissionController(admit)

			// mutating 曹祖平
			if mutatingAdmission, ok := admit.(admission.MutationInterface); ok && mutatingAdmission.Handles(admission.Create) {
				if err := mutatingAdmission.Admit(ctx, admissionAttributes, scope); err != nil {
					return nil, err
				}
			}
			// Dedup owner references again after mutating admission happens
			dedupOwnerReferencesAndAddWarning(obj, req.Context(), true)
			result, err := requestFunc()
             // ...
			return result, err
		})
        // ...
	}
}
```

## 启动

启动的代码逻辑可以分为9个步骤：

1. 资源注册
2. Cobra命令行参数解析
3. 创建apiserver通用配置
4. 创建APIExtensionsServer
5. 创建KubeAPIServer
6. 创建AggregatorServer
7. 创建GenericAPIServer
8. 启动http服务
9. 启动https服务

```go
// https://github.com/kubernetes/kubernetes/blob/3d2f5d27f80b8eb00e908e85978c97a1fb28f9e8/cmd/kube-apiserver/app/server.go
func Run(completeOptions completedServerRunOptions, stopCh <-chan struct{}) error {
    // ...
    // 创建服务链
	server, err := CreateServerChain(completeOptions)
	if err != nil {
		return err
	}
    // 预运行: 主要完成了健康检查、存活检查和OpenAPI路由的注册工作
	prepared, err := server.PrepareRun()
	if err != nil {
		return err
	}
    // 正式运行
	return prepared.Run(stopCh)
}
```



### CreateServerChain: API 层 创建 Three Servers

| 服务名 |                                                     概述                                                      | 对象管理 |资源注册表 |
| :--: |:-----------------------------------------------------------------------------------------------------------:| :--: |:--: |
| APIExtensionsServer | 主要处理 CustomResourceDefinition（CRD）和 CustomResource（CR）的 REST 请求，也是 Delegation 的最后一环，如果对应 CR 不能被处理的话则会返回 404 | CustomResourceDefinitions |extensionsapiserver.Scheme |
| KubeAPIServer |                                核心服务，提供k8s内置核心资源服务，不允许开发者随意修改，如：Pod，Service等                                 | Master |Legacyscheme.Scheme |
| AggregatorServer|                                              API聚合服务，提供了聚合服务,功能类似于一个七层负载均衡，将来自用户的请求拦截转发给其他服务器，并且负责整个 APIServer 的 Discovery 功能                                               | APIAggregator |aggregatorscheme.Scheme |



三个 APIServer 通过 delegation 委托模式 的关系关联,初始化的过程都是类似的，包括：

- 首先为每个server创建对应的config
- 然后初始化http server，具体包括：
  - 初始化GoRestfulContainer
  - 安装server所包含的api，细节有：
    - 为每个api-resource创建对应的后端存储RESTStorage
    - 为每个api-resource所支持的verbs添加对应的handler
    - 将handler注册到router中
    - 将router注册到webservice

{{<figure src="three_apiserver.png#center" width=800px >}}
```go
// 创建服务链
func CreateServerChain(completedOptions completedServerRunOptions) (*aggregatorapiserver.APIAggregator, error) {
    // ...
	
	// APIExtensionsServer 的 delegationTarget 是一个空的 Delegate，即什么都不做
	// API扩展服务，主要针对CRD
	apiExtensionsServer, err := createAPIExtensionsServer(apiExtensionsConfig, genericapiserver.NewEmptyDelegateWithCustomHandler(notFoundHandler))
	if err != nil {
		return nil, err
	}

	// 将 APIExtensionsServer 的 GenericAPIServer 作为 delegationTarget 传给了 KubeAPIServe
	// API核心服务，包括常见的Pod/Deployment/Service
	kubeAPIServer, err := CreateKubeAPIServer(kubeAPIServerConfig, apiExtensionsServer.GenericAPIServer)
	if err != nil {
		return nil, err
	}

    // ...
	
	// 将 kubeAPIServer 的 GenericAPIServer 作为 delegationTarget 传给了 AggregatorServer，创建出了 AggregatorServer
	// API聚合服务，将请求转发给 API 对应的用户服务；如果没有命中，转 API核心服务
	aggregatorServer, err := createAggregatorServer(aggregatorConfig, kubeAPIServer.GenericAPIServer, apiExtensionsServer.Informers, crdAPIEnabled)
	if err != nil {
		// we don't need special handling for innerStopCh because the aggregator server doesn't create any go routines
		return nil, err
	}

	return aggregatorServer, nil
}
```


在APIExtensionsServer、KubeAPIServer和AggregatorServer三种Server启动时，我们都能发现这么一个函数 completedConfig.New。
GenericAPIServer 提供了一个通用的http server，定义了通用的模板，例如地址、端口、认证、授权、健康检查等等通用功能。

```go
func (c completedConfig) New(name string, delegationTarget DelegationTarget) (*GenericAPIServer, error) {
    // ..

	// 中间件
	handlerChainBuilder := func(handler http.Handler) http.Handler {
		return c.BuildHandlerChainFunc(handler, c.Config)
	}

    // ...
	
    // 新建Handler
	apiServerHandler := NewAPIServerHandler(name, c.Serializer, handlerChainBuilder, delegationTarget.UnprotectedHandler())

	s := &GenericAPIServer{
		discoveryAddresses:             c.DiscoveryAddresses,
		LoopbackClientConfig:           c.LoopbackClientConfig,
		legacyAPIGroupPrefixes:         c.LegacyAPIGroupPrefixes,
		admissionControl:               c.AdmissionControl,
		Serializer:                     c.Serializer,
		AuditBackend:                   c.AuditBackend,
		Authorizer:                     c.Authorization.Authorizer,
		delegationTarget:               delegationTarget,
		EquivalentResourceRegistry:     c.EquivalentResourceRegistry,
		NonLongRunningRequestWaitGroup: c.NonLongRunningRequestWaitGroup,
		WatchRequestWaitGroup:          c.WatchRequestWaitGroup,
		Handler:                        apiServerHandler,
		UnprotectedDebugSocket:         debugSocket,

		listedPathProvider: apiServerHandler,

        // 。。
	}

    // 。。


	// 处理钩子hook操作
	// first add poststarthooks from delegated targets
	for k, v := range delegationTarget.PostStartHooks() {
		s.postStartHooks[k] = v
	}

	for k, v := range delegationTarget.PreShutdownHooks() {
		s.preShutdownHooks[k] = v
	}

	// add poststarthooks that were preconfigured.  Using the add method will give us an error if the same name has already been registered.
	for name, preconfiguredPostStartHook := range c.PostStartHooks {
		if err := s.AddPostStartHook(name, preconfiguredPostStartHook.hook); err != nil {
			return nil, err
		}
	}

	// register mux signals from the delegated server
	for k, v := range delegationTarget.MuxAndDiscoveryCompleteSignals() {
		if err := s.RegisterMuxAndDiscoveryCompleteSignal(k, v); err != nil {
			return nil, err
		}
	}

    // ...

	// 安装API相关参数
	installAPI(s, c.Config)

	// use the UnprotectedHandler from the delegation target to ensure that we don't attempt to double authenticator, authorize,
	// or some other part of the filter chain in delegation cases.
	if delegationTarget.UnprotectedHandler() == nil && c.EnableIndex {
		s.Handler.NonGoRestfulMux.NotFoundHandler(routes.IndexLister{
			StatusCode:   http.StatusNotFound,
			PathProvider: s.listedPathProvider,
		})
	}

	return s, nil
}
```

一些通用的 API
```go
func installAPI(s *GenericAPIServer, c *Config) {
	// 添加 /index.html 路由规则
	if c.EnableIndex {
		routes.Index{}.Install(s.listedPathProvider, s.Handler.NonGoRestfulMux)
	}
	// 性能分析
	if c.EnableProfiling {
		routes.Profiling{}.Install(s.Handler.NonGoRestfulMux)
		if c.EnableContentionProfiling {
			goruntime.SetBlockProfileRate(1)
		}
		// so far, only logging related endpoints are considered valid to add for these debug flags.
		routes.DebugFlags{}.Install(s.Handler.NonGoRestfulMux, "v", routes.StringFlagPutHandler(logs.GlogSetter))
	}
	if s.UnprotectedDebugSocket != nil {
		s.UnprotectedDebugSocket.InstallProfiling()
		s.UnprotectedDebugSocket.InstallDebugFlag("v", routes.StringFlagPutHandler(logs.GlogSetter))
		if c.EnableContentionProfiling {
			goruntime.SetBlockProfileRate(1)
		}
	}
    //  metrics 的指标路由规则
	if c.EnableMetrics {
        // ..
	}

	// 添加版本 /version 的路由规则
	routes.Version{Version: c.Version}.Install(s.Handler.GoRestfulContainer)

    // 开启服务发现
	if c.EnableDiscovery {
		if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.AggregatedDiscoveryEndpoint) {
			wrapped := discoveryendpoint.WrapAggregatedDiscoveryToHandler(s.DiscoveryGroupManager, s.AggregatedDiscoveryGroupManager)
			s.Handler.GoRestfulContainer.Add(wrapped.GenerateWebService("/apis", metav1.APIGroupList{}))
		} else {
			s.Handler.GoRestfulContainer.Add(s.DiscoveryGroupManager.WebService())
		}
	}
	if c.FlowControl != nil && utilfeature.DefaultFeatureGate.Enabled(genericfeatures.APIPriorityAndFairness) {
		c.FlowControl.Install(s.Handler.NonGoRestfulMux)
	}
}
```


### prepared.Run

```go
func (s preparedGenericAPIServer) Run(stopCh <-chan struct{}) error {
	delayedStopCh := s.lifecycleSignals.AfterShutdownDelayDuration
	shutdownInitiatedCh := s.lifecycleSignals.ShutdownInitiated

	// Clean up resources on shutdown.
	defer s.Destroy()

    // ...
	
	

	// 判断是否要启动审计日志
	if s.AuditBackend != nil {
		if err := s.AuditBackend.Run(drainedCh.Signaled()); err != nil {
			return fmt.Errorf("failed to run the audit backend: %v", err)
		}
	}
    
	// 调用 s.NonBlockingRun 完成启动流程
	stoppedCh, listenerStoppedCh, err := s.NonBlockingRun(stopHttpServerCh, shutdownTimeout)
	if err != nil {
		return err
	}

    // ...
	
	<-stopCh

	//当收到退出信号后完成一些收尾工作
	func() {
		defer func() {
			preShutdownHooksHasStoppedCh.Signal()
			klog.V(1).InfoS("[graceful-termination] pre-shutdown hooks completed", "name", preShutdownHooksHasStoppedCh.Name())
		}()
		err = s.RunPreShutdownHooks()
	}()
	if err != nil {
		return err
	}

	// Wait for all requests in flight to drain, bounded by the RequestTimeout variable.
	<-drainedCh.Signaled()

	if s.AuditBackend != nil {
		s.AuditBackend.Shutdown()
		klog.V(1).InfoS("[graceful-termination] audit backend shutdown completed")
	}

	// wait for stoppedCh that is closed when the graceful termination (server.Shutdown) is finished.
	<-listenerStoppedCh
	<-stoppedCh

	klog.V(1).Info("[graceful-termination] apiserver is exiting")
	return nil
}


func (s preparedGenericAPIServer) NonBlockingRun(stopCh <-chan struct{}, shutdownTimeout time.Duration) (<-chan struct{}, <-chan struct{}, error) {
	// Use an internal stop channel to allow cleanup of the listeners on error.
	internalStopCh := make(chan struct{})
	var stoppedCh <-chan struct{}
	var listenerStoppedCh <-chan struct{}
	if s.SecureServingInfo != nil && s.Handler != nil { 
		var err error
		// 启动 https server
		stoppedCh, listenerStoppedCh, err = s.SecureServingInfo.Serve(s.Handler, shutdownTimeout, internalStopCh)
		if err != nil {
			close(internalStopCh)
			return nil, nil, err
		}
	}

	// Now that listener have bound successfully, it is the
	// responsibility of the caller to close the provided channel to
	// ensure cleanup.
	go func() {
		<-stopCh
		close(internalStopCh)
	}()
    // 执行 postStartHooks
	s.RunPostStartHooks(stopCh)

	// 向 systemd 发送 ready 信号
	if _, err := systemd.SdNotify(true, "READY=1\n"); err != nil {
		klog.Errorf("Unable to send systemd daemon successful start message: %v\n", err)
	}

	return stoppedCh, listenerStoppedCh, nil
}
```

### apiExtensionsServer

apiExtensionsServer主要负责CustomResourceDefinition（CRD）apiResources以及apiVersions的注册，同时处理CRD以及相应CustomResource（CR）的REST请求(如果对应CR不能被处理的话则会返回404)，也是apiserver Delegation的最后一环

```go
func createAPIExtensionsServer(apiextensionsConfig *apiextensionsapiserver.Config, delegateAPIServer genericapiserver.DelegationTarget) (*apiextensionsapiserver.CustomResourceDefinitions, error) {
	return apiextensionsConfig.Complete().New(delegateAPIServer)
}

```

```go
func (c completedConfig) New(delegationTarget genericapiserver.DelegationTarget) (*CustomResourceDefinitions, error) {
    // APIExtensionsServer依赖GenericAPIServer
    // 通过GenericConfig创建一个名为apiextensions-apiserver的服务
	genericServer, err := c.GenericConfig.New("apiextensions-apiserver", delegationTarget)
	if err != nil {
		return nil, err
	}

    // ..
    // APIExtensionsServer通过CustomResourceDefinitions对象进行管理
    // 实例化该对象后才能注册APIExtensionsServer下的资源
	s := &CustomResourceDefinitions{
		GenericAPIServer: genericServer,
	}

	apiResourceConfig := c.GenericConfig.MergedResourceConfig
	// apiextensions.k8s.io // 实例化APIGroupInfo，该对象用于描述资源组信息
	apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(apiextensions.GroupName, Scheme, metav1.ParameterCodec, Codecs)
	storage := map[string]rest.Storage{}
	// customresourcedefinitions
	if resource := "customresourcedefinitions"; apiResourceConfig.ResourceEnabled(v1.SchemeGroupVersion.WithResource(resource)) { // 如果开启了v1资源版本，将资源版本、资源、资源存储存放到APIGroupInfo的map中
		// 生成CRD对应的RESTStorage
		customResourceDefinitionStorage, err := customresourcedefinition.NewREST(Scheme, c.GenericConfig.RESTOptionsGetter)
        // ...
		storage[resource] = customResourceDefinitionStorage
		
		// 生成CRD status子资源对应的RESTStorage
		storage[resource+"/status"] = customresourcedefinition.NewStatusREST(Scheme, customResourceDefinitionStorage)
	}
	if len(storage) > 0 {
		// 将apiGroupInfo和RESTStorage关联起来，下一步注册apiGroupInfo会用到
		apiGroupInfo.VersionedResourcesStorageMap[v1.SchemeGroupVersion.Version] = storage
	}
    // 注册api
	if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, err
	}

	crdClient, err := clientset.NewForConfig(s.GenericAPIServer.LoopbackClientConfig)
	if err != nil {
		// it's really bad that this is leaking here, but until we can fix the test (which I'm pretty sure isn't even testing what it wants to test),
		// we need to be able to move forward
		return nil, fmt.Errorf("failed to create clientset: %v", err)
	}
	s.Informers = externalinformers.NewSharedInformerFactory(crdClient, 5*time.Minute)

	delegateHandler := delegationTarget.UnprotectedHandler()
	if delegateHandler == nil {
		delegateHandler = http.NotFoundHandler()
	}

	versionDiscoveryHandler := &versionDiscoveryHandler{
		discovery: map[schema.GroupVersion]*discovery.APIVersionHandler{},
		delegate:  delegateHandler,
	}
	groupDiscoveryHandler := &groupDiscoveryHandler{
		discovery: map[string]*discovery.APIGroupHandler{},
		delegate:  delegateHandler,
	}
	// 初始化主controller
	establishingController := establish.NewEstablishingController(s.Informers.Apiextensions().V1().CustomResourceDefinitions(), crdClient.ApiextensionsV1())
	// 申明handler
	crdHandler, err := NewCustomResourceDefinitionHandler(
		versionDiscoveryHandler,
		groupDiscoveryHandler,
		s.Informers.Apiextensions().V1().CustomResourceDefinitions(),
		delegateHandler,
		c.ExtraConfig.CRDRESTOptionsGetter,
		c.GenericConfig.AdmissionControl,
		establishingController,
		c.ExtraConfig.ServiceResolver,
		c.ExtraConfig.AuthResolverWrapper,
		c.ExtraConfig.MasterCount,
		s.GenericAPIServer.Authorizer,
		c.GenericConfig.RequestTimeout,
		time.Duration(c.GenericConfig.MinRequestTimeout)*time.Second,
		apiGroupInfo.StaticOpenAPISpec,
		c.GenericConfig.MaxRequestBodyBytes,
	)
	if err != nil {
		return nil, err
	}
	// 添加handler函数
	s.GenericAPIServer.Handler.NonGoRestfulMux.Handle("/apis", crdHandler)
	s.GenericAPIServer.Handler.NonGoRestfulMux.HandlePrefix("/apis/", crdHandler)
	s.GenericAPIServer.RegisterDestroyFunc(crdHandler.destroy)

	aggregatedDiscoveryManager := genericServer.AggregatedDiscoveryGroupManager
	if aggregatedDiscoveryManager != nil {
		aggregatedDiscoveryManager = aggregatedDiscoveryManager.WithSource(aggregated.CRDSource)
	}
	discoveryController := NewDiscoveryController(s.Informers.Apiextensions().V1().CustomResourceDefinitions(), versionDiscoveryHandler, groupDiscoveryHandler, aggregatedDiscoveryManager)
	// 初始化namingController
	namingController := status.NewNamingConditionController(s.Informers.Apiextensions().V1().CustomResourceDefinitions(), crdClient.ApiextensionsV1())
	nonStructuralSchemaController := nonstructuralschema.NewConditionController(s.Informers.Apiextensions().V1().CustomResourceDefinitions(), crdClient.ApiextensionsV1())
	apiApprovalController := apiapproval.NewKubernetesAPIApprovalPolicyConformantConditionController(s.Informers.Apiextensions().V1().CustomResourceDefinitions(), crdClient.ApiextensionsV1())
	// 初始化finalizingController
	finalizingController := finalizer.NewCRDFinalizer(
		s.Informers.Apiextensions().V1().CustomResourceDefinitions(),
		crdClient.ApiextensionsV1(),
		crdHandler,
	)

    // ...

	return s, nil
}
```

APIGroupInfo用于描述资源组信息，一个资源对应一个APIGroupInfo对象，每个资源对应一个资源存储对象
```go
func NewDefaultAPIGroupInfo(group string, scheme *runtime.Scheme, parameterCodec runtime.ParameterCodec, codecs serializer.CodecFactory) APIGroupInfo {
	return APIGroupInfo{
		PrioritizedVersions:          scheme.PrioritizedVersionsForGroup(group),
		// 这个map用于存储资源、资源存储对象的映射关系
        // 格式：资源版本/资源/资源存储对象
        // 资源存储对象RESTStorage，负责资源的增删改查
        // 后续会将RESTStorage转换为http的handler函数
		VersionedResourcesStorageMap: map[string]map[string]rest.Storage{},
		// TODO unhardcode this.  It was hardcoded before, but we need to re-evaluate
		OptionsExternalVersion: &schema.GroupVersion{Version: "v1"},
		Scheme:                 scheme,
		ParameterCodec:         parameterCodec,
		NegotiatedSerializer:   codecs,
	}
}
```

### kubeAPIServer

KubeAPIServer主要提供对内建API Resources的操作请求，为Kubernetes中各API Resources注册路由信息，同时暴露RESTFul API，使集群中以及集群外的服务都可以通过RESTful API操作Kubernetes中的资源

```go
func CreateKubeAPIServer(kubeAPIServerConfig *controlplane.Config, delegateAPIServer genericapiserver.DelegationTarget) (*controlplane.Instance, error) {
	return kubeAPIServerConfig.Complete().New(delegateAPIServer)
}

```

```go
func (c completedConfig) New(delegationTarget genericapiserver.DelegationTarget) (*Instance, error) {
    // ...

	// 初始化 kube-apiserver  GenericAPIServer
	s, err := c.GenericConfig.New("kube-apiserver", delegationTarget)
	if err != nil {
		return nil, err
	}

    // ...

	m := &Instance{
		GenericAPIServer:          s,
		ClusterAuthenticationInfo: c.ExtraConfig.ClusterAuthenticationInfo,
	}

	// install legacy rest storage
	if err := m.InstallLegacyAPI(&c, c.GenericConfig.RESTOptionsGetter); err != nil {
		return nil, err
	}
    // ...

    // REST接口的存储定义
	restStorageProviders := []RESTStorageProvider{
		apiserverinternalrest.StorageProvider{},
		authenticationrest.RESTStorageProvider{Authenticator: c.GenericConfig.Authentication.Authenticator, APIAudiences: c.GenericConfig.Authentication.APIAudiences},
		authorizationrest.RESTStorageProvider{Authorizer: c.GenericConfig.Authorization.Authorizer, RuleResolver: c.GenericConfig.RuleResolver},
		autoscalingrest.RESTStorageProvider{},
		batchrest.RESTStorageProvider{},
		certificatesrest.RESTStorageProvider{},
		coordinationrest.RESTStorageProvider{},
		discoveryrest.StorageProvider{},
		networkingrest.RESTStorageProvider{},
		noderest.RESTStorageProvider{},
		policyrest.RESTStorageProvider{},
		rbacrest.RESTStorageProvider{Authorizer: c.GenericConfig.Authorization.Authorizer},
		schedulingrest.RESTStorageProvider{},
		storagerest.RESTStorageProvider{},
		flowcontrolrest.RESTStorageProvider{InformerFactory: c.GenericConfig.SharedInformerFactory},
		// keep apps after extensions so legacy clients resolve the extensions versions of shared resource names.
		// See https://github.com/kubernetes/kubernetes/issues/42392
		appsrest.StorageProvider{},
		admissionregistrationrest.RESTStorageProvider{Authorizer: c.GenericConfig.Authorization.Authorizer, DiscoveryClient: discoveryClientForAdmissionRegistration},
		eventsrest.RESTStorageProvider{TTL: c.ExtraConfig.EventTTL},
		resourcerest.RESTStorageProvider{},
	}
	// 注册API
	if err := m.InstallAPIs(c.ExtraConfig.APIResourceConfigSource, c.GenericConfig.RESTOptionsGetter, restStorageProviders...); err != nil {
		return nil, err
	}

	
    // 。。
	

	return m, nil
}
```

注册API的关键在InstallLegacyAPI和InstallAPIs


```go
// non-legacy API group 和 legacy APIs  路由前缀区别
const (
	// DefaultLegacyAPIPrefix is where the legacy APIs will be located.
	DefaultLegacyAPIPrefix = "/api"

	// APIGroupPrefix is where non-legacy API group will be located.
	APIGroupPrefix = "/apis"
)
```

```go
func (m *Instance) InstallLegacyAPI(c *completedConfig, restOptionsGetter generic.RESTOptionsGetter) error {
	legacyRESTStorageProvider := corerest.LegacyRESTStorageProvider{
		StorageFactory:              c.ExtraConfig.StorageFactory,
		ProxyTransport:              c.ExtraConfig.ProxyTransport,
		KubeletClientConfig:         c.ExtraConfig.KubeletClientConfig,
		EventTTL:                    c.ExtraConfig.EventTTL,
		ServiceIPRange:              c.ExtraConfig.ServiceIPRange,
		SecondaryServiceIPRange:     c.ExtraConfig.SecondaryServiceIPRange,
		ServiceNodePortRange:        c.ExtraConfig.ServiceNodePortRange,
		LoopbackClientConfig:        c.GenericConfig.LoopbackClientConfig,
		ServiceAccountIssuer:        c.ExtraConfig.ServiceAccountIssuer,
		ExtendExpiration:            c.ExtraConfig.ExtendExpiration,
		ServiceAccountMaxExpiration: c.ExtraConfig.ServiceAccountMaxExpiration,
		APIAudiences:                c.GenericConfig.Authentication.APIAudiences,
		Informers:                   c.ExtraConfig.VersionedInformers,
	}
	legacyRESTStorage, apiGroupInfo, err := legacyRESTStorageProvider.NewLegacyRESTStorage(c.ExtraConfig.APIResourceConfigSource, restOptionsGetter)
    // ...

	if err := m.GenericAPIServer.InstallLegacyAPIGroup(genericapiserver.DefaultLegacyAPIPrefix, &apiGroupInfo); err != nil {
		return fmt.Errorf("error in registering group versions: %v", err)
	}
	return nil
}
```

```go
func (c LegacyRESTStorageProvider) NewLegacyRESTStorage(apiResourceConfigSource serverstorage.APIResourceConfigSource, restOptionsGetter generic.RESTOptionsGetter) (LegacyRESTStorage, genericapiserver.APIGroupInfo, error) {
	apiGroupInfo := genericapiserver.APIGroupInfo{
		PrioritizedVersions:          legacyscheme.Scheme.PrioritizedVersionsForGroup(""),
		VersionedResourcesStorageMap: map[string]map[string]rest.Storage{},
		Scheme:                       legacyscheme.Scheme,
		ParameterCodec:               legacyscheme.ParameterCodec,
		NegotiatedSerializer:         legacyscheme.Codecs,
	}

	podDisruptionClient, err := policyclient.NewForConfig(c.LoopbackClientConfig)
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}
	restStorage := LegacyRESTStorage{}
    //  PodTemplate 资源的 RESTStorage 初始化
	podTemplateStorage, err := podtemplatestore.NewREST(restOptionsGetter)
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}
    // event事件
	eventStorage, err := eventstore.NewREST(restOptionsGetter, uint64(c.EventTTL.Seconds()))
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}
	// limitRange资源限制
	limitRangeStorage, err := limitrangestore.NewREST(restOptionsGetter)
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}
	// resourceQuota资源配额
	resourceQuotaStorage, resourceQuotaStatusStorage, err := resourcequotastore.NewREST(restOptionsGetter)
    // 等等核心资源，暂不一一列举
	// ...

	// 将资源和对应的 RESTStorage 进行绑定
	storage := map[string]rest.Storage{}
    if resource := "pods"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
        storage[resource] = podStorage.Pod
        storage[resource+"/attach"] = podStorage.Attach
        storage[resource+"/status"] = podStorage.Status
        storage[resource+"/log"] = podStorage.Log
        storage[resource+"/exec"] = podStorage.Exec
        storage[resource+"/portforward"] = podStorage.PortForward
        storage[resource+"/proxy"] = podStorage.Proxy
        storage[resource+"/binding"] = podStorage.Binding
        if podStorage.Eviction != nil {
            storage[resource+"/eviction"] = podStorage.Eviction
        }
        storage[resource+"/ephemeralcontainers"] = podStorage.EphemeralContainers
    
    }

	if resource := "bindings"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = podStorage.LegacyBinding
	}

	if resource := "podtemplates"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = podTemplateStorage
	}

	if resource := "replicationcontrollers"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = controllerStorage.Controller
		storage[resource+"/status"] = controllerStorage.Status
		if legacyscheme.Scheme.IsVersionRegistered(schema.GroupVersion{Group: "autoscaling", Version: "v1"}) {
			storage[resource+"/scale"] = controllerStorage.Scale
		}
	}

	if resource := "services"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = serviceRESTStorage
		storage[resource+"/proxy"] = serviceRESTProxy
		storage[resource+"/status"] = serviceStatusStorage
	}

	if resource := "endpoints"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = endpointsStorage
	}

	if resource := "nodes"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = nodeStorage.Node
		storage[resource+"/proxy"] = nodeStorage.Proxy
		storage[resource+"/status"] = nodeStorage.Status
	}

	if resource := "events"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = eventStorage
	}

    // 等等其他资源...

	if len(storage) > 0 {
		apiGroupInfo.VersionedResourcesStorageMap["v1"] = storage
	}

	return restStorage, apiGroupInfo, nil
}

```

{{<figure src="./rest_storage.png#center" width=800px >}}

这里拿 pod 作为案例

```go
// https://github.com/kubernetes/kubernetes/blob/62889f416cb60f66b3f04810ef2475c425b8394a/pkg/registry/core/pod/storage/storage.go
func NewStorage(optsGetter generic.RESTOptionsGetter, k client.ConnectionInfoGetter, proxyTransport http.RoundTripper, podDisruptionBudgetClient policyclient.PodDisruptionBudgetsGetter) (PodStorage, error) {
	store := &genericregistry.Store{
		NewFunc:                   func() runtime.Object { return &api.Pod{} }, //返回特定资源信息
		NewListFunc:               func() runtime.Object { return &api.PodList{} }, //返回特定资源列表
		PredicateFunc:             registrypod.MatchPod,
		DefaultQualifiedResource:  api.Resource("pods"),
		SingularQualifiedResource: api.Resource("pod"),
        // 增改删的策略
		CreateStrategy:      registrypod.Strategy, // 特定资源创建时的策略
		UpdateStrategy:      registrypod.Strategy,
		DeleteStrategy:      registrypod.Strategy,
		ResetFieldsStrategy: registrypod.Strategy,
		ReturnDeletedObject: true,

		TableConvertor: printerstorage.TableConvertor{TableGenerator: printers.NewTableGenerator().With(printersinternal.AddHandlers)},
	}
	// Store 配置
	options := &generic.StoreOptions{
		RESTOptions: optsGetter,
		AttrFunc:    registrypod.GetAttrs,
		TriggerFunc: map[string]storage.IndexerFunc{"spec.nodeName": registrypod.NodeNameTriggerFunc},
		Indexers:    registrypod.Indexers(),
	}
	if err := store.CompleteWithOptions(options); err != nil {
		return PodStorage{}, err
	}

	statusStore := *store
	statusStore.UpdateStrategy = registrypod.StatusStrategy
	statusStore.ResetFieldsStrategy = registrypod.StatusStrategy
	ephemeralContainersStore := *store
	ephemeralContainersStore.UpdateStrategy = registrypod.EphemeralContainersStrategy

	bindingREST := &BindingREST{store: store}
	return PodStorage{
		Pod:                 &REST{store, proxyTransport},
		Binding:             &BindingREST{store: store},
		LegacyBinding:       &LegacyBindingREST{bindingREST},
		Eviction:            newEvictionStorage(&statusStore, podDisruptionBudgetClient),
		Status:              &StatusREST{store: &statusStore},
		EphemeralContainers: &EphemeralContainersREST{store: &ephemeralContainersStore},
		Log:                 &podrest.LogREST{Store: store, KubeletConn: k},
		Proxy:               &podrest.ProxyREST{Store: store, ProxyTransport: proxyTransport},
		Exec:                &podrest.ExecREST{Store: store, KubeletConn: k},
		Attach:              &podrest.AttachREST{Store: store, KubeletConn: k},
		PortForward:         &podrest.PortForwardREST{Store: store, KubeletConn: k},
	}, nil
}
```

```go
func (e *Store) CompleteWithOptions(options *generic.StoreOptions) error {
    // 相关校验
	// ...
	opts, err := options.RESTOptions.GetRESTOptions(e.DefaultQualifiedResource)
    
	// 存储
	if e.Storage.Storage == nil {
		e.Storage.Codec = opts.StorageConfig.Codec
		var err error
		e.Storage.Storage, e.DestroyFunc, err = opts.Decorator(
			opts.StorageConfig,
			prefix,
			keyFunc,
			e.NewFunc,
			e.NewListFunc,
			attrFunc,
			options.TriggerFunc,
			options.Indexers,
		)
		if err != nil {
			return err
		}
		e.StorageVersioner = opts.StorageConfig.EncodeVersioner

        // ...
	}

	return nil
}

```

### aggregatorServer 

负责处理  apiregistration.k8s.io 组下的 APIService 资源请求，同时将来自用户的请求拦截转发给 Aggregated APIServer(AA)；

```yaml
apiVersion: apiregistration.k8s.io/v1beta1
kind: APIService
metadata:
  name: v1alpha1.custom-metrics.metrics.k8s.io
spec:
  insecureSkipTLSVerify: true
  group: custom-metrics.metrics.k8s.io
  groupPriorityMinimum: 1000
  versionPriority: 15
  service:
    name: api
    namespace: custom-metrics
  version: v1alpha1

```

```go
func createAggregatorServer(aggregatorConfig *aggregatorapiserver.Config, delegateAPIServer genericapiserver.DelegationTarget, apiExtensionInformers apiextensionsinformers.SharedInformerFactory, crdAPIEnabled bool) (*aggregatorapiserver.APIAggregator, error) {
	// 初始化delegate
	aggregatorServer, err := aggregatorConfig.Complete().NewWithDelegate(delegateAPIServer)
	if err != nil {
		return nil, err
	}

	// 创建autoRegistrationController
	apiRegistrationClient, err := apiregistrationclient.NewForConfig(aggregatorConfig.GenericConfig.LoopbackClientConfig)
	if err != nil {
		return nil, err
	}
	autoRegistrationController := autoregister.NewAutoRegisterController(aggregatorServer.APIRegistrationInformers.Apiregistration().V1().APIServices(), apiRegistrationClient)
	// apiService
	apiServices := apiServicesToRegister(delegateAPIServer, autoRegistrationController)
	// 创建crdRegistrationController
	crdRegistrationController := crdregistration.NewCRDRegistrationController(
		apiExtensionInformers.Apiextensions().V1().CustomResourceDefinitions(),
		autoRegistrationController)

	// Imbue all builtin group-priorities onto the aggregated discovery
	if aggregatorConfig.GenericConfig.AggregatedDiscoveryGroupManager != nil {
		for gv, entry := range apiVersionPriorities {
			aggregatorConfig.GenericConfig.AggregatedDiscoveryGroupManager.SetGroupVersionPriority(metav1.GroupVersion(gv), int(entry.group), int(entry.version))
		}
	}

	err = aggregatorServer.GenericAPIServer.AddPostStartHook("kube-apiserver-autoregistration", func(context genericapiserver.PostStartHookContext) error {
		// 启动crdRegistrationController
		go crdRegistrationController.Run(5, context.StopCh)
		go func() {
			// let the CRD controller process the initial set of CRDs before starting the autoregistration controller.
			// this prevents the autoregistration controller's initial sync from deleting APIServices for CRDs that still exist.
			// we only need to do this if CRDs are enabled on this server.  We can't use discovery because we are the source for discovery.
			if crdAPIEnabled {
				klog.Infof("waiting for initial CRD sync...")
				crdRegistrationController.WaitForInitialSync()
				klog.Infof("initial CRD sync complete...")
			} else {
				klog.Infof("CRD API not enabled, starting APIService registration without waiting for initial CRD sync")
			}
			// 启动autoRegistrationController
			autoRegistrationController.Run(5, context.StopCh)
		}()
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = aggregatorServer.GenericAPIServer.AddBootSequenceHealthChecks(
		makeAPIServiceAvailableHealthCheck(
			"autoregister-completion",
			apiServices,
			aggregatorServer.APIRegistrationInformers.Apiregistration().V1().APIServices(),
		),
	)
	if err != nil {
		return nil, err
	}

	return aggregatorServer, nil
}

```


## 参考

- [APIServer的认证机制](https://github.com/yinwenqin/kubeSourceCodeNote/blob/master/apiServer/Kubernetes%E6%BA%90%E7%A0%81%E5%AD%A6%E4%B9%A0-APIServer-P3-APIServer%E7%9A%84%E8%AE%A4%E8%AF%81%E6%9C%BA%E5%88%B6.md)
- [APIServer的鉴权机制](https://github.com/yinwenqin/kubeSourceCodeNote/blob/master/apiServer/Kubernetes%E6%BA%90%E7%A0%81%E5%AD%A6%E4%B9%A0-APIServer-P4-APIServer%E7%9A%84%E9%89%B4%E6%9D%83%E6%9C%BA%E5%88%B6.md)
- [ApiServer之三大server及权限与数据存储](https://juejin.cn/post/7154591873066565668#heading-8)
- [k8s源码分析（2）- kube-apiserver](https://cloud.tencent.com/developer/article/1717417)