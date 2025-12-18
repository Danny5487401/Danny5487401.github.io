---
title: "OpenID Connect 协议(OIDC 协议)"
date: 2025-12-10T15:24:29+08:00
summary: "oidc ,配置keycloak 在argo-workflow 中使用"
categories:
  - oidc
---


OAuth是一个关于授权（authorization）的开放网络标准.

OpenID Connect 是在OAuth2.0 协议基础上增加了身份验证层 （identity layer）。
OAuth 2.0 定义了通过access token去获取请求资源的机制，但是没有定义提供用户身份信息的标准方法。
OpenID Connect作为OAuth2.0的扩展，实现了Authentication的流程。OpenID Connect根据用户的 id_token 来验证用户，并获取用户的基本信息。

而 OIDC 的登录过程与 OAuth 相比，最主要的扩展就是提供了 ID Token.
id_token通常是JWT（Json Web Token），JWT有三部分组成，header，body，signature。




## 授权方式

OAuth 2.0定义了四种授权方式。

- 授权码模式（authorization code）: 适用于拥有服务器端能力的 Web 应用。用户授权后，客户端获取授权码，再通过后台请求换取访问令牌，避免暴露敏感信息
- 简化模式（implicit）: 用于纯前端应用（如 SPA），直接返回令牌，但安全性较低，不推荐高敏感场景。
- 密码模式（resource owner password credentials）: 用户直接提供用户名和密码换取令牌，仅适用于高度信任的客户端，如自有客户端与自有服务。
- 客户端模式（client credentials）,也叫应用授信模式: 适用于服务间通信，无用户参与，使用客户端自身凭证获取访问权限。


### 授权码模式（authorization code）

{{<figure src="./featured.png#center" width=800px >}}

{{<figure src="./authorization_code_without_id_token.png#center" width=800px >}}

1. 用户访问客户端，客户端将用户重定向到认证服务器；（我需要访问这个用户在你的服务器上的数据！）
1. 你的服务器询问用户是否同意授权，要求用户输入用户名和密码，并弹出对方请求获取的信息条目（好的，我先问问用户是否同意你获取这些信息）
1. 返回一个授权码给三方应用前端（或后端）。（把这个授权码给你的后端，让他凭此来获取 token！）
1. 三方应用后端携带这个授权码向你服务器的 token 颁发接口请求数据。（请给我一个 token，授权码是 xxx）
1. 返回 id_token, access_token。(好的，这是你的 token，可以携带 access_token 去用户信息接口获取数据)




## OAuth 中心组件

### 1 OAuth Scopes

Scopes即Authorization时的一些请求权限，即与access token绑定在一起的一组权限。


### 2 OAuth Tokens
Token从Authorization server上的不同的endpoint获取。主要两个endpoint为authorize endpoint和token endpoint.

authorize endpoint主要用来获得来自用户的许可和授权(consent and authorization)，并将用户的授权信息传递给token endpoint。
token endpoint对用户的授权信息，处理之后返回access token和refresh token

### 3 OAuth Actors

有一个"云冲印"的网站，可以将用户储存在Google的照片，冲印出来。用户为了使用该服务，必须让"云冲印"读取自己储存在Google上的照片

（1）Third-party application：第三方应用程序，本文中又称"客户端"（client），即例子中的"云冲印"。

（2）HTTP service：HTTP服务提供商，本文中简称"服务提供商"，即上一节例子中的Google。

（3）Resource Owner：资源所有者，本文中又称"用户"（user）。

（4）User Agent：用户代理，本文中就是指浏览器。

（5）Authorization server：认证服务器，即服务提供商专门用来处理认证的服务器。

（6）Resource server：资源服务器，即服务提供商存放用户生成的资源的服务器。它与认证服务器，可以是同一台服务器，也可以是不同的服务器。



## OIDC provider


- github.com/keycloak/keycloak：企业级协议强者（SAML/OAuth/LDAP），适用于需要细粒度访问控制及自建部署的大型组织。

- github.com/casdoor/casdoor：以 Web UI 为中心的 IAM 与 SSO 平台，支持 OAuth 2.0、OIDC、SAML、CAS、LDAP 和 SCIM。

- github.com/dexidp/dex




### keycloak

Keycloak实现了业内常见的认证授权协议和通用的安全技术，主要有：

- 浏览器应用程序的单点登录（SSO）。
- OIDC认证授权。
- OAuth 2.0。
- SAML。

#### OpenID Provider 元数据
```shell
(⎈|kind-cilium-cluster:nacos)➜  ~ curl -s http://keycloak.keycloak:8080/realms/myrealm/.well-known/openid-configuration  | jq .
{
  "issuer": "http://keycloak.keycloak:8080/realms/myrealm",
  "authorization_endpoint": "http://keycloak.keycloak:8080/realms/myrealm/protocol/openid-connect/auth",
  "token_endpoint": "http://keycloak.keycloak:8080/realms/myrealm/protocol/openid-connect/token",
  "introspection_endpoint": "http://keycloak.keycloak:8080/realms/myrealm/protocol/openid-connect/token/introspect",
  "userinfo_endpoint": "http://keycloak.keycloak:8080/realms/myrealm/protocol/openid-connect/userinfo",
  "end_session_endpoint": "http://keycloak.keycloak:8080/realms/myrealm/protocol/openid-connect/logout",
  "frontchannel_logout_session_supported": true,
  "frontchannel_logout_supported": true,
  "jwks_uri": "http://keycloak.keycloak:8080/realms/myrealm/protocol/openid-connect/certs",
  "check_session_iframe": "http://keycloak.keycloak:8080/realms/myrealm/protocol/openid-connect/login-status-iframe.html",
  "grant_types_supported": [
    "authorization_code",
    "client_credentials",
    "implicit",
    "password",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code",
    "urn:ietf:params:oauth:grant-type:token-exchange",
    "urn:ietf:params:oauth:grant-type:uma-ticket",
    "urn:openid:params:grant-type:ciba"
  ],
  "acr_values_supported": [
    "0",
    "1"
  ],
  "response_types_supported": [
    "code",
    "none",
    "id_token",
    "token",
    "id_token token",
    "code id_token",
    "code token",
    "code id_token token"
  ],
  "subject_types_supported": [
    "public",
    "pairwise"
  ],
  "prompt_values_supported": [
    "none",
    "login",
    "consent"
  ],
  # ...
  "response_modes_supported": [
    "query",
    "fragment",
    "form_post",
    "query.jwt",
    "fragment.jwt",
    "form_post.jwt",
    "jwt"
  ],
  "registration_endpoint": "http://keycloak.keycloak:8080/realms/myrealm/clients-registrations/openid-connect",
  "token_endpoint_auth_methods_supported": [
    "private_key_jwt",
    "client_secret_basic",
    "client_secret_post",
    "tls_client_auth",
    "client_secret_jwt"
  ],
  "token_endpoint_auth_signing_alg_values_supported": [
    "PS384",
    "RS384",
    "EdDSA",
    "ES384",
    "HS256",
    "HS512",
    "ES256",
    "RS256",
    "HS384",
    "ES512",
    "PS256",
    "PS512",
    "RS512"
  ],
  "introspection_endpoint_auth_methods_supported": [
    "private_key_jwt",
    "client_secret_basic",
    "client_secret_post",
    "tls_client_auth",
    "client_secret_jwt"
  ],
  # ....
  "claims_supported": [
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "name",
    "given_name",
    "family_name",
    "preferred_username",
    "email",
    "acr",
    "azp",
    "nonce"
  ],
  "claim_types_supported": [
    "normal"
  ],
  "claims_parameter_supported": true,
  "scopes_supported": [
    "openid",
    "offline_access",
    "address",
    "profile",
    "microprofile-jwt",
    "web-origins",
    "phone",
    "danny_test_client_scope",
    "acr",
    "basic",
    "service_account",
    "email",
    "roles",
    "organization"
  ],
  "request_parameter_supported": true,
  "request_uri_parameter_supported": true,
  "require_request_uri_registration": true,
  "code_challenge_methods_supported": [
    "plain",
    "S256"
  ],
  "tls_client_certificate_bound_access_tokens": true,
  "dpop_signing_alg_values_supported": [
    "PS384",
    "RS384",
    "EdDSA",
    "ES384",
    "ES256",
    "RS256",
    "ES512",
    "PS256",
    "PS512",
    "RS512"
  ],
  "revocation_endpoint": "http://keycloak.keycloak:8080/realms/myrealm/protocol/openid-connect/revoke",
  "revocation_endpoint_auth_methods_supported": [
    "private_key_jwt",
    "client_secret_basic",
    "client_secret_post",
    "tls_client_auth",
    "client_secret_jwt"
  ],
  "revocation_endpoint_auth_signing_alg_values_supported": [
    "PS384",
    "RS384",
    "EdDSA",
    "ES384",
    "HS256",
    "HS512",
    "ES256",
    "RS256",
    "HS384",
    "ES512",
    "PS256",
    "PS512",
    "RS512"
  ],
  "backchannel_logout_supported": true,
  "backchannel_logout_session_supported": true,
  "device_authorization_endpoint": "http://keycloak.keycloak:8080/realms/myrealm/protocol/openid-connect/auth/device",
  "backchannel_token_delivery_modes_supported": [
    "poll",
    "ping"
  ],
  "backchannel_authentication_endpoint": "http://keycloak.keycloak:8080/realms/myrealm/protocol/openid-connect/ext/ciba/auth",
  "backchannel_authentication_request_signing_alg_values_supported": [
    "PS384",
    "RS384",
    "EdDSA",
    "ES384",
    "ES256",
    "RS256",
    "ES512",
    "PS256",
    "PS512",
    "RS512"
  ],
  "require_pushed_authorization_requests": false,
  "pushed_authorization_request_endpoint": "http://keycloak.keycloak:8080/realms/myrealm/protocol/openid-connect/ext/par/request",
  "mtls_endpoint_aliases": {
    "token_endpoint": "http://keycloak.keycloak:8080/realms/myrealm/protocol/openid-connect/token",
    "revocation_endpoint": "http://keycloak.keycloak:8080/realms/myrealm/protocol/openid-connect/revoke",
    "introspection_endpoint": "http://keycloak.keycloak:8080/realms/myrealm/protocol/openid-connect/token/introspect",
    "device_authorization_endpoint": "http://keycloak.keycloak:8080/realms/myrealm/protocol/openid-connect/auth/device",
    "registration_endpoint": "http://keycloak.keycloak:8080/realms/myrealm/clients-registrations/openid-connect",
    "userinfo_endpoint": "http://keycloak.keycloak:8080/realms/myrealm/protocol/openid-connect/userinfo",
    "pushed_authorization_request_endpoint": "http://keycloak.keycloak:8080/realms/myrealm/protocol/openid-connect/ext/par/request",
    "backchannel_authentication_endpoint": "http://keycloak.keycloak:8080/realms/myrealm/protocol/openid-connect/ext/ciba/auth"
  },
  "authorization_response_iss_parameter_supported": true
}
```


provider 初始化
```go
// github.com/coreos/go-oidc/v3@v3.14.1/oidc/oidc.go

func NewProvider(ctx context.Context, issuer string) (*Provider, error) {
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequest("GET", wellKnown, nil)
    // ...

	// 解析数据
	var p providerJSON
	err = unmarshalResp(resp, body, &p)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to decode provider discovery object: %v", err)
	}

	issuerURL, skipIssuerValidation := ctx.Value(issuerURLKey).(string)
	if !skipIssuerValidation {
		issuerURL = issuer
	}
	if p.Issuer != issuerURL && !skipIssuerValidation {
		return nil, fmt.Errorf("oidc: issuer did not match the issuer returned by provider, expected %q got %q", issuer, p.Issuer)
	}
	var algs []string
	for _, a := range p.Algorithms {
		if supportedAlgorithms[a] {
			algs = append(algs, a)
		}
	}
	return &Provider{
		issuer:        issuerURL,
		authURL:       p.AuthURL,
		tokenURL:      p.TokenURL,
		deviceAuthURL: p.DeviceAuthURL,
		userInfoURL:   p.UserInfoURL,
		jwksURL:       p.JWKSURL,
		algorithms:    algs,
		rawClaims:     body,
		client:        getClient(ctx),
	}, nil
}
```

#### keycloak 基本概念

##### Realm 领域
realm是管理用户和对应应用的空间

{{<figure src="./keycloak_realm.png#center" width=800px >}}

Master Realm中的管理员账户有权查看和管理在Keycloak服务器实例上创建的任何其它Realm。
其它Realm是指用Master创建的Realm。


Keycloak 中的角色有两种类型：
- Realm Roles: 跨越整个 Realm（域）使用的角色，适用于所有客户端。
- Client Roles: 特定客户端（应用程序）的角色，仅对某个客户端有效

##### scope 授权的范围

##### client 客户端
通常指一些需要向keycloak请求以认证一个用户的应用或者服务，甚至可以说寻求keycloak保护并在keycloak上注册的请求实体都是客户端。

##### client scope
{{<figure src="./client_scope.png#center" width=800px >}}

keycloak中的client-scope允许你为每个客户端分配scope，而scope就是授权范围，它直接影响了token中的内容，及userinfo端点可以获取到的用户信息，

##### 授权服务
授权服务包括下列三种REST端点：

- Token Endpoint
- Resource Management Endpoint
- Permission Management Endpoint


#### 自定义协议 Mapper


## 第三方应用--> argo workflow

内置的角色包括（以下都是 ClusterRole）：

argo-aggregate-to-view

argo-aggregate-to-edit

argo-aggregate-to-admin

argo-cluster-role，没有 workfloweventbindings 的权限

argo-server-cluster-role，包含所有需要的权限


初始化 sso
```go
func newSso(
	factory providerFactory,
	c Config,
	secretsIf corev1.SecretInterface,
	baseHRef string,
	secure bool,
) (Interface, error) {
    // ...

    // ClientID 与 ClientSecret 由授权服务器分配，Scopes 指定权限范围，Endpoint 对应授权与令牌端点。
	config := &oauth2.Config{
		ClientID:     string(clientID),
		ClientSecret: string(clientSecret),
		RedirectURL:  c.RedirectURL,
		Endpoint:     provider.Endpoint(), // AuthURL,TokenURL 等
		Scopes:       append(c.Scopes, oidc.ScopeOpenID),
	}
	idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: privateKey.Public()}, &jose.EncrypterOptions{Compression: jose.DEFLATE})
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT encrpytor: %w", err)
	}

	var filterGroupsRegex []*regexp.Regexp
	if len(c.FilterGroupsRegex) > 0 {
		for _, regex := range c.FilterGroupsRegex {
			compiledRegex, err := regexp.Compile(regex)
			if err != nil {
				return nil, fmt.Errorf("failed to compile sso.filterGroupRegex: %s %w", regex, err)
			}
			filterGroupsRegex = append(filterGroupsRegex, compiledRegex)
		}
	}

	lf := log.Fields{"redirectUrl": config.RedirectURL, "issuer": c.Issuer, "issuerAlias": "DISABLED", "clientId": c.ClientID, "scopes": config.Scopes, "insecureSkipVerify": c.InsecureSkipVerify, "filterGroupsRegex": c.FilterGroupsRegex}
	if c.IssuerAlias != "" {
		lf["issuerAlias"] = c.IssuerAlias
	}
	log.WithFields(lf).Info("SSO configuration")

	return &sso{
		config:            config,
		idTokenVerifier:   idTokenVerifier,
		baseHRef:          baseHRef,
		httpClient:        httpClient,
		secure:            secure,
		privateKey:        privateKey,
		encrypter:         encrypter,
		rbacConfig:        c.RBAC,
		expiry:            c.GetSessionExpiry(),
		customClaimName:   c.CustomGroupClaimName,
		userInfoPath:      c.UserInfoPath,
		issuer:            c.Issuer,
		filterGroupsRegex: filterGroupsRegex,
	}, nil
}

```

调用地址

```shell
http://keycloak.keycloak.svc.cluster.local:8080/realms/myrealm/protocol/openid-connect/auth?
client_id=argo-workflow&redirect_uri=https://localhost:2746/oauth2/callback&response_type=code&scope=groups email profile openid&state=8dc3decc9f
```


/oauth2/redirect 处理 
```go
func (s *sso) HandleRedirect(w http.ResponseWriter, r *http.Request) {
	finalRedirectURL := r.URL.Query().Get("redirect")
	if !isValidFinalRedirectURL(finalRedirectURL) {
		finalRedirectURL = s.baseHRef
	}
	state, err := pkgrand.RandString(10)
	if err != nil {
		log.WithError(err).Error("failed to create state")
		w.WriteHeader(500)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     state,
		Value:    finalRedirectURL,
		Expires:  time.Now().Add(3 * time.Minute),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secure,
	})

	redirectOption := oauth2.SetAuthURLParam("redirect_uri", s.getRedirectURL(r))
	// 定向到 auth endpoint 
	http.Redirect(w, r, s.config.AuthCodeURL(state, redirectOption), http.StatusFound)
}

```

客户端申请授权，重定向到认证服务器的URI中需要包含这些参数：
```go
func (c *Config) AuthCodeURL(state string, opts ...AuthCodeOption) string {
	var buf bytes.Buffer
	buf.WriteString(c.Endpoint.AuthURL)
	v := url.Values{
		"response_type": {"code"}, // 授权类型，此处的值为code, 必须
		"client_id":     {c.ClientID}, // 客户端ID，客户端到资源服务器注册的ID	必须
	} 
	if c.RedirectURL != "" { // 重定向URI	可选
		v.Set("redirect_uri", c.RedirectURL)
	}
	if len(c.Scopes) > 0 { // 申请的权限范围，多个逗号隔开	可选
		v.Set("scope", strings.Join(c.Scopes, " "))
	}
	if state != "" { // 客户端的当前状态，可以指定任意值，认证服务器会原封不动的返回这个值	推荐
		v.Set("state", state)
	}
	for _, opt := range opts {
		opt.setValue(v)
	}
	if strings.Contains(c.Endpoint.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	return buf.String()
}
```


调用地址

```shell
https://localhost:2746/oauth2/callback?
state=14d97e5995&session_state=e88425bf-d9ef-b206-1c09-00a9e5cab71b&iss=http://keycloak.keycloak.svc.cluster.local:8080/realms/myrealm&code=88f91156-e4c2-5d54-0ad3-84eb30a74bfc.e88425bf-d9ef-b206-1c09-00a9e5cab71b.30f2278c-0d09-447a-8dcf-2d95defd4e95
```
/oauth2/callback 处理

```go
// https://github.com/argoproj/argo-workflows/blob/a4f457eace1193b07f81999f31243f99ff620966/server/auth/sso/sso.go

func (s *sso) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie(state)
	http.SetCookie(w, &http.Cookie{Name: state, MaxAge: 0})
	if err != nil {
		log.WithError(err).Error("failed to get cookie")
		w.WriteHeader(400)
		return
	}
	
	// 将 authorization code 转成 token 
	redirectOption := oauth2.SetAuthURLParam("redirect_uri", s.getRedirectURL(r))
	// Use sso.httpClient in order to respect TLSOptions
	oauth2Context := context.WithValue(ctx, oauth2.HTTPClient, s.httpClient)
	oauth2Token, err := s.config.Exchange(oauth2Context, r.URL.Query().Get("code"), redirectOption)
	if err != nil {
		log.WithError(err).Error("failed to get oauth2Token by using code from the oauth2 server")
		w.WriteHeader(401)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		log.Error("failed to extract id_token from the response")
		w.WriteHeader(401)
		return
	}
	idToken, err := s.idTokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.WithError(err).Error("failed to verify the id token issued")
		w.WriteHeader(401)
		return
	}
	c := &types.Claims{}
	if err := idToken.Claims(c); err != nil {
		log.WithError(err).Error("failed to get claims from the id token")
		w.WriteHeader(401)
		return
	}
	// Default to groups claim but if customClaimName is set
	// extract groups based on that claim key
	groups := c.Groups
	if s.customClaimName != "" {
		groups, err = c.GetCustomGroup(s.customClaimName)
		if err != nil {
			log.Warn(err)
		}
	}
	// Some SSO implementations (Okta) require a call to
	// the OIDC user info path to get attributes like groups
	if s.userInfoPath != "" {
		groups, err = c.GetUserInfoGroups(s.httpClient, oauth2Token.AccessToken, s.issuer, s.userInfoPath)
		if err != nil {
			log.WithError(err).Errorf("failed to get groups claim from the given userInfoPath(%s)", s.userInfoPath)
			w.WriteHeader(401)
			return
		}
	}

	// only return groups that match at least one of the regexes
	if len(s.filterGroupsRegex) > 0 {
		var filteredGroups []string
		for _, group := range groups {
			for _, regex := range s.filterGroupsRegex {
				if regex.MatchString(group) {
					filteredGroups = append(filteredGroups, group)
					break
				}
			}
		}
		groups = filteredGroups
	}

	argoClaims := &types.Claims{
		Claims: jwt.Claims{
			Issuer:  issuer,
			Subject: c.Subject,
			Expiry:  jwt.NewNumericDate(time.Now().Add(s.expiry)),
		},
		Groups:                  groups,
		Email:                   c.Email,
		EmailVerified:           c.EmailVerified,
		Name:                    c.Name,
		ServiceAccountName:      c.ServiceAccountName,
		PreferredUsername:       c.PreferredUsername,
		ServiceAccountNamespace: c.ServiceAccountNamespace,
	}
	raw, err := jwt.Encrypted(s.encrypter).Claims(argoClaims).CompactSerialize()
	if err != nil {
		log.WithError(err).Errorf("failed to encrypt and serialize the jwt token")
		w.WriteHeader(401)
		return
	}
	value := Prefix + raw
	log.Debugf("handing oauth2 callback %v", value)
	http.SetCookie(w, &http.Cookie{
		Value:    value,
		Name:     "authorization",
		Path:     s.baseHRef,
		Expires:  time.Now().Add(s.expiry),
		SameSite: http.SameSiteStrictMode,
		Secure:   s.secure,
	})

	finalRedirectURL := cookie.Value
	if !isValidFinalRedirectURL(cookie.Value) {
		finalRedirectURL = s.baseHRef

	}
	http.Redirect(w, r, finalRedirectURL, http.StatusFound)
}
```

## 参考
- https://datatracker.ietf.org/doc/html/rfc6749
- https://www.keycloak.org/server/configuration
- [理解 OIDC 流程](https://old-docs.authing.cn/authentication/oidc/understand-oidc.html)
- [理解OAuth 2.0](https://www.ruanyifeng.com/blog/2014/05/oauth_2_0.html)
- [Keycloak 梳理](https://juejin.cn/post/7087587016610840589)