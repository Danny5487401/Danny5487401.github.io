---
title: "OpenID Connect 协议(OIDC 协议)"
date: 2025-12-10T15:24:29+08:00
summary: "oidc ,配置keycloak 在argo-workflow 中使用"
categories:
  - oidc
---


OAuth 是一个关于授权（authorization）的开放网络标准.

OpenID Connect 是在OAuth2.0 协议基础上增加了身份验证层 （identity layer）。
OAuth 2.0 定义了通过access token去获取请求资源的机制，但是没有定义提供用户身份信息的标准方法。
OpenID Connect作为OAuth2.0的扩展，实现了Authentication的流程。OpenID Connect根据用户的 id_token 来验证用户，并获取用户的基本信息。

而 OIDC 的登录过程与 OAuth 相比，最主要的扩展就是提供了 ID Token.
id_token通常是JWT（Json Web Token），JWT有三部分组成，header，body，signature。




## 授权方式

{{<figure src="./keycloak_ authentication_flow.png#center" width=800px >}}

OAuth 2.0定义了四种授权方式,这四种授权方式在 Keycloak 客户端的 `Capability config` 中对应以下开关：

| OAuth 2.0 授权方式 | `grant_type` | Keycloak 开关 | 说明 |
| --- | --- | --- | --- |
| 授权码模式 | `authorization_code` | `Standard flow` | 启用 OIDC Authorization Code Flow；服务端客户端通常还需开启 `Client authentication`，纯前端公共客户端建议配合 PKCE |
| 简化模式 | `implicit` | `Implicit flow` | 启用 OIDC Implicit Flow；该模式安全性较低，不推荐新应用使用 |
| 密码模式 | `password` | `Direct access grants` | Keycloak 将 Resource Owner Password Credentials 称为 Direct Access Grants；不推荐新应用使用 |
| 客户端模式（应用授信模式） | `client_credentials` | `Service accounts roles` | 必须同时开启 `Client authentication`，并在 `Service account roles` 中为服务账号分配所需角色 |

`Authorization` 开关用于启用 Keycloak 的细粒度授权服务，并不对应授权码模式。`OAuth 2.0 Device Authorization Grant` 和 `OIDC CIBA Grant` 则是前述四种方式之外的扩展授权流程。


### 授权码模式（authorization code）



{{<figure src="./authorization_code_without_id_token.png#center" width=800px >}}

1. 用户访问客户端，客户端将用户重定向到认证服务器；（我需要访问这个用户在你的服务器上的数据！）
1. 你的服务器询问用户是否同意授权，要求用户输入用户名和密码，并弹出对方请求获取的信息条目（好的，我先问问用户是否同意你获取这些信息）
1. 返回一个授权码给三方应用前端（或后端）。（把这个授权码给你的后端，让他凭此来获取 token！）
1. 三方应用后端携带这个授权码向你服务器的 token 颁发接口请求数据。（请给我一个 token，授权码是 xxx）
1. 返回 id_token, access_token。(好的，这是你的 token，可以携带 access_token 去用户信息接口获取数据)



### 扩展一: Device Authorization Flow

标准的 Authorization Code Flow 依赖浏览器重定向，用户需要在授权页面输入账号密码并点击同意。但对于以下场景，这套流程完全行不通：

- 智能电视 / 流媒体盒子：有屏幕，但没有键盘，无法输入复杂的 URL 和密码
- CLI 工具（如 gh auth login、AWS CLI SSO）：运行在终端，无法弹出浏览器
- IoT 设备：资源受限，可能没有显示屏，更没有浏览器


{{<figure src="./device_auth.png#center" width=800px >}}


1. 首先用户启动应用
2. 应用携带 client_id, scope 请求 Authorization Server 的 /oauth/device/code 接口获取登录URL
3. Authorization Server 返回 device_code, user_code, verification_url, verification_uri_complete, expires_in, interval
4. 用户打开URL或者扫码访问，并且授权
5. 应用按照服务器返回的轮询间隔，开始轮询 Authorization Server
6. Authorization Server 判断用户是否已经同意授权
7. 如果用户同意授权，则返回 access_token
8. 应用使用 access_token 访问资源
9. 服务器判断 access_token 是否有效，如果有效，返回对应资源



### 扩展二: authorization code+ PKCE ( Proof Key for Code Exchange)

PKCE 主要是为了减少公共客户端的授权码拦截攻击.

OAuth 2.0 核心规范定义了两种客户端类型， confidential 机密的， 和 public 公开的， 区分这两种类型的方法是， 判断这个客户端是否有能力维护自己的机密性凭据 client_secret.


{{<figure src="./featured.png#center" width=800px >}}

这里步骤 3 是不安全.
在 OAuth 2.0 核心规范中， 要求授权服务器的 anthorize endpoint 和 token endpoint 必须使用 TLS（安全传输层协议）保护， 但是授权服务器携带授权码code返回到客户端的回调地址时， 有可能不受TLS 的保护， 恶意程序就可以在这个过程中拦截授权码code， 拿到 code 之后， 接下来就是通过 code 向授权服务器换取访问令牌 access_token ， 对于机密的客户端来说， 请求 access_token 时需要携带客户端的密钥 client_secret ， 而密钥保存在后端服务器上， 所以恶意程序通过拦截拿到授权码code 也没有用， 而对于公开的客户端（手机App， 桌面应用）来说， 本身没有能力保护 client_secret， 因为可以通过反编译等手段， 拿到客户端 client_secret， 也就可以通过授权码 code 换取 access_token， 到这一步，恶意应用就可以拿着 token 请求资源服务器了



{{<figure src="./authorization_code_with_pkce.png.png#center" width=800px >}}

在向授权服务器的 authorize endpoint 请求时，需要额外的 code_challenge 和 code_challenge_method 参数， 向 token endpoint 请求时， 需要额外的 code_verifier 参数， 最后授权服务器会对这三个参数进行对比验证， 通过后颁发令牌.


既然固定的 client_secret 是不安全的， 那就每次请求生成一个随机的密钥（code_verifier）， 第一次请求到授权服务器的 authorize endpoint时， 携带 code_challenge 和 code_challenge_method， 也就是 code_verifier 转换后的值和转换方法， 然后授权服务器需要把这两个参数缓存起来， 第二次请求到 token endpoint 时， 携带生成的随机密钥的原始值 (code_verifier) ， 然后授权服务器使用下面的方法进行验证



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
- [oauth 2.0 实战课](https://time.geekbang.org/column/article/254565)
