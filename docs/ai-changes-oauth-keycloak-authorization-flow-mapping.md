# OAuth 授权方式与 Keycloak 映射变更记录

## 需求

在 OIDC 文档中补充 OAuth 2.0 四种授权方式与 Keycloak 客户端 `Capability config` 开关之间的映射关系。

## 变更

- 新增 OAuth 2.0 授权方式、`grant_type` 与 Keycloak 开关的对照表。
- 说明客户端凭证模式还需要开启 `Client authentication` 并为服务账号分配角色。
- 说明 Keycloak 的 `Authorization` 开关不对应授权码模式。
- 补充 Device Authorization Grant 和 CIBA Grant 属于扩展授权流程的说明。

## 验证

- 对照 Keycloak 官方 Server Administration Guide 核对各 Capability config 开关含义。
- 执行 Hugo 构建，检查 Markdown 表格及页面渲染是否正常。
