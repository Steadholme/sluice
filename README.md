# Sluice

Sluice 是 Holdfast 平台的 L7 反向代理 / SSO 网关（v0），基于 Go 标准库 `net/http` +
`httputil.ReverseProxy` 构建，仅引入一个外部依赖 `github.com/golang-jwt/jwt/v5`
用于标准正确的 RS256 JWT 校验。

## 它是什么

- 配置驱动的反向代理：路由表来自 JSON 配置文件，匹配规则为「Host 精确匹配（可选）+ 最长
  `path_prefix` 优先」。
- 对匹配到的请求做流式代理（保留 method/body/headers），并写入 `X-Forwarded-For/Proto/Host`。
- 对受保护路由执行 forward-auth：要求 `Authorization: Bearer <jwt>`，用 Keystone 的 JWKS
  （通过 OIDC discovery 发现 `jwks_uri`，按 `kid` 缓存）校验 RS256 签名，并验证 `iss` 与 `exp`；
  成功后向上游注入 `X-Auth-Subject`(=sub) 与 `X-Auth-Scope`(=scope)，失败统一返回
  `401` + `WWW-Authenticate: Bearer`。
- 每个请求输出一行结构化 slog JSON 访问日志（method/path/status/upstream/duration_ms/sub）。

## 如何运行

Go 二进制不在默认 PATH 上，每条命令需先导出：

```bash
export PATH=$PATH:/usr/local/go/bin

# 构建与测试
go build ./...
go test ./...

# 运行（先从示例配置拷贝一份本地配置）
cp config.example.json config.json
go run ./cmd/sluice -config config.json
```

默认监听 `127.0.0.1:9090`，期望 Keystone issuer 为 `http://127.0.0.1:8080`。
健康检查：`curl http://127.0.0.1:9090/healthz` 返回 `ok`。

## 配置说明

```jsonc
{
  "listen_addr": "127.0.0.1:9090",            // 监听地址
  "keystone_issuer": "http://127.0.0.1:8080", // 期望的 OIDC issuer（校验 iss）
  "discovery_url": "",                         // 可选；留空则由 issuer 派生 /.well-known/openid-configuration
  "jwks_refresh_interval": 300000000000,       // time.Duration（纳秒）；300000000000 = 5 分钟
  "routes": [
    { "name": "public-api",    "match": { "path_prefix": "/public" }, "upstream": "http://127.0.0.1:8081", "protected": false },
    { "name": "protected-api", "match": { "host": "api.local", "path_prefix": "/api" }, "upstream": "http://127.0.0.1:8082", "protected": true }
  ]
}
```

注意：`jwks_refresh_interval` 是 Go `time.Duration`，JSON 中以纳秒整数表示。

## v0 覆盖范围

- `GET /healthz` -> `200 "ok"`。
- 配置文件驱动的路由匹配（最长前缀优先 + 可选 Host 精确匹配）。
- 流式反向代理 + `X-Forwarded-*` 注入。
- 受保护路由的 RS256 forward-auth：OIDC discovery、JWKS 按 `kid` 缓存、未知 `kid` 触发
  冷却门控的惰性刷新（吸收密钥轮换）；校验 `iss` + `exp`，固定算法 RS256（抵御 `alg=none`
  与 RS->HS 混淆）。
- 在每个路由上剥离客户端伪造的 `X-Auth-*` 头，仅由校验通过的中间件注入可信值。
- 结构化访问日志。
- 完整端到端契约测试 `test/integration_test.go`（伪 Keystone + echo 上游 + 真实 Sluice）。

## 明确推迟（后续阶段）

- **`aud` 校验**：v0 不校验 audience（Sluice 作为资源服务器尚不知道 `client_id`）。预留 seam，
  待可配置期望 audience 后用 `jwt.WithAudience` 开启。详见 `internal/auth/verifier.go`。
- **TLS**：v0 仅在 loopback 上以明文 HTTP 绑定，仅用于开发。生产需后续 Keyward 驱动的 TLS 终止。
- **时钟偏移容忍**：默认零 leeway；后续可加 `jwt.WithLeeway`。
- **FusionDB / CDC 控制面**：路由当前为文件加载的内存 `StaticStore`。
  `internal/store/store.go` 标注了 `TODO(fusiondb-seam)`：未来的 `FusionDBStore` 消费 CDC
  变更流热加载路由，数据路径只调用 `RouteStore.Routes()`，因此替换只是 `cmd/sluice/main.go`
  的接线改动，代理 / 鉴权代码零改动。
- WebSocket / gRPC / HTTP2 推送、负载均衡、单飞 + 退避的 JWKS 刷新等为后续阶段。

## 代码结构

```
cmd/sluice/main.go            入口：加载配置、构建 store/JWKS/verifier、组装 server、监听
internal/config/              Config/Route/Match 结构、JSON 加载与校验、discovery URL 派生
internal/store/               RouteStore 接口 + 内存 StaticStore（标注 FusionDB seam）
internal/auth/jwks.go         OIDC discovery + JWKS 抓取 + RSA 公钥重建 + kid 缓存
internal/auth/verifier.go     基于 golang-jwt 的 RS256/iss/exp 校验
internal/auth/middleware.go   forward-auth 中间件
internal/gateway/router.go    路由匹配（Host 精确 + 最长前缀）
internal/gateway/proxy.go     基于 ReverseProxy 的流式代理（X-Forwarded-* 注入、X-Auth-* 剥离）
internal/gateway/server.go    HTTP handler 组装（healthz、路由分发、鉴权包裹、访问日志）
internal/accesslog/           slog JSON 访问日志包裹器
```
