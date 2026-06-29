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

### 环境变量（覆盖 dev 默认，未设置时保持原值）

| 变量 | 作用 | 默认 |
|------|------|------|
| `LISTEN_ADDR` | 监听地址（覆盖 `listen_addr`） | `127.0.0.1:9090` |
| `KEYSTONE_ISSUER` | 期望 OIDC issuer（覆盖 `keystone_issuer`，并重新派生 discovery） | `http://127.0.0.1:8080` |
| `JWKS_ROTATION_COOLDOWN` | 健康缓存遇未知 kid 时的**反应式**刷新冷却（Go duration，如 `5s`）；冷却内视为垃圾 kid 风暴并抑制刷新，过冷却即视为 kid 轮换并立即刷新 | `5s` |
| `SLUICE_STORE` | 路由 store：`static` 或 `postgres` | `static` |
| `DATABASE_URL` | Postgres DSN（`SLUICE_STORE=postgres` 时必填） | 空 |
| `ROUTES_SEED` | Postgres 播种用的路由配置文件路径（可选，缺省用 `-config` 里的 routes） | 空 |

```bash
# 以 Postgres 作为路由数据源运行（表为空时从配置 routes 幂等播种）
export SLUICE_STORE=postgres
export DATABASE_URL='postgres://postgres:pw@127.0.0.1:5432/sluice'
go run ./cmd/sluice -config config.json
```

### 容器运行

```bash
docker build -t holdfast/sluice:dev .
docker run -d --name sluice -p 9090:9090 holdfast/sluice:dev
curl http://127.0.0.1:9090/healthz   # -> ok
```

镜像为多阶段构建：`golang` builder 产出 `CGO_ENABLED=0` 静态二进制，运行阶段为
`scratch` + 非 root（UID 65532）+ `EXPOSE 9090`。`HEALTHCHECK` 复用二进制自带的
`sluice -healthcheck` 标志探测 `/healthz`（scratch 无 shell/wget），探测地址取自
`LISTEN_ADDR`（`0.0.0.0` 自动改用回环拨号）。

## 配置说明

```jsonc
{
  "listen_addr": "127.0.0.1:9090",            // 监听地址
  "keystone_issuer": "http://127.0.0.1:8080", // 期望的 OIDC issuer（校验 iss）
  "discovery_url": "",                         // 可选；留空则由 issuer 派生 /.well-known/openid-configuration
  "jwks_refresh_interval": 300000000000,       // time.Duration（纳秒）；300000000000 = 5 分钟（proactive 间隔）
  "jwks_rotation_cooldown": 5000000000,        // time.Duration（纳秒）；5000000000 = 5 秒（kid 轮换反应式冷却）
  "routes": [
    { "name": "public-api",    "match": { "path_prefix": "/public" }, "upstream": "http://127.0.0.1:8081", "protected": false },
    { "name": "protected-api", "match": { "host": "api.local", "path_prefix": "/api" }, "upstream": "http://127.0.0.1:8082", "protected": true }
  ]
}
```

注意：`jwks_refresh_interval` 与 `jwks_rotation_cooldown` 均为 Go `time.Duration`，JSON 中以纳秒整数表示；
后者亦可用 `JWKS_ROTATION_COOLDOWN` 以 Go duration 字符串（如 `5s`）覆盖。

## v0 覆盖范围

- `GET /healthz` -> `200 "ok"`。
- 配置文件驱动的路由匹配（最长前缀优先 + 可选 Host 精确匹配）。
- 流式反向代理 + `X-Forwarded-*` 注入。
- 受保护路由的 RS256 forward-auth：OIDC discovery、JWKS 按 `kid` 缓存；校验 `iss` + `exp`，
  固定算法 RS256（抵御 `alg=none` 与 RS->HS 混淆）。
- **JWKS 按需刷新韧性**：kid-miss 时按缓存健康度决定行为——健康缓存对未知 kid 用**短反应式
  冷却** `rotationCooldown`（默认 5s，可经 `JWKS_ROTATION_COOLDOWN` 配置）作护栏：冷却内视为
  垃圾 kid 风暴并抑制刷新，过冷却即视为真实签名密钥轮换并立即刷新（`singleflight` 合并为单次
  上游抓取），因此 Keystone 重启轮换 kid 后**数秒内**即被接管，而非等待 `jwks_refresh_interval`
  这一更长的 proactive 间隔；冷/失败缓存则强制刷新且不受成功冷却抑制；仅对**重复失败**施加有界
  指数退避，首次重试立即放行——因此 Keystone 启动时不可达不会让 forward-auth 长期卡在 401，
  恢复后首个请求即放行（见 `internal/auth/jwks_recovery_test.go` 与 `jwks_rotation_test.go`）。
- **可移植 Postgres 路由数据层**（`SLUICE_STORE=postgres`）：`pgx/v5` + 幂等
  `CREATE TABLE IF NOT EXISTS`，仅用标准 SQL，空表时从配置 routes 幂等播种；默认仍走静态
  内存 store，现有测试无需数据库。
- 在每个路由上剥离客户端伪造的 `X-Auth-*` 头，仅由校验通过的中间件注入可信值。
- 结构化访问日志。
- 完整端到端契约测试 `test/integration_test.go`（伪 Keystone + echo 上游 + 真实 Sluice）。

## 明确推迟（后续阶段）

- **`aud` 校验**：v0 不校验 audience（Sluice 作为资源服务器尚不知道 `client_id`）。预留 seam，
  待可配置期望 audience 后用 `jwt.WithAudience` 开启。详见 `internal/auth/verifier.go`。
- **TLS**：v0 仅在 loopback 上以明文 HTTP 绑定，仅用于开发。生产需后续 Keyward 驱动的 TLS 终止。
- **时钟偏移容忍**：默认零 leeway；后续可加 `jwt.WithLeeway`。
- **FusionDB / CDC 控制面**：路由当前为内存 `StaticStore` 或一次性加载快照的
  `PostgresStore`（均不热加载）。`internal/store/store.go` 标注了 `TODO(fusiondb-seam)`：
  未来的 `FusionDBStore` 消费 CDC 变更流热加载路由，数据路径只调用 `RouteStore.Routes()`，
  因此替换只是 `cmd/sluice/main.go` 的接线改动，代理 / 鉴权代码零改动。Postgres 数据层
  刻意只用标准 SQL（`TEXT/BOOLEAN`、`PRIMARY KEY/NOT NULL/DEFAULT`、参数化、`ON CONFLICT`），
  以便后续不改代码即可跑在 FusionDB 的 pgwire 上。
- WebSocket / gRPC / HTTP2 推送、负载均衡等为后续阶段。

## 代码结构

```
cmd/sluice/main.go            入口：加载配置、按 SLUICE_STORE 选 store、构建 JWKS/verifier、组装 server；-healthcheck 探针
internal/config/              Config/Route/Match 结构、JSON 加载与校验、discovery URL 派生、env 覆盖（ApplyEnv）
internal/store/store.go       RouteStore 接口 + 内存 StaticStore（标注 FusionDB seam）
internal/store/postgres.go    pgx/v5 PostgresStore：幂等迁移 + 空表播种 + 快照加载（可移植 SQL）
internal/auth/jwks.go         OIDC discovery + JWKS 抓取 + RSA 公钥重建 + kid 缓存 + singleflight/退避恢复
Dockerfile / .dockerignore    多阶段静态构建 -> scratch 非 root 运行，-healthcheck 驱动 HEALTHCHECK
internal/auth/verifier.go     基于 golang-jwt 的 RS256/iss/exp 校验
internal/auth/middleware.go   forward-auth 中间件
internal/gateway/router.go    路由匹配（Host 精确 + 最长前缀）
internal/gateway/proxy.go     基于 ReverseProxy 的流式代理（X-Forwarded-* 注入、X-Auth-* 剥离）
internal/gateway/server.go    HTTP handler 组装（healthz、路由分发、鉴权包裹、访问日志）
internal/accesslog/           slog JSON 访问日志包裹器
```
