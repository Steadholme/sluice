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
| `LISTEN_ADDR` | 明文模式（`TLS_MODE=off`）的单一监听地址 | `127.0.0.1:9090` |
| `KEYSTONE_ISSUER` | 期望的**公网** OIDC issuer（校验 JWT `iss`，并重新派生 discovery） | `http://127.0.0.1:8080` |
| `OIDC_DISCOVERY_URL` | 覆盖 discovery 文档抓取 URL（指向**内网** Keystone，避免 TLS 回环） | 由 issuer 派生 |
| `JWKS_FETCH_URL` | 直接指定 `jwks_uri`，**完全跳过 discovery**（指向内网 Keystone 的 `/jwks.json`） | 空 |
| `JWKS_ROTATION_COOLDOWN` | 健康缓存遇未知 kid 时的**反应式**刷新冷却（Go duration，如 `5s`） | `5s` |
| `TLS_MODE` | TLS 终止模式：`off` / `file` / `acme` | `off` |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | `file` 模式的证书链与私钥（PEM） | 空 |
| `ACME_DOMAIN` | `acme` 模式允许签发的唯一主机（HostPolicy 白名单） | 空 |
| `ACME_EMAIL` | `acme` 账户联系邮箱 | 空 |
| `ACME_CACHE_DIR` | autocert 缓存目录（已签发证书 + 账户密钥） | `/acme` |
| `ACME_DIRECTORY_URL` | 可选 ACME directory（如 LE staging），用于不烧生产额度地验证签发 | 空（= LE 生产） |
| `HTTP_ADDR` | TLS 模式下 :80 的 ACME HTTP-01 挑战 + HTTP→HTTPS 跳转绑定 | `:80` |
| `HTTPS_ADDR` | TLS 模式下 :443 的 HTTPS 绑定 | `:443` |
| `SLUICE_STORE` | 路由 store：`static` 或 `postgres` | `static` |
| `DATABASE_URL` | Postgres DSN（`SLUICE_STORE=postgres` 时必填） | 空 |
| `ROUTES_SEED` | Postgres 播种用的路由配置文件路径（可选，缺省用 `-config` 里的 routes） | 空 |
| `GW_OIDC` | 启用 OIDC **浏览器 SSO** Relying Party：`on`/`off` | `off` |
| `OIDC_ISSUER` | SSO 用的**公网** issuer（authorize 跳转 + id_token `iss`/`aud` 校验） | 取 `KEYSTONE_ISSUER` |
| `GW_CLIENT_ID` | 网关在 Keystone 注册的 OIDC `client_id` | 空 |
| `GW_CLIENT_SECRET` | 网关 client secret（token 端点 `client_secret_post`） | 空 |
| `GW_REDIRECT_URI` | **公网** 回调地址，须为 `https://id.w33d.xyz/_gw/auth/callback` | 空 |
| `GW_TOKEN_URL` | **内网** token 端点（开 mTLS 时 `https://keystone:8443/token`，否则 `http://keystone:8080/token`） | 空 |
| `GW_SESSION_TTL` | 网关浏览器会话有效期（Go duration，如 `8h`） | `8h` |
| `GW_SESSION_SECRET` | 签名 `__Host-gw` 不透明 cookie id 的 HMAC 密钥（强随机、稳定） | 空（缺省临时随机，重启失效） |
| `INTERNAL_MTLS` | 到 Keystone 内网跳启用 **mTLS**：`on`/`off` | `off` |
| `KEYSTONE_MTLS_CERT` / `KEYSTONE_MTLS_KEY` | Keyward 签发的客户端证书 + 私钥（CN=sluice，PEM） | 空 |
| `KEYSTONE_MTLS_CA` | 信任锚 PEM（Keyward root CA） | 空 |
| `KEYSTONE_TLS_SERVERNAME` | 内网 mTLS 校验的 server name（SNI/证书主机） | `keystone` |
| `AUDIT_ENABLED` | 启用向 Watchtower 发送**安全审计事件**：`on`/`off`（关闭即零行为变化） | `off` |
| `WATCHTOWER_URL` | Watchtower 基址（内网，如 `http://watchtower:8500`） | 空 |
| `AUDIT_INGEST_TOKEN` | `POST /events` 的 Bearer 凭据（与 Watchtower 共享） | 空 |

### TLS 终止与公网暴露

Sluice 是整套 Holdfast 的**唯一公网面**：它在 `id.w33d.xyz` 上终止 TLS 并反代到内网
Keystone / whoami（后者均不对外发布）。`TLS_MODE` 选择终止方式：

- **`off`（默认，开发）**：在 `LISTEN_ADDR` 上绑定单一明文 HTTP，行为与历史完全一致。
- **`file`**：从 `TLS_CERT_FILE` / `TLS_KEY_FILE` 加载证书在 `HTTPS_ADDR`（默认 `:443`）服务
  HTTPS；同时在 `HTTP_ADDR`（默认 `:80`）将一切 301 跳转到 https。迭代期可用自签证书
  + `/etc/hosts id.w33d.xyz 127.0.0.1` 演练完整 HTTPS 链路。
- **`acme`**：用 `golang.org/x/crypto/acme/autocert` 自动签发/续期 Let's Encrypt 证书，
  HostPolicy 白名单锁定 `ACME_DOMAIN`，证书与账户密钥缓存在 `ACME_CACHE_DIR`（`/acme` 卷）；
  `:80` 由 `autocert` 的 HTTPHandler 服务 ACME HTTP-01 挑战，其余 301 跳转到 https；`:443`
  使用 `manager.TLSConfig()`。设 `ACME_DIRECTORY_URL` 为 LE staging 可先行验证签发再切生产。

**公网 issuer vs 内网抓取**：`KEYSTONE_ISSUER` 始终是用于校验 `iss` 的**公网**值
（`https://id.w33d.xyz`），而 `JWKS_FETCH_URL`（或 `OIDC_DISCOVERY_URL`）让 Sluice 从**内网**
Keystone（`http://keystone:8080`）抓取 JWKS，避免穿过自身 TLS 回环。设了 `JWKS_FETCH_URL`
即直接拉取该 `jwks_uri` 并跳过 discovery（discovery 文档里的 `jwks_uri` 指向公网，会回环）。

### 前置（front）Keystone 的生产路由表

`config.holdfast.json` 是已就绪的生产路由表：把 Keystone 的公开端点
（`/.well-known/`、`/authorize`、`/token`、`/jwks.json`、`/userinfo`、`/login`、`/logout`、
`/account`、`/register`、`/webauthn/`、`/static/`、`/callback`、以及根 `/`）作为**非保护**路由
反代到 `http://keystone:8080`，把演示用 `/api` 作为**保护**路由（forward-auth）反代到
`http://whoami:80`。反代时**保留原始 Host 头**并（TLS 终止后）置 `X-Forwarded-Proto=https`，
使 Keystone 能正确构造绝对 OIDC URL。最长前缀优先保证 `/api` 等更具体前缀压过根 `/`。

```bash
# 生产（acme）：env 提供 TLS 模式，路由表来自 config.holdfast.json
docker run -d --name sluice -p 80:80 -p 443:443 -v sluice-acme:/acme \
  -e TLS_MODE=acme -e ACME_DOMAIN=id.w33d.xyz -e ACME_EMAIL=momoxiaomaster@gmail.com \
  holdfast/sluice:dev -config /app/config.holdfast.json
```

```bash
# 以 Postgres 作为路由数据源运行（表为空时从配置 routes 幂等播种）
export SLUICE_STORE=postgres
export DATABASE_URL='postgres://postgres:pw@127.0.0.1:5432/sluice'
go run ./cmd/sluice -config config.json
```

### 路由鉴权三模式：`public` / `bearer` / `sso`

每条路由新增可选 `auth` 字段，泛化原来的 `protected` 布尔：

- **`public`**：不鉴权，直接反代（等价 `protected:false`）。
- **`bearer`**：现有 **API forward-auth**——要求 `Authorization: Bearer <RS256 JWT>`，
  校验通过注入 `X-Auth-*`，失败 `401`（等价 `protected:true`）。**行为完全不变。**
- **`sso`**：新增 **浏览器 SSO**——见下。

向后兼容：`auth` 留空时由 `protected` 派生（`true→bearer`、`false→public`），
因此既有配置文件与 Postgres 路由行**零改动、行为不变**；显式写 `auth` 即覆盖。
Postgres `routes` 表自动新增 `auth` 列（旧库经幂等 `ALTER ... ADD COLUMN IF NOT
EXISTS` 回填，旧行 `auth=''` 仍按 `protected` 派生）。

### OIDC 浏览器 SSO（`GW_OIDC=on`）

这是「**每个公网 base-service UI 都挂到 Keystone SSO 后面**」的机制。`auth=sso`
的路由把**浏览器**门禁到 Keystone 登录：

1. 无有效网关会话（`__Host-gw` cookie）→ 用 `authorization_code` + PKCE S256
   `302` 跳到 Keystone **公网** `OIDC_ISSUER/authorize`（带 `client_id=GW_CLIENT_ID`、
   `redirect_uri=GW_REDIRECT_URI`、`scope="openid email profile"`、`state`、`nonce`、
   `code_challenge`）。`{state,nonce,code_verifier,original_url}` 以 `state` 为键短时
   持久化（Postgres `gw_oauth_state` 或内存）。
2. 用户在 Keystone 完成口令/passkey 登录后带 `code` 回到 **Sluice 自服务**端点
   `GET /_gw/auth/callback`（**不被反代**，路由匹配前拦截）：校验单次 `state`、在
   **内网** token 端点（可走 mTLS，见下）以 `client_secret_post` + PKCE verifier 换码，
   用共享 JWKS 校验 `id_token` 签名与 `iss==OIDC_ISSUER`/`aud==GW_CLIENT_ID`/`nonce`/`exp`，
   建网关会话（`gw_sessions`），下发**签名不透明** `__Host-gw` cookie（`Secure`、`HttpOnly`、
   `SameSite=Lax`），`302` 回 `original_url`。
3. 持有效 `__Host-gw` 会话的请求 → 注入 `X-Auth-Subject` / `X-Auth-Email` /
   `X-Auth-Scope` 并反代上游。`GET /_gw/auth/logout` 清会话与 cookie。

**与 Bearer API 路径并存且互不影响**：`bearer` 路由仍只认 `Authorization: Bearer`；
公网口令/passkey 登录 UI（反代 Keystone 的 `/login`、`/webauthn/` 等公开路由）照常工作。
整套 SSO 由 `GW_OIDC` 开关控制，**关闭即完全不经过该路径**；开启但配置不全时，
provider 构建失败仅令 `sso` 路由 `503`（fail-closed），`bearer`/`public` 不受影响。

### 内网 mTLS 到 Keystone（`INTERNAL_MTLS=on`）

Sluice 到 Keystone 的**内网 server-to-server 跳**（反代上游 + OIDC token/JWKS 抓取）
启用双向 TLS：出示 Keyward 签发的客户端证书（`CN=sluice`），仅信任 Keyward root CA，
固定 `ServerName`（默认 `keystone`）。开启后把 Keystone 上游与 `GW_TOKEN_URL`/`JWKS_FETCH_URL`
指向 `https://keystone:8443/...`；反代仅对 **https 上游**挂 mTLS transport，明文上游不变。
开关 `off` 时维持原 `http://keystone:8080`。构建失败（缺证书/格式错）自动降级回明文，
**不拖垮网关**。

### 安全审计事件到 Watchtower（`AUDIT_ENABLED=on`）

开启后，Sluice 把网关侧的安全相关动作以**非阻塞、即发即忘**的方式上报到 Watchtower
（`POST WATCHTOWER_URL/events`，`Authorization: Bearer AUDIT_INGEST_TOKEN`）。Watchtower
负责分配 `seq`/`ts` 并追加到 SHA-256 哈希链；生产者只发逻辑字段。

**绝不阻塞/失败请求路径**：`internal/audit` 用一个**有界 channel（cap 1024）+ 后台
worker**——handler 调用 `Emit` 只做一次 `select`+`default` 的非阻塞投递，队列满或
Watchtower 不可达即**丢弃并计数**（warn 日志），错误绝不回传到用户请求。worker 以
~2s 短超时 POST。`AUDIT_ENABLED=off`（默认）时 `Emit` 为 no-op，**零行为变化**；
**Watchtower 宕机不影响登录与反代**。

**绝不泄密**：事件字段为 `actor`/`action`/`target`/`severity`/`detail`/`source`，
`detail` 为短安全字符串，**绝不含 token/密码/client secret/cookie/code_verifier**。
`forward_auth.deny` 只记 reason（`missing token`/`invalid token`/`expired`），**不含 token 本体**。

埋点事件（`source="sluice"`）：

| action | 触发点 | actor | target | severity |
|--------|--------|-------|--------|----------|
| `forward_auth.allow` | bearer 路由校验通过 | 已验证 `sub` | 请求路径 | info |
| `forward_auth.deny` | bearer 校验失败 | `anonymous` | 请求路径 | warning（`detail`=原因） |
| `sso.session.establish` | OIDC 回调建立会话 | `sub`/`email` | `GW_CLIENT_ID` | info |
| `sso.session.deny` | 回调 state/nonce/sig 校验失败 | `anonymous` | `GW_CLIENT_ID` | warning（`detail`=原因） |
| `sso.logout` | `/_gw/auth/logout` | 已知则 `sub` | `GW_CLIENT_ID` | info |

### 容器运行

```bash
docker build -t holdfast/sluice:dev .
docker run -d --name sluice -p 9090:9090 holdfast/sluice:dev
curl http://127.0.0.1:9090/healthz   # -> ok
```

镜像为多阶段构建：`golang` builder 产出 `CGO_ENABLED=0` 静态二进制，运行阶段为
`scratch` + 非 root（UID 65532）+ `EXPOSE 80 443 9090` + `VOLUME /acme`（autocert 缓存，
属主即 65532，证书随重启留存以免触发 LE 额度）。`HEALTHCHECK` 复用二进制自带的
`sluice -healthcheck` 标志探测 `/healthz`（scratch 无 shell/wget），并按 `TLS_MODE` 选择
scheme：`off` 走 `LISTEN_ADDR` 的明文 HTTP，`file`/`acme` 走 `HTTPS_ADDR` 的 HTTPS
（回环拨号，跳过证书校验）。镜像内置 `/app/config.json`（dev 默认）与
`/app/config.holdfast.json`（生产路由表）。

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
- 流式反向代理 + `X-Forwarded-*` 注入 + **保留原始 Host 头**（供 Keystone 构造绝对 URL）。
- **TLS 终止三模式**（`TLS_MODE=off|file|acme`）：`file` 加载证书文件，`acme` 用 autocert 自动
  签发 LE 证书（HostPolicy 锁定 `ACME_DOMAIN`、缓存 `/acme`、可选 staging directory）；`file`/`acme`
  均在 `:80` 服务 ACME HTTP-01 挑战并 301 跳转 https，在 `:443` 终止 TLS。`off` 保持历史明文行为。
- **前置 Keystone**：把 Keystone 公开端点作为非保护路由反代到内网 `http://keystone:8080`，演示
  `/api` 作为保护路由反代到 `http://whoami:80`（`config.holdfast.json`）。
- **公网 issuer / 内网抓取分离**：`KEYSTONE_ISSUER` 校验公网 `iss`，`JWKS_FETCH_URL` /
  `OIDC_DISCOVERY_URL` 从内网 Keystone 抓取 JWKS，避免穿过自身 TLS 回环。
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
internal/auth/middleware.go   forward-auth 中间件 + Identity（含 Email）+ ContextWithIdentity + 审计埋点（WithAuditor）
internal/audit/audit.go       非阻塞审计发射器：有界 channel + 后台 worker，即发即忘 POST 到 Watchtower，满/宕机即丢弃
internal/mtls/mtls.go         内网 mTLS 客户端 transport/Client 构建（Keyward 客户端证书 + root CA + ServerName）
internal/oidc/oidc.go         OIDC 浏览器 SSO Relying Party：Middleware、/_gw 回调与登出、PKCE、签名 cookie、id_token 校验
internal/oidc/store.go        gw 会话/状态接口 + 内存实现（测试/静态部署）
internal/oidc/postgres.go     gw_sessions / gw_oauth_state 的 Postgres 实现（可移植标准 SQL，state 事务内单次消费）
internal/gateway/router.go    路由匹配（Host 精确 + 最长前缀）
internal/gateway/proxy.go     基于 ReverseProxy 的流式代理（X-Forwarded-* 注入、保留 Host、X-Auth-* 剥离/注入、https 上游挂 mTLS）
internal/gateway/tls.go       file 模式证书加载、acme autocert.Manager 构建、:80 HTTP→HTTPS 跳转
internal/gateway/server.go    HTTP handler 组装（healthz、/_gw 拦截、路由分发、public/bearer/sso 三模式鉴权、访问日志）
internal/accesslog/           slog JSON 访问日志包裹器
```
