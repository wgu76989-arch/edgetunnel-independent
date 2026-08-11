# edgetunnel independent

这是用于个人独立部署的 Cloudflare Worker 源码仓库。运行入口是
[`_worker.js`](./_worker.js)，管理前端和静态数据均指向
`wgu76989-arch` 账号下的独立镜像仓库。

## 自有依赖

- 管理前端：<https://wgu76989-arch.github.io/edgetunnel-pages>
- ACL 配置：<https://github.com/wgu76989-arch/edgetunnel-acl4ssr>
- CIDR 和接口快照：<https://github.com/wgu76989-arch/edgetunnel-data>
- Sing-box GeoIP：<https://github.com/wgu76989-arch/edgetunnel-sing-geoip>
- Sing-box GeoSite：<https://github.com/wgu76989-arch/edgetunnel-sing-geosite>
- 订阅转换源码：<https://github.com/wgu76989-arch/edgetunnel-subconverter>

## Cloudflare Workers 部署

1. 创建一个 KV 命名空间，并在 `wrangler.toml` 中以 `KV` 为绑定名填写其 ID。
2. 使用 `wrangler secret put ADMIN` 设置后台登录密码。
3. 运行 `wrangler deploy`。
4. 访问 Worker 域名下的 `/login` 或 `/admin`。

默认未设置 `SUBAPI`，因此 mixed/Base64 订阅可以直接生成，Clash、Sing-box、
Surge 等格式会返回 501。部署 `edgetunnel-subconverter` 后，在后台填写它的服务地址
即可启用转换。

## 独立性说明

仓库不包含自动同步上游的 workflow。代码中的仓库和静态页面依赖已改为当前账号的
镜像；Cloudflare Workers/KV、公共 DNS、IP/ASN 查询、测速、地图和 Telegram 等动态
服务仍属于运行时网络服务，不能用 GitHub 静态仓库替代。

本仓库基于原项目制作，授权条款见 [`LICENSE`](./LICENSE)，原始变更记录见
[`CHANGELOG`](./CHANGELOG)。
