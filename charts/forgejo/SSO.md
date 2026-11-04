# Vasi 统一登录

本 Chart 独立安装；`auth.mode: external` 保留已有部署方接线，`auth.mode: oidc` 消费 Vasi 登记的身份源。
`publicUrl` 必须是包含入口端口的 HTTPS origin，`ingress.host` 必须匹配它。客户端、回调、角色和命名空间由 Vasi 的受管 SSO 操作登记；仅上传 Chart 不会创建身份客户端或授予用户权限。

Vasi 写入专属 CA ConfigMap 和凭据 Secret 的引用；values 只保存引用，不保存密码、客户端密钥或用户令牌。制品发布者必须把所有主容器、初始化容器和 sidecar 镜像纳入完整材料清单并提供已导入 Nexus 的固定摘要。

`auth.mode: oidc` 只使用 Forgejo 原生登录源，要求 `sso.enabled: true`、`oidc.enabled: false`。`auth.oidc.existingSecret` 提供 `issuer/client-id/client-secret`，`auth.oidc.directorySecret` 提供独立只读目录客户端的相同键，`adminSecret` 提供专属恢复账号的 `username/password`。

`provisioner.image` 使用 `deploy/sso/Dockerfile` 构建，基础镜像与应用同为固定的 Forgejo 15.0.9。init 先迁移本应用数据库、创建原生登录源与恢复管理员，再启动 Web；该版本 CLI 不支持安全的非交互密钥输入，因此密钥及恢复密码哈希通过本应用 PostgreSQL 的私有 stdin 写入。它不访问其他应用数据库，不输出秘密，不把秘密放 argv。恢复账号先于首个 SSO 用户创建，避免首人自动成为站点管理员。

产品 sidecar 通过 loopback 原生 API 按 `(login_source, IAM subject)` 投影账号。兼容邮箱是不可投递的 `@platform.invalid` 地址，不用于认领身份或验证真实邮箱；自动注册、按同邮箱关联都关闭。同名或不属于此登录源的账号不接管。`git-admin` 映射站点管理员，权限范围覆盖整个 Code 实例；撤销成员资格会禁止已管理账号登录并降为非管理员。

绑定信息保存在数据卷，issuer/client ID 改变会拒绝启动。Web 以 UID 1000 直接启动并关闭 SSH；clone/push 使用 HTTPS，避免官方 root 入口脚本在已初始化数据卷内生成不可读 SSH 文件。已有原生源的无标记部署不会自动认领；迁移需单独核对。

OIDC 与目录服务不可用时投影 sidecar 不就绪，受管实例关闭入口；恢复后重试，不回退到其他身份源。external 模式保持已有接线。

投影每十秒刷新，完整目录扫描有两分钟期限；readiness 检查最近一次成功的时间，超过两分钟关闭入口，不能用永远存在的 ready 文件掩盖卡住的同步进程。
