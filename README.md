# 信息 · 短信转发收件箱

一个 Cloudflare Worker（单文件 `worker.js`）：接收手机转发到邮箱的短信，用尽量还原 iOS「信息」App 的网页查看，验证码一键拷贝。

```
手机短信 ──(邮件「内容/发件人/时间」)──▶ 收件地址
   ├─ 方式 A：Cloudflare 邮件路由「发送到 Worker」──────────────▶ Worker 解析 ──▶ D1 ──▶ 网页
   └─ 方式 B：Resend Inbound ──(email.received Webhook)──▶ Worker 读取正文、解析 ──▶ D1
```

两种方式可以只用一种，也可以同时用。域名已经在用 Cloudflare 邮件路由的话，方式 A 最简单，不需要 Resend。

## 功能

- **iOS 原生体验**：大标题列表、毛玻璃浮动按钮、带尾巴的灰色气泡、「今天 下午8:22」时间分隔、iOS 26 式头像与名称胶囊
- **验证码**：自动识别（验证码 / 校验码 / 动态密码 / code / OTP / 取件码…），列表顶部卡片显示 10 分钟内最新验证码；气泡里的验证码带下划线，点按即拷贝；对话底部有「来自“信息”」快捷拷贝条
- **手势**（弹簧动画，可随时打断，继承手指速度）
  - 列表：左滑删除、右滑标为已读/未读，滑到底直接执行
  - 对话：左滑显示每条信息的时间，右滑返回（添加到主屏幕后从屏幕边缘也可以）
  - 长按气泡：拷贝验证码 / 拷贝 / 删除（桌面端右键）
- **数据检测**：链接、电话号码（95555、400、手机号等）可点
- **搜索**：全文搜索，命中高亮，点击跳到对应信息
- 发件人显示为短信签名（如【招商银行】→「招商银行」），没有签名则显示格式化号码
- 深色模式、减弱动态效果、降低透明度、Dynamic Type；宽屏（≥900px）自动左右分栏
- 可「添加到主屏幕」作为全屏 App 使用；每 4 秒检查一次新信息（只读一行数据）

## 部署

需要 Node.js 20+ 和一个 Cloudflare 账号。

```bash
npm install
npx wrangler login

# 1. 创建 D1 数据库，把输出的 database_id 填进 wrangler.toml（表结构会在首次请求时自动创建）
npx wrangler d1 create sms-inbox

# 2. 设置密钥
npx wrangler secret put ACCESS_PASSWORD          # 网页访问密码，建议 12 位以上
npx wrangler secret put RESEND_API_KEY           # Resend → API Keys，权限选 Full access（需要读取收到的邮件）
npx wrangler secret put RESEND_WEBHOOK_SECRET    # 第 4 步拿到的 whsec_... 

# 3. 部署，得到 https://sms-inbox.<你的子域>.workers.dev
npm run deploy
```

### 4A. 用 Cloudflare 邮件路由收信（不需要 Resend）

1. Cloudflare 控制台 → 你的域名（如 `cuven.us`）→ **电子邮件 → 电子邮件路由**，确认已启用。
2. **路由规则 → 创建地址**：自定义地址填 `0901`（即 `0901@cuven.us`），操作选 **发送到 Worker**，目标选这个 Worker。
3. 手机把短信转发到 `0901@cuven.us` 即可，邮件会直接交给 Worker 解析入库。
4. 可选：原来这个地址会转发到你的邮箱的话，设置 `FORWARD_TO`（必须是邮件路由里已验证的目标地址），Worker 存完后会再转发一份。

用这种方式时，`RESEND_API_KEY` 和 `RESEND_WEBHOOK_SECRET` 可以不设置。

### 4B. 用 Resend 收信

1. **Domains → 添加域名 → Receiving**：开启收信，按提示添加 MX 记录。
   注意：如果根域名已经在用别的邮箱或 Cloudflare 邮件路由（MX 指向 `route*.mx.cloudflare.net`），**不要**改根域名的 MX，那会弄坏现有邮箱；改在子域名上收信，例如在 Resend 添加 `0901.cuven.us`，给 `0901` 加 Resend 给出的 MX 记录，手机发到 `sms@0901.cuven.us`。
2. **Webhooks → Add Endpoint**：
   - URL：`https://sms-inbox.<你的子域>.workers.dev/webhooks/resend`
   - 事件：勾选 `email.received`
   - 创建后复制 Signing Secret（`whsec_...`），执行 `npx wrangler secret put RESEND_WEBHOOK_SECRET`
3. **收件地址过滤（可选，只对 Resend 生效）**：同一个 Resend 账号收到的所有邮件都会推给这个 Webhook，可以在 `wrangler.toml` 里限制：
   - 地址是 `0901@cuven.us` → `INBOX = "0901@cuven.us"`
   - 在子域 `0901.cuven.us` 收信 → `INBOX = "@0901.cuven.us"`
   - 留空则全部接收

### 5. 手机端

让转发 App / 快捷指令把短信发到收件地址，**正文或主题**为：

```
内容/发件人/时间
【招商银行】您账户8578于10月14日16:26……完成扣款人民币13.05/+8615710653301/2026年10月22日 下午8:22
```

内容里可以有 `/` 和换行（从右往左拆分）。时间支持 `2026年10月22日 下午8:22`、`2026-10-22 20:22:15`、`2026/10/22 20:22`、`10月22日 20:22`、Unix 时间戳等；没有时区的时间按 `TZ_OFFSET`（默认 `+08:00`）处理。解析失败的邮件也会保存，发件人显示为邮件发件人。

### 6. iPhone

Safari 打开 Worker 地址 → 输入访问密码 → 分享 → **添加到主屏幕**。

## 收不到信息？

打开网页 → 右上角「…」→ **连接诊断**（列表为空时也可以点「检查连接」）。它会直接告诉你卡在哪一步：

| 诊断结果 | 原因 | 处理 |
| --- | --- | --- |
| 无法读取 Resend 收件箱 · 401 | API Key 填错，或是只有发信权限的 Key | 在 Resend 新建 **Full access** 的 Key，更新 `RESEND_API_KEY` |
| 域名的邮件由 Cloudflare 邮件路由接收 | 根域名 MX 指向 `route*.mx.cloudflare.net`，邮件到不了 Resend | 用 4A 把地址「发送到 Worker」，或按 4B 改用子域名收信 |
| Resend 还没有收到任何邮件 | 手机发到了别的地址（`0901@cuven.us` 和 `…@0901.cuven.us` 是两个不同的域名） | 诊断页会显示开启收信的域名，手机要发到 `…@该域名` |
| Webhook 已被停用 / 没有指向这里的 Webhook | 之前连续失败被 Resend 自动停用，或地址、事件填错 | 地址填诊断页里的「Webhook 地址」（填成根地址也可以），勾选 `email.received`，在 Resend 里重新启用 |
| 没有开启收信的域名 / MX 未验证 | 域名没打开 Receiving，或 MX 记录没加在对应主机上 | 诊断页「Resend 设置」会列出每个域名的收信状态和实际 MX 记录 |
| Webhook 签名校验失败 | `RESEND_WEBHOOK_SECRET` 和 Resend 后台的 Signing secret 不一致 | 重新复制 `whsec_...` |
| N 封邮件还没入库 | Webhook 之前失败过（Resend 重试几次后就放弃了） | 点「从 Resend 导入」补上 |

> 1.1 之前的版本请求 Resend API 时没有带 `User-Agent`，在线上会被 Resend 以 403（error 1010）拒绝，导致所有邮件都存不进来。升级后点「从 Resend 导入」，它会往前翻页，把 Resend 还保存着的邮件都补回来（每次最多 25 封，没补完会自动接着补；导入的信息保留邮件原本的接收时间，旧验证码不会被当成新的）。

另外，打开网页时会自动向 Resend 补拉一次最新邮件里漏掉的（20 秒内只拉一次）；想在不打开网页时也自动补拉，可以在 `wrangler.toml` 里打开每分钟一次的 Cron Trigger。

## 不用命令行部署

Cloudflare 控制台 → Workers & Pages → 创建 Worker → 编辑代码，粘贴整个 `worker.js` → 部署。然后在 Worker 的 设置 → 绑定 里添加 D1 数据库（变量名 `DB`），在 变量和机密 里添加 `ACCESS_PASSWORD`；用 Resend 收信时再加 `RESEND_API_KEY`、`RESEND_WEBHOOK_SECRET`（以及可选的 `INBOX`、`TZ_OFFSET`、`FORWARD_TO`）。

## 可选：不经过邮件直接推送

设置 `INGEST_TOKEN` 后可以直接 POST（比如转发 App 支持 Webhook 时）：

```bash
curl -X POST https://sms-inbox.<子域>.workers.dev/api/ingest \
  -H "Authorization: Bearer <INGEST_TOKEN>" \
  --data '【京东】验证码：482910，5分钟内有效。/1069021112345/2026年10月22日 下午8:22'
```

也接受 JSON：`{"text": "..."}` 或 `{"content": "...", "sender": "...", "time": "..."}`。

## 本地开发

```bash
cat > .dev.vars <<'EOF'
ACCESS_PASSWORD="test-pass"
RESEND_WEBHOOK_SECRET="whsec_bG9jYWwtZGV2LW9ubHktc2VjcmV0"
RESEND_API_KEY="re_xxx"
INGEST_TOKEN="ingest-test"
EOF
npm run dev      # http://localhost:8787，用 /api/ingest 塞几条测试短信
npm test         # 解析、验证码识别、Webhook 签名的单元测试
```

## 安全

- 网页需要密码登录；会话是 HttpOnly + Secure Cookie（180 天），**修改 `ACCESS_PASSWORD` 即可让所有设备下线**
- 同一 IP 15 分钟内输错 10 次会被暂时锁定
- Webhook 校验 Resend（Svix）签名，拒绝 5 分钟以外的时间戳；同一封邮件重复投递只存一次
- 严格的 Content-Security-Policy；短信内容一律按纯文本渲染
- 写操作要求自定义请求头，防 CSRF

## 接口

| 路径 | 说明 |
| --- | --- |
| `POST /webhooks/resend` | Resend `email.received` Webhook |
| `POST /api/ingest` | 直接推送（需 `INGEST_TOKEN`） |
| `GET /api/threads` | 对话列表 + 最新验证码 |
| `GET /api/messages?sender=` | 某个对话的信息（支持 `before_ts`/`before_id` 翻页、`after` 增量） |
| `GET /api/search?q=` | 搜索 |
| `POST /api/read`、`POST /api/delete` | 标记已读/未读、删除 |
| `GET /api/diagnostics` | 连接诊断（配置、Resend 收件箱、最近 Webhook 请求） |
| `POST /api/import` | 从 Resend 补拉漏掉的邮件（`{"force": true}` 跳过 20 秒限流） |
