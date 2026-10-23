/**
 * 信息 · 短信转发收件箱（Cloudflare Worker，单文件）
 *
 * 手机把短信按「内容/发件人/时间」发到邮箱 → Resend Inbound 收信 →
 * email.received Webhook → 本 Worker 校验签名、读取正文、解析并存入 D1 →
 * 一个尽量还原 iOS「信息」App 的网页（验证码一键拷贝）。
 *
 * 绑定与变量（详见 README.md）：
 *   DB                     D1 数据库（必需）
 *   ACCESS_PASSWORD        网页访问密码（secret，必需）
 *   RESEND_API_KEY         Resend API Key，用于读取收到的邮件正文（secret）
 *   RESEND_WEBHOOK_SECRET  Resend Webhook 签名密钥 whsec_...（secret）
 *   INBOX                  只处理发往这些地址的邮件，逗号分隔，"@域名" 表示整个域；留空 = 全部
 *   TZ_OFFSET              短信时间所在时区，默认 +08:00
 *   INGEST_TOKEN           可选：开启 POST /api/ingest，用 Bearer Token 直接推送短信
 */

const SESSION_COOKIE = '__Host-sms_session';
const SESSION_DAYS = 180;
const LOGIN_MAX_FAILS = 10;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const WEBHOOK_TOLERANCE_S = 5 * 60;
const RESEND_API = 'https://api.resend.com';
const RESEND_USER_AGENT = 'sms-inbox-worker/1.1';
const MAX_BODY_CHARS = 4000;
const PAGE_SIZE = 80;
const WEBHOOK_LOG_KEEP = 50;
const IMPORT_LIMIT = 20;
const IMPORT_THROTTLE_MS = 20 * 1000;

const enc = new TextEncoder();

export default {
  async fetch(request, env, ctx) {
    try {
      return await handle(request, env, ctx);
    } catch (err) {
      console.error('unhandled error', err && err.stack ? err.stack : err);
      return json({ error: 'internal_error' }, 500);
    }
  },

  // 可选：在 wrangler.toml 里配置 Cron Trigger 后，定时从 Resend 补拉 Webhook 漏掉的邮件
  async scheduled(event, env, ctx) {
    if (!env.DB || !secret(env, 'RESEND_API_KEY')) return;
    ctx.waitUntil(
      ensureSchema(env.DB)
        .then(() => importFromResend(env))
        .then((r) => {
          if (!r.ok) console.error('scheduled import failed', r.error);
        }),
    );
  },
};

async function handle(request, env, ctx) {
  const url = new URL(request.url);
  const { pathname } = url;
  const method = request.method;

  if (method === 'GET' || method === 'HEAD') {
    if (pathname === '/manifest.webmanifest') return manifestResponse();
    if (pathname === '/icon.svg') return assetResponse(ICON_SVG, 'image/svg+xml');
    if (pathname === '/apple-touch-icon.png' || pathname === '/apple-touch-icon-precomposed.png') {
      return assetResponse(base64ToBytes(APPLE_TOUCH_ICON_B64), 'image/png');
    }
    if (pathname === '/favicon.ico') return new Response(null, { status: 204 });
  }

  // 带 Svix 签名头的 POST 一律按 Webhook 处理，Resend 里填成根地址也能收
  if (pathname === '/webhooks/resend' || (method === 'POST' && request.headers.has('svix-id'))) {
    if (method !== 'POST') return json({ error: 'method_not_allowed' }, 405);
    return handleResendWebhook(request, env, ctx);
  }

  const problems = configProblems(env);
  if (problems.length) {
    if (pathname.startsWith('/api/')) return json({ error: 'not_configured', problems }, 503);
    return setupPage(problems);
  }
  await ensureSchema(env.DB);

  if (pathname === '/api/ingest' && method === 'POST') return handleIngest(request, env);
  if (pathname === '/api/login' && method === 'POST') return handleLogin(request, env);
  if (pathname === '/api/logout' && method === 'POST') {
    return json({ ok: true }, 200, { 'Set-Cookie': `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax` });
  }

  const authed = await hasSession(request, env);
  if (pathname === '/' && (method === 'GET' || method === 'HEAD')) return authed ? appPage(env) : loginPage();
  if (pathname.startsWith('/api/')) {
    if (!authed) return json({ error: 'unauthorized' }, 401);
    // 简单 CSRF 防护：所有接口都要带自定义请求头（跨站表单和跳转都带不上）
    if (request.headers.get('X-Requested-With') !== 'fetch') return json({ error: 'forbidden' }, 403);
    return handleApi(request, env, url);
  }
  return new Response('Not found', { status: 404, headers: SECURITY_HEADERS });
}

function configProblems(env) {
  const problems = [];
  if (!env.DB) problems.push('DB');
  if (!env.ACCESS_PASSWORD) problems.push('ACCESS_PASSWORD');
  return problems;
}

/* ------------------------------------------------------------------ */
/* D1                                                                  */
/* ------------------------------------------------------------------ */

let schemaReady = null;

function ensureSchema(db) {
  if (!schemaReady) {
    schemaReady = db
      .batch([
        db.prepare(`CREATE TABLE IF NOT EXISTS messages (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          email_id TEXT UNIQUE,
          sender TEXT NOT NULL,
          body TEXT NOT NULL,
          code TEXT,
          sent_at INTEGER NOT NULL,
          raw_time TEXT,
          received_at INTEGER NOT NULL,
          is_read INTEGER NOT NULL DEFAULT 0
        )`),
        db.prepare('CREATE INDEX IF NOT EXISTS idx_messages_sender_time ON messages (sender, sent_at)'),
        db.prepare('CREATE INDEX IF NOT EXISTS idx_messages_time ON messages (sent_at)'),
        db.prepare('CREATE INDEX IF NOT EXISTS idx_messages_code ON messages (received_at) WHERE code IS NOT NULL'),
        db.prepare('CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL)'),
        db.prepare("INSERT OR IGNORE INTO meta (k, v) VALUES ('version', 0)"),
        db.prepare('CREATE TABLE IF NOT EXISTS login_fails (ip TEXT PRIMARY KEY, fails INTEGER NOT NULL, until INTEGER NOT NULL)'),
        // 已删除邮件的 Resend id，防止补拉时又导回来
        db.prepare('CREATE TABLE IF NOT EXISTS deleted_emails (email_id TEXT PRIMARY KEY)'),
        db.prepare(
          'CREATE TABLE IF NOT EXISTS webhook_log (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, status INTEGER NOT NULL, result TEXT NOT NULL, detail TEXT, email_id TEXT)',
        ),
      ])
      .catch((err) => {
        schemaReady = null;
        throw err;
      });
  }
  return schemaReady;
}

// 每次写入都递增 version，前端只需轮询这一行就知道有没有变化
const BUMP_VERSION_SQL = "UPDATE meta SET v = v + 1 WHERE k = 'version'";
const VERSION_SQL = "SELECT v FROM meta WHERE k = 'version'";
const THREADS_SQL = `
  SELECT sender, body, code, sent_at AS ts, id, unread, total FROM (
    SELECT sender, body, code, sent_at, id,
      ROW_NUMBER() OVER (PARTITION BY sender ORDER BY sent_at DESC, id DESC) AS rn,
      SUM(CASE WHEN is_read = 0 THEN 1 ELSE 0 END) OVER (PARTITION BY sender) AS unread,
      COUNT(*) OVER (PARTITION BY sender) AS total
    FROM messages
  ) WHERE rn = 1 ORDER BY sent_at DESC, id DESC LIMIT 1000`;
const LATEST_CODE_SQL = `
  SELECT id, sender, body, code, sent_at AS ts, received_at AS rx FROM messages
  WHERE code IS NOT NULL ORDER BY received_at DESC, id DESC LIMIT 1`;
const MESSAGE_COLUMNS = 'id, body, code, sent_at AS ts, received_at AS rx';

async function insertMessage(db, record, emailId, receivedAt = Date.now()) {
  const id = emailId || null;
  const [insert] = await db.batch([
    db
      .prepare(
        `INSERT OR IGNORE INTO messages (email_id, sender, body, code, sent_at, raw_time, received_at)
         SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7 WHERE NOT EXISTS (SELECT 1 FROM deleted_emails WHERE email_id = ?1)`,
      )
      .bind(id, record.sender, record.body, record.code || null, record.sentAt, record.rawTime || null, receivedAt),
    db.prepare(BUMP_VERSION_SQL),
  ]);
  return insert.meta.changes > 0;
}

/* ------------------------------------------------------------------ */
/* Resend inbound: webhook, import, diagnostics                        */
/* ------------------------------------------------------------------ */

// 控制台里粘贴的值常带空格、换行或引号
function secret(env, name) {
  return String(env[name] || '')
    .trim()
    .replace(/^(["'])([\s\S]*)\1$/, '$2')
    .trim();
}

// Resend API 要求带 User-Agent（否则被 403 error 1010 拦截），Workers 的 fetch 默认不带
async function resendGet(env, path) {
  const send = () =>
    fetch(`${secret(env, 'RESEND_API_URL') || RESEND_API}${path}`, {
      headers: { Authorization: `Bearer ${secret(env, 'RESEND_API_KEY')}`, 'User-Agent': RESEND_USER_AGENT, Accept: 'application/json' },
    });
  let res = await send();
  if (res.status === 429) {
    // 团队级限流（每秒几次），按 retry-after 等一下再试一次
    await sleep(Math.min(2000, (Number(res.headers.get('retry-after')) || 1) * 1000));
    res = await send();
  }
  return res;
}

async function resendJson(env, path) {
  const res = await resendGet(env, path);
  if (!res.ok) return { ok: false, error: await resendError(res) };
  return { ok: true, data: await res.json() };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function resendError(res) {
  const text = await res.text().catch(() => '');
  try {
    const body = JSON.parse(text);
    return `${res.status} ${body.name || ''} ${body.message || ''}`.trim();
  } catch {
    return `${res.status} ${text.slice(0, 200)}`.trim();
  }
}

async function handleResendWebhook(request, env, ctx) {
  let outcome;
  try {
    outcome = await processResendWebhook(request, env);
  } catch (err) {
    outcome = { status: 500, result: 'error', detail: String((err && err.message) || err) };
  }
  if (outcome.status >= 400) console.error('webhook', outcome.status, outcome.result, outcome.detail || '');
  if (env.DB && outcome.log !== false) {
    const write = logWebhook(env.DB, outcome).catch((err) => console.error('webhook log failed', err));
    if (ctx && ctx.waitUntil) ctx.waitUntil(write);
    else await write;
  }
  return json({ result: outcome.result, detail: outcome.detail || undefined }, outcome.status);
}

async function processResendWebhook(request, env) {
  if (!env.DB) return { status: 503, result: 'not_configured', detail: 'D1 数据库 DB 未绑定', log: false };
  await ensureSchema(env.DB);
  if (!secret(env, 'RESEND_WEBHOOK_SECRET')) return { status: 503, result: 'not_configured', detail: 'RESEND_WEBHOOK_SECRET 未设置' };

  const payload = await request.text();
  const problem = await webhookSignatureProblem(payload, request.headers, secret(env, 'RESEND_WEBHOOK_SECRET'));
  // 没带 Svix 头的多半是扫描器，不记日志
  if (problem) return { status: 401, result: 'invalid_signature', detail: problem, log: problem !== 'missing_headers' };

  let event;
  try {
    event = JSON.parse(payload);
  } catch {
    return { status: 400, result: 'invalid_json' };
  }
  if (!event || event.type !== 'email.received') return { status: 200, result: 'ignored_event', detail: String(event && event.type) };

  const data = event.data || {};
  if (!recipientAllowed(env.INBOX, data)) {
    return { status: 200, result: 'ignored_recipient', detail: recipientsOf(data).join(', '), emailId: data.email_id };
  }
  return { ...(await storeReceivedEmail(env, data)), emailId: data.email_id };
}

// Webhook 和补拉共用：Webhook / 列表接口都只有元数据，正文要再调 Receiving API 读取
async function storeReceivedEmail(env, meta) {
  const emailId = meta.email_id || meta.id;
  let email = meta;
  if (meta.text == null && meta.html == null) {
    if (!secret(env, 'RESEND_API_KEY')) return { status: 503, result: 'not_configured', detail: 'RESEND_API_KEY 未设置' };
    const res = await resendGet(env, `/emails/receiving/${encodeURIComponent(emailId)}?html_format=cid`);
    // 非 2xx → Resend 会重试这次 Webhook
    if (!res.ok) return { status: 502, result: 'resend_api_error', detail: await resendError(res) };
    email = { ...meta, ...(await res.json()) };
  }
  const record = messageFromEmail(email, parseTzOffset(env.TZ_OFFSET));
  // 用 Resend 收到邮件的时间：补拉或 Webhook 重试时，旧验证码不能显示成「刚刚」
  const receivedAt = Math.min(Date.now(), Date.parse(email.created_at || '') || Date.now());
  const inserted = await insertMessage(env.DB, record, emailId, receivedAt);
  return { status: 200, result: inserted ? 'stored' : 'duplicate', detail: record.sender };
}

async function logWebhook(db, outcome) {
  const now = Date.now();
  // 签名错误的请求谁都能发：每分钟最多记一条，免得被刷爆 D1 写入或冲掉真实记录
  const throttle = outcome.result === 'invalid_signature' ? now - 60000 : now + 1;
  await db.batch([
    db
      .prepare(
        `INSERT INTO webhook_log (at, status, result, detail, email_id) SELECT ?1, ?2, ?3, ?4, ?5
         WHERE NOT EXISTS (SELECT 1 FROM webhook_log WHERE result = ?3 AND at > ?6)`,
      )
      .bind(now, outcome.status, outcome.result, String(outcome.detail || '').slice(0, 300), outcome.emailId || null, throttle),
    db.prepare('DELETE FROM webhook_log WHERE id <= (SELECT MAX(id) FROM webhook_log) - ?').bind(WEBHOOK_LOG_KEEP),
  ]);
}

// 从 Resend 收件箱补拉 Webhook 没送达的邮件（已入库或已删除的跳过）。
// 平时只看最新一页；手动导入会往前翻页。每次请求最多读 maxFetch 封正文（Workers 子请求有上限），
// 没读完时返回 more: true，由前端接着再调。
async function importFromResend(env, { pageSize = IMPORT_LIMIT, maxPages = 1, maxFetch = 10 } = {}) {
  if (!secret(env, 'RESEND_API_KEY')) return { ok: false, error: 'RESEND_API_KEY 未设置' };
  const result = { ok: true, checked: 0, imported: 0, skipped: 0, errors: [], more: false };
  const seen = new Set();
  let after = '';
  let fetched = 0;
  pages: for (let page = 0; page < maxPages; page++) {
    const res = await resendGet(env, `/emails/receiving?limit=${pageSize}${after ? `&after=${encodeURIComponent(after)}` : ''}`);
    if (!res.ok) {
      if (!page) return { ok: false, error: await resendError(res) };
      result.errors.push(await resendError(res));
      break;
    }
    const list = await res.json();
    const emails = (list.data || []).filter((e) => e && e.id && !seen.has(e.id));
    if (!emails.length) break;
    emails.forEach((e) => seen.add(e.id));
    result.checked += emails.length;
    const known = await knownEmailIds(env.DB, emails.map((e) => e.id));
    for (const email of emails.slice().reverse()) {
      if (known.has(email.id)) continue;
      if (!recipientAllowed(env.INBOX, email)) {
        result.skipped++;
        continue;
      }
      if (fetched >= maxFetch) {
        result.more = true;
        break pages;
      }
      if (fetched++) await sleep(300); // 别撞上 Resend 的团队限流
      const stored = await storeReceivedEmail(env, { ...email, email_id: email.id });
      if (stored.result === 'stored') result.imported++;
      else if (stored.status >= 400) {
        result.errors.push(stored.detail);
        if (/^429\b/.test(stored.detail)) {
          result.more = true; // 剩下的留给下次补拉
          break pages;
        }
      }
    }
    if (!list.has_more) break;
    after = emails[emails.length - 1].id;
  }
  return result;
}

// email_id → 'stored' | 'deleted'
async function knownEmailIds(db, ids) {
  const known = new Map();
  if (!ids.length) return known;
  const marks = ids.map(() => '?').join(',');
  const [stored, deleted] = await db.batch([
    db.prepare(`SELECT email_id FROM messages WHERE email_id IN (${marks})`).bind(...ids),
    db.prepare(`SELECT email_id FROM deleted_emails WHERE email_id IN (${marks})`).bind(...ids),
  ]);
  for (const row of deleted.results) known.set(row.email_id, 'deleted');
  for (const row of stored.results) known.set(row.email_id, 'stored');
  return known;
}

// 页面打开时顺手补拉一次；限流，避免每个设备每次轮询都打 Resend
async function throttledImport(env, force) {
  const db = env.DB;
  const now = Date.now();
  if (force) return importFromResend(env, { pageSize: 100, maxPages: 10, maxFetch: 25 });
  const claim = await db
    .prepare("INSERT INTO meta (k, v) VALUES ('last_import', ?1) ON CONFLICT(k) DO UPDATE SET v = ?1 WHERE v < ?2")
    .bind(now, now - IMPORT_THROTTLE_MS)
    .run();
  if (!claim.meta.changes) return { ok: true, throttled: true, imported: 0 };
  return importFromResend(env);
}

async function diagnostics(env, origin) {
  const db = env.DB;
  const config = {
    webhookUrl: `${origin}/webhooks/resend`,
    apiKey: !secret(env, 'RESEND_API_KEY') ? 'missing' : /^re_[\w-]+$/.test(secret(env, 'RESEND_API_KEY')) ? 'ok' : 'format',
    webhookSecret: webhookSecretState(secret(env, 'RESEND_WEBHOOK_SECRET')),
    inbox: String(env.INBOX || '').trim(),
    tz: String(env.TZ_OFFSET || '+08:00'),
  };
  let resend = null;
  let setup = null;
  if (config.apiKey !== 'missing') {
    const res = await resendGet(env, '/emails/receiving?limit=10');
    setup = await resendSetup(env, origin).catch((err) => {
      const error = String((err && err.message) || err);
      return { webhooks: { ok: false, error }, domains: { ok: false, error } };
    });
    if (res.ok) {
      const emails = ((await res.json()).data || []).filter((e) => e && e.id);
      const known = await knownEmailIds(db, emails.map((e) => e.id));
      resend = {
        ok: true,
        emails: emails.map((e) => ({
          id: e.id,
          to: recipientsOf(e).join(', '),
          from: displayFrom(e.from),
          // INBOX 之外的邮件只显示收件人，不显示主题
          subject: recipientAllowed(env.INBOX, e) ? e.subject || '' : '',
          at: Date.parse(e.created_at || '') || null,
          state: known.get(e.id) || 'missing',
          allowed: recipientAllowed(env.INBOX, e),
        })),
      };
    } else {
      resend = { ok: false, error: await resendError(res) };
    }
  }
  const [log, count] = await db.batch([
    db.prepare('SELECT at, status, result, detail FROM webhook_log ORDER BY id DESC LIMIT 20'),
    db.prepare('SELECT COUNT(*) AS n FROM messages'),
  ]);
  return { config, resend, setup, webhooks: log.results, messages: count.results[0] ? count.results[0].n : 0, now: Date.now() };
}

// 读 Resend 后台的 Webhook 和域名收信配置，再用 DoH 查 MX，判断邮件到底能不能进 Resend
async function resendSetup(env, origin) {
  const ownHost = new URL(origin).host;
  const hooks = await resendJson(env, '/webhooks');
  const webhooks = hooks.ok
    ? {
        ok: true,
        items: (hooks.data.data || []).map((w) => {
          let url = null;
          try {
            url = new URL(w.endpoint);
          } catch {}
          return {
            endpoint: url ? url.origin + url.pathname : String(w.endpoint || ''),
            status: w.status,
            events: w.events,
            matches: !!url && (url.host === ownHost || url.pathname === '/webhooks/resend'),
          };
        }),
      }
    : { ok: false, error: hooks.error };

  const list = await resendJson(env, '/domains');
  let domains;
  if (list.ok) {
    const items = [];
    for (const d of (list.data.data || []).slice(0, 5)) {
      const detail = await resendJson(env, `/domains/${encodeURIComponent(d.id)}`);
      const records = detail.ok ? detail.data.records || [] : [];
      const mx = records.find((r) => r.record === 'Receiving');
      items.push({
        name: d.name,
        receiving: ((detail.ok && detail.data.capabilities) || d.capabilities || {}).receiving || 'disabled',
        mxRecord: mx ? { status: mx.status, value: mx.value, priority: mx.priority } : null,
        dns: await lookupMx(d.name),
      });
    }
    domains = { ok: true, items };
  } else {
    domains = { ok: false, error: list.error };
  }
  return { webhooks, domains };
}

async function lookupMx(host) {
  try {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=MX`, {
      headers: { Accept: 'application/dns-json' },
    });
    if (!res.ok) return null;
    const body = await res.json();
    return (body.Answer || [])
      .filter((a) => a.type === 15)
      .map((a) => {
        const [priority, target] = String(a.data).split(/\s+/);
        return { priority: Number(priority), host: String(target || '').replace(/\.$/, '') };
      })
      .sort((x, y) => x.priority - y.priority);
  } catch {
    return null;
  }
}

function webhookSecretState(value) {
  if (!value) return 'missing';
  try {
    return base64ToBytes(value.replace(/^whsec_/, '')).length >= 16 ? 'ok' : 'format';
  } catch {
    return 'format';
  }
}

function recipientsOf(data) {
  return [...new Set([].concat(data.received_for || [], data.to || []).map(emailAddress).filter(Boolean))];
}

// Resend 使用 Svix / Standard Webhooks 签名：base64(HMAC-SHA256(secret, `${id}.${timestamp}.${body}`))
async function verifyWebhookSignature(payload, headers, secretValue) {
  return (await webhookSignatureProblem(payload, headers, secretValue)) === '';
}

async function webhookSignatureProblem(payload, headers, secretValue) {
  const id = headers.get('svix-id') || headers.get('webhook-id');
  const timestamp = headers.get('svix-timestamp') || headers.get('webhook-timestamp');
  const signatures = headers.get('svix-signature') || headers.get('webhook-signature');
  if (!id || !timestamp || !signatures) return 'missing_headers';
  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || Math.abs(Date.now() / 1000 - ts) > WEBHOOK_TOLERANCE_S) return 'stale_timestamp';

  let keyBytes;
  try {
    keyBytes = base64ToBytes(secretValue.trim().replace(/^whsec_/, ''));
  } catch {
    return 'secret_not_base64';
  }
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(`${id}.${timestamp}.${payload}`)));
  const expected = enc.encode(bytesToBase64(mac));
  const ok = signatures.split(' ').some((part) => {
    const [version, signature] = part.split(',');
    return version === 'v1' && signature && timingSafeEqual(enc.encode(signature), expected);
  });
  return ok ? '' : 'signature_mismatch';
}

function recipientAllowed(inbox, data) {
  const rules = String(inbox || '')
    .toLowerCase()
    .split(/[\s,;]+/)
    .filter(Boolean);
  if (!rules.length) return true;
  const addresses = [].concat(data.received_for || [], data.to || [], data.cc || []).map(emailAddress).filter(Boolean);
  // "a@b.com" 精确匹配；"@b.com" 或 "b.com" 匹配整个域
  return addresses.some((addr) =>
    rules.some((rule) => (rule.includes('@') && !rule.startsWith('@') ? addr === rule : addr.endsWith(`@${rule.replace(/^@/, '')}`))),
  );
}

function emailAddress(value) {
  const s = String(value || '').trim().toLowerCase();
  const m = /<([^>]+)>/.exec(s);
  return (m ? m[1] : s).trim();
}

function inboxLabel(env) {
  const first = String(env.INBOX || '')
    .split(/[\s,;]+/)
    .find((rule) => rule.includes('@') && !rule.startsWith('@'));
  return first || '';
}

/* ------------------------------------------------------------------ */
/* Direct ingest (optional)                                            */
/* ------------------------------------------------------------------ */

async function handleIngest(request, env) {
  if (!env.INGEST_TOKEN) return json({ error: 'ingest_disabled' }, 404);
  const token = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  if (!token || !(await secretsMatch(token, env.INGEST_TOKEN))) return json({ error: 'unauthorized' }, 401);

  const type = request.headers.get('Content-Type') || '';
  let text = '';
  if (type.includes('application/json')) {
    const body = await request.json().catch(() => ({}));
    if (typeof body.text === 'string') text = body.text;
    else if (typeof body.content === 'string') text = [body.content, body.sender || body.from || '', body.time || ''].join('/');
  } else {
    text = await request.text();
  }
  if (!text.trim()) return json({ error: 'empty' }, 400);

  const record = messageFromEmail({ text }, parseTzOffset(env.TZ_OFFSET));
  await insertMessage(env.DB, record, null);
  return json({ ok: true, message: { sender: record.sender, body: record.body, code: record.code, ts: record.sentAt } });
}

/* ------------------------------------------------------------------ */
/* Parsing: 「内容/发件人/时间」                                       */
/* ------------------------------------------------------------------ */

function messageFromEmail(email, tzMinutes, now = Date.now()) {
  const text = normalizeText(email.text && email.text.trim() ? email.text : htmlToText(email.html || ''));
  const subject = normalizeText(email.subject || '');
  const parsed = parseSms(text, tzMinutes, now) || parseWithoutTrailingLines(text, tzMinutes, now) || parseSms(subject, tzMinutes, now);
  const base = parsed || {
    body: text || subject || '（无内容）',
    sender: displayFrom(email.from) || '未知发件人',
    sentAt: Date.parse(email.created_at || '') || now,
    rawTime: '',
  };
  const body = base.body.slice(0, MAX_BODY_CHARS);
  return { ...base, body, code: extractCode(body) };
}

// 时间里可能也带 "/"（2026/10/22 20:22），所以从右往左试几个分隔符，取能解析成时间的最长后缀
function parseSms(raw, tzMinutes, now = Date.now()) {
  const s = normalizeText(raw);
  if (!s) return null;
  let split = -1;
  let sentAt = null;
  let rawTime = '';
  let p = s.length;
  for (let i = 0; i < 4; i++) {
    p = s.lastIndexOf('/', p - 1);
    if (p <= 0) break;
    const candidate = s.slice(p + 1).trim();
    const ts = parseSmsTime(candidate, tzMinutes, now);
    if (ts != null) {
      split = p;
      sentAt = ts;
      rawTime = candidate;
    }
  }
  if (split < 0) return null;
  const head = s.slice(0, split);
  const q = head.lastIndexOf('/');
  if (q <= 0) return null;
  const sender = head.slice(q + 1).trim();
  const body = head.slice(0, q).trim();
  if (!sender || !body || sender.length > 64 || sender.includes('\n')) return null;
  return { body, sender: normalizeSender(sender), sentAt, rawTime };
}

// 邮件客户端可能在末尾追加签名，逐行去掉末尾再试
function parseWithoutTrailingLines(text, tzMinutes, now) {
  const lines = text.split('\n');
  for (let n = lines.length - 1; n >= 1 && lines.length - n <= 12; n--) {
    const parsed = parseSms(lines.slice(0, n).join('\n'), tzMinutes, now);
    if (parsed) return parsed;
  }
  return null;
}

const SMS_TIME_RE =
  /^(?:(\d{4})\s*[年/.-]\s*)?(\d{1,2})\s*[月/.-]\s*(\d{1,2})\s*日?[\sT,，]*(?:(?:星期|周|礼拜)[一二三四五六日天]\s*)?(凌晨|早上|早晨|上午|中午|下午|傍晚|晚上|夜里|夜间|AM|PM|am|pm)?\s*(\d{1,2})[:：](\d{2})(?:[:：](\d{2}))?(?:\.\d+)?\s*(AM|PM|am|pm)?\s*(Z|(?:GMT|UTC)?\s*[+-]\d{1,2}:?\d{2})?$/;

function parseSmsTime(input, tzMinutes, now = Date.now()) {
  const s = String(input || '').trim().replace(/\s+/g, ' ');
  if (!s || s.length > 48) return null;
  if (/^\d{13}$/.test(s)) return Number(s);
  if (/^\d{10}$/.test(s)) return Number(s) * 1000;
  const m = SMS_TIME_RE.exec(s);
  if (!m) return null;
  const [, year, mo, d, period1, h, mi, sec, period2, zone] = m;
  const month = Number(mo);
  const day = Number(d);
  let hour = Number(h);
  const minute = Number(mi);
  const second = Number(sec || 0);
  if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) return null;

  const period = period1 || period2;
  if (period) {
    if (/^(下午|傍晚|晚上|夜里|夜间|pm)$/i.test(period)) {
      if (hour < 12) hour += 12;
    } else if (period === '中午') {
      if (hour < 11) hour += 12;
    } else if (hour === 12) {
      hour = 0; // 凌晨/上午/AM 12 点
    }
  }

  const offset = zone ? parseTzOffset(zone.replace(/^(GMT|UTC)\s*/i, '').replace(/^Z$/i, '+00:00')) : tzMinutes;
  const toTs = (y) => Date.UTC(y, month - 1, day, hour, minute, second) - offset * 60000;
  let ts;
  if (year) {
    ts = toTs(Number(year));
  } else {
    const y = new Date(now + offset * 60000).getUTCFullYear();
    ts = toTs(y);
    if (ts > now + 2 * 86400000) ts = toTs(y - 1); // 没写年份且落在未来 → 去年
  }
  if (new Date(ts + offset * 60000).getUTCDate() !== day) return null; // 2 月 31 日之类
  return ts;
}

function parseTzOffset(value) {
  const m = /^([+-])(\d{1,2})(?::?(\d{2}))?$/.exec(String(value || '').trim());
  if (!m) return 480;
  const minutes = Number(m[2]) * 60 + Number(m[3] || 0);
  return m[1] === '-' ? -minutes : minutes;
}

function normalizeSender(raw) {
  let s = String(raw).trim();
  const compact = s.replace(/[\s\-()（）]/g, '');
  if (/^\+?\d{3,20}$/.test(compact)) {
    s = compact;
    const cn = /^(?:\+?86|0086)?(1[3-9]\d{9})$/.exec(s);
    if (cn) s = `+86${cn[1]}`;
  }
  return s.slice(0, 64);
}

const CODE_KEYWORD_RE =
  /验证码|校验码|检验码|确认码|激活码|动态码|动态密码|随机码|安全码|认证码|授权码|登录码|登陆码|短信码|交易码|口令|取件码|取货码|提货码|取餐码|verification code|security code|confirmation code|login code|sign[- ]?in code|one[- ]?time (?:password|passcode|code)|auth(?:entication)? code|passcode|\bcode\b|\botp\b|\bpin\b/gi;
const CODE_CANDIDATE_RE = /(?<![A-Za-z0-9-])(\d{1,4}(?:-\d{1,4}){1,3})(?![A-Za-z0-9])|(?<![A-Za-z0-9])([A-Za-z0-9]{4,8})(?![A-Za-z0-9])/g;
const NOT_CODE_BEFORE_RE = /(尾号|账户|账号|卡号|手机|号码|编号|单号|订单|工号|ID|No\.?)\s*[:：]?\s*$/i;
const NOT_CODE_AFTER_RE = /^\s*(元|块|分钟|分|秒|小时|天|年|月|日|号|人|次|笔|%|[.,]\d)/;

// 找离「验证码」等关键词最近的 4-8 位数字/字母串
function extractCode(text) {
  if (!text) return null;
  const keywords = [...text.matchAll(CODE_KEYWORD_RE)].map((m) => [m.index, m.index + m[0].length]);
  if (!keywords.length) return null;
  let best = null;
  for (const m of text.matchAll(CODE_CANDIDATE_RE)) {
    const token = m[1] || m[2];
    const start = m.index;
    const end = start + token.length;
    const digits = token.replace(/\D/g, '').length;
    const letters = token.replace(/[^A-Za-z]/g, '').length;
    if (digits === 0 || (letters && digits < 2)) continue;
    if (m[1] && (digits < 4 || /^(19|20)\d{2}-/.test(token))) continue; // 太短或像日期
    if (NOT_CODE_BEFORE_RE.test(text.slice(Math.max(0, start - 8), start))) continue;
    if (NOT_CODE_AFTER_RE.test(text.slice(end, end + 4))) continue;
    let score = Infinity;
    for (const [ks, ke] of keywords) {
      if (start >= ke) score = Math.min(score, start - ke);
      else if (end <= ks) score = Math.min(score, ks - end + 4);
    }
    if (score > 24) continue;
    if (letters) score += 6;
    if (!best || score < best.score) best = { code: token, score };
  }
  return best ? best.code : null;
}

function normalizeText(value) {
  return String(value || '')
    .replace(/\r\n?/g, '\n')
    .replace(/[​-‍﻿]/g, '')
    .replace(/ /g, ' ')
    .trim();
}

function htmlToText(html) {
  return decodeEntities(
    String(html || '')
      .replace(/<(script|style|head)[\s\S]*?<\/\1>/gi, '')
      .replace(/<br\s*\/?>/gi, '\n')
      .replace(/<\/(p|div|li|tr|h[1-6])>/gi, '\n')
      .replace(/<[^>]+>/g, ''),
  )
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function decodeEntities(s) {
  const named = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (all, ref) => {
    if (ref[0] === '#') {
      const code = ref[1] === 'x' || ref[1] === 'X' ? parseInt(ref.slice(2), 16) : parseInt(ref.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code < 0x110000 ? String.fromCodePoint(code) : all;
    }
    return named[ref.toLowerCase()] ?? all;
  });
}

function displayFrom(from) {
  const s = String(from || '').trim();
  const m = /^"?([^"<]*?)"?\s*<([^>]+)>$/.exec(s);
  if (m) return m[1].trim() || m[2].trim();
  return s;
}

/* ------------------------------------------------------------------ */
/* Auth                                                                */
/* ------------------------------------------------------------------ */

async function handleLogin(request, env) {
  const db = env.DB;
  const ip = request.headers.get('CF-Connecting-IP') || 'local';
  const now = Date.now();
  const row = await db.prepare('SELECT fails, until FROM login_fails WHERE ip = ?').bind(ip).first();
  if (row && row.until > now && row.fails >= LOGIN_MAX_FAILS) {
    return json({ error: 'too_many_attempts', retryAfter: Math.ceil((row.until - now) / 1000) }, 429);
  }

  const body = await request.json().catch(() => ({}));
  const password = typeof body.password === 'string' ? body.password : '';
  if (password && (await secretsMatch(password, env.ACCESS_PASSWORD))) {
    if (row) await db.prepare('DELETE FROM login_fails WHERE ip = ?').bind(ip).run();
    const token = await createSession(env);
    return json({ ok: true }, 200, {
      'Set-Cookie': `${SESSION_COOKIE}=${token}; Path=/; Max-Age=${SESSION_DAYS * 86400}; HttpOnly; Secure; SameSite=Lax`,
    });
  }

  const fails = row && row.until > now ? row.fails + 1 : 1;
  await db
    .prepare('INSERT INTO login_fails (ip, fails, until) VALUES (?1, ?2, ?3) ON CONFLICT(ip) DO UPDATE SET fails = ?2, until = ?3')
    .bind(ip, fails, now + LOGIN_WINDOW_MS)
    .run();
  return json({ error: 'wrong_password' }, 401);
}

// 会话 = 过期时间 + HMAC 签名；密钥由访问密码派生，改密码即让所有会话失效
async function sessionKey(env) {
  const raw = await crypto.subtle.digest('SHA-256', enc.encode(`sms-inbox/session/v1\n${env.ACCESS_PASSWORD}`));
  return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function createSession(env) {
  const exp = String(Date.now() + SESSION_DAYS * 86400000);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', await sessionKey(env), enc.encode(exp)));
  return `${exp}.${bytesToBase64(sig).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}`;
}

async function hasSession(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return false;
  const [exp, sig] = token.split('.');
  if (!sig || !/^\d+$/.test(exp) || Number(exp) < Date.now()) return false;
  let sigBytes;
  try {
    sigBytes = base64ToBytes(sig.replace(/-/g, '+').replace(/_/g, '/'));
  } catch {
    return false;
  }
  return crypto.subtle.verify('HMAC', await sessionKey(env), sigBytes, enc.encode(exp));
}

function getCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return '';
}

async function secretsMatch(a, b) {
  const [x, y] = await Promise.all([sha256(a), sha256(b)]);
  return timingSafeEqual(x, y);
}

async function sha256(value) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(String(value))));
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToBase64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

/* ------------------------------------------------------------------ */
/* JSON API                                                            */
/* ------------------------------------------------------------------ */

async function handleApi(request, env, url) {
  const db = env.DB;
  const path = url.pathname;
  const params = url.searchParams;

  if (request.method === 'GET') {
    if (path === '/api/version') {
      const row = await db.prepare(VERSION_SQL).first();
      return json({ version: row ? row.v : 0 });
    }

    if (path === '/api/threads') {
      const [version, threads, code] = await db.batch([db.prepare(VERSION_SQL), db.prepare(THREADS_SQL), db.prepare(LATEST_CODE_SQL)]);
      return json({
        version: version.results[0] ? version.results[0].v : 0,
        threads: threads.results,
        latestCode: code.results[0] || null,
        now: Date.now(),
      });
    }

    if (path === '/api/messages') {
      const sender = params.get('sender');
      if (!sender) return json({ error: 'missing_sender' }, 400);

      if (params.has('after')) {
        const { results } = await db
          .prepare(`SELECT ${MESSAGE_COLUMNS} FROM messages WHERE sender = ? AND id > ? ORDER BY sent_at, id LIMIT 500`)
          .bind(sender, Number(params.get('after')) || 0)
          .all();
        return json({ messages: results });
      }

      const beforeTs = Number(params.get('before_ts'));
      const beforeId = Number(params.get('before_id'));
      const stmt =
        params.has('before_ts') && Number.isFinite(beforeTs) && Number.isFinite(beforeId)
          ? db
              .prepare(
                `SELECT ${MESSAGE_COLUMNS} FROM messages WHERE sender = ?1 AND (sent_at < ?2 OR (sent_at = ?2 AND id < ?3))
                 ORDER BY sent_at DESC, id DESC LIMIT ?4`,
              )
              .bind(sender, beforeTs, beforeId, PAGE_SIZE + 1)
          : db
              .prepare(`SELECT ${MESSAGE_COLUMNS} FROM messages WHERE sender = ? ORDER BY sent_at DESC, id DESC LIMIT ?`)
              .bind(sender, PAGE_SIZE + 1);
      const { results } = await stmt.all();
      return json({ messages: results.slice(0, PAGE_SIZE).reverse(), hasMore: results.length > PAGE_SIZE });
    }

    if (path === '/api/search') {
      const q = (params.get('q') || '').trim().slice(0, 64);
      if (!q) return json({ results: [] });
      const like = `%${q.replace(/[\\%_]/g, '\\$&')}%`;
      const { results } = await db
        .prepare(
          `SELECT id, sender, body, code, sent_at AS ts FROM messages
           WHERE body LIKE ?1 ESCAPE '\\' OR sender LIKE ?1 ESCAPE '\\'
           ORDER BY sent_at DESC, id DESC LIMIT 60`,
        )
        .bind(like)
        .all();
      return json({ results });
    }
  }

  if (request.method === 'POST') {
    const body = await request.json().catch(() => ({}));

    if (path === '/api/read') {
      let stmt;
      if (body.all === true) {
        stmt = db.prepare('UPDATE messages SET is_read = 1 WHERE is_read = 0');
      } else if (typeof body.sender === 'string') {
        stmt =
          body.read === false
            ? db
                .prepare('UPDATE messages SET is_read = 0 WHERE id = (SELECT id FROM messages WHERE sender = ? ORDER BY sent_at DESC, id DESC LIMIT 1)')
                .bind(body.sender)
            : db.prepare('UPDATE messages SET is_read = 1 WHERE sender = ? AND is_read = 0').bind(body.sender);
      } else {
        return json({ error: 'bad_request' }, 400);
      }
      await db.batch([stmt, db.prepare(BUMP_VERSION_SQL)]);
      return json({ ok: true });
    }

    if (path === '/api/delete') {
      let where;
      let value;
      if (Number.isInteger(body.id)) [where, value] = ['id = ?', body.id];
      else if (typeof body.sender === 'string') [where, value] = ['sender = ?', body.sender];
      else return json({ error: 'bad_request' }, 400);
      await db.batch([
        db.prepare(`INSERT OR IGNORE INTO deleted_emails (email_id) SELECT email_id FROM messages WHERE ${where} AND email_id IS NOT NULL`).bind(value),
        db.prepare(`DELETE FROM messages WHERE ${where}`).bind(value),
        db.prepare(BUMP_VERSION_SQL),
      ]);
      return json({ ok: true });
    }

    if (path === '/api/import') return json(await throttledImport(env, body.force === true));
  }

  if (request.method === 'GET' && path === '/api/diagnostics') return json(await diagnostics(env, url.origin));

  return json({ error: 'not_found' }, 404);
}

/* ------------------------------------------------------------------ */
/* Responses                                                           */
/* ------------------------------------------------------------------ */

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
};

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...SECURITY_HEADERS, ...extraHeaders },
  });
}

function htmlResponse(body, nonce, status = 200) {
  const csp = [
    "default-src 'none'",
    `script-src 'nonce-${nonce}'`,
    `style-src 'nonce-${nonce}'`,
    "img-src 'self' data:",
    "connect-src 'self'",
    "manifest-src 'self'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; ');
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Security-Policy': csp, ...SECURITY_HEADERS },
  });
}

function assetResponse(body, type) {
  return new Response(body, { headers: { 'Content-Type': type, 'Cache-Control': 'public, max-age=86400', ...SECURITY_HEADERS } });
}

function manifestResponse() {
  const manifest = {
    name: '信息',
    short_name: '信息',
    start_url: '/',
    scope: '/',
    display: 'standalone',
    background_color: '#ffffff',
    theme_color: '#ffffff',
    icons: [
      { src: '/icon.svg', sizes: 'any', type: 'image/svg+xml' },
      { src: '/apple-touch-icon.png', sizes: '180x180', type: 'image/png' },
    ],
  };
  return assetResponse(JSON.stringify(manifest), 'application/manifest+json');
}

function makeNonce() {
  return bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

function headCommon(title) {
  return `<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#ffffff" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#000000" media="(prefers-color-scheme: dark)">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="信息">
<meta name="apple-mobile-web-app-status-bar-style" content="default">
<meta name="format-detection" content="telephone=no">
<meta name="robots" content="noindex, nofollow">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="icon" href="/icon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<title>${escapeHtml(title)}</title>`;
}

function appPage(env) {
  const nonce = makeNonce();
  const cfg = JSON.stringify({ inbox: inboxLabel(env), icons: ICONS }).replace(/</g, '\\u003c');
  const html = `<!doctype html>
<html lang="zh-CN">
<head>
${headCommon('信息')}
<style nonce="${nonce}">${BASE_CSS}${APP_CSS}</style>
</head>
<body>
${appBody()}
<script id="cfg" type="application/json">${cfg}</script>
<script nonce="${nonce}">${APP_JS}</script>
</body>
</html>`;
  return htmlResponse(html, nonce);
}

function loginPage() {
  const nonce = makeNonce();
  const html = `<!doctype html>
<html lang="zh-CN">
<head>
${headCommon('信息 · 登录')}
<style nonce="${nonce}">${BASE_CSS}${LOGIN_CSS}</style>
</head>
<body>
<main class="login">
  <div class="login-card" id="box">
    <img class="login-icon" src="/apple-touch-icon.png" alt="" width="76" height="76">
    <h1 class="login-title">信息</h1>
    <p class="login-sub">输入访问密码以查看短信</p>
    <form id="form" class="login-form" autocomplete="on">
      <input class="sr-only" type="text" name="username" autocomplete="username" value="sms" tabindex="-1" aria-hidden="true">
      <div class="login-field glass">
        <input id="pw" type="password" name="password" autocomplete="current-password" placeholder="密码" aria-label="访问密码" required autofocus enterkeyhint="go">
        <button id="go" class="login-go" type="submit" aria-label="登录">${ICONS.arrowCircle}</button>
      </div>
      <p id="msg" class="login-msg" role="alert"></p>
    </form>
  </div>
</main>
<script nonce="${nonce}">${LOGIN_JS}</script>
</body>
</html>`;
  return htmlResponse(html, nonce);
}

function setupPage(problems) {
  const nonce = makeNonce();
  const items = {
    DB: '绑定 D1 数据库，变量名 <code>DB</code>（wrangler.toml 里的 <code>[[d1_databases]]</code>）',
    ACCESS_PASSWORD: '设置访问密码：<code>npx wrangler secret put ACCESS_PASSWORD</code>',
  };
  const html = `<!doctype html>
<html lang="zh-CN">
<head>
${headCommon('信息 · 尚未配置')}
<style nonce="${nonce}">${BASE_CSS}${LOGIN_CSS}</style>
</head>
<body>
<main class="login">
  <div class="login-card">
    <img class="login-icon" src="/apple-touch-icon.png" alt="" width="76" height="76">
    <h1 class="login-title">还差一步</h1>
    <p class="login-sub">Worker 已运行，但还缺少以下配置：</p>
    <ul class="setup-list">${problems.map((p) => `<li>${items[p] || escapeHtml(p)}</li>`).join('')}</ul>
  </div>
</main>
</body>
</html>`;
  return htmlResponse(html, nonce, 503);
}

/* ------------------------------------------------------------------ */
/* Icons（SF Symbols 风格，前后端共用）                                */
/* ------------------------------------------------------------------ */

const ICONS = {
  chevronLeft:
    '<svg viewBox="0 0 12 20" width="12" height="20"><path d="M10 1.9 1.9 10l8.1 8.1" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  chevronSmall:
    '<svg viewBox="0 0 8 14" width="8" height="14"><path d="M1.5 1.5 6.5 7l-5 5.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  chevronTiny:
    '<svg viewBox="0 0 6 10" width="6" height="10"><path d="M1.2 1.2 4.8 5 1.2 8.8" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  ellipsis:
    '<svg viewBox="0 0 24 24" width="22" height="22"><circle cx="5" cy="12" r="2" fill="currentColor"/><circle cx="12" cy="12" r="2" fill="currentColor"/><circle cx="19" cy="12" r="2" fill="currentColor"/></svg>',
  search:
    '<svg viewBox="0 0 20 20" width="17" height="17"><circle cx="8.5" cy="8.5" r="6" fill="none" stroke="currentColor" stroke-width="2.1"/><path d="m13 13 5 5" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round"/></svg>',
  xmarkFill:
    '<svg viewBox="0 0 20 20" width="18" height="18"><circle cx="10" cy="10" r="9" fill="currentColor"/><path class="xm" d="m6.9 6.9 6.2 6.2m0-6.2-6.2 6.2" fill="none" stroke-width="1.8" stroke-linecap="round"/></svg>',
  copy:
    '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"><rect x="8" y="8" width="12" height="13" rx="2.6"/><path d="M16 8V5.6A2.6 2.6 0 0 0 13.4 3H6.6A2.6 2.6 0 0 0 4 5.6v8.8A2.6 2.6 0 0 0 6.6 17H8"/></svg>',
  key:
    '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="12" r="4"/><path d="M11.5 12H21m-3.5 0v3.2M21 12v2.4"/></svg>',
  trash:
    '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6.5h16M9.5 6.5V4.8c0-.7.6-1.3 1.3-1.3h2.4c.7 0 1.3.6 1.3 1.3v1.7M6 6.5l.9 12.2a2 2 0 0 0 2 1.8h6.2a2 2 0 0 0 2-1.8L18 6.5M10 10.5v6M14 10.5v6"/></svg>',
  trashFill:
    '<svg viewBox="0 0 24 24" width="24" height="24"><path fill="currentColor" fill-rule="evenodd" d="M9.6 3h4.8c.9 0 1.6.7 1.6 1.6V6h3.8a.8.8 0 0 1 0 1.6h-.9l-.8 11.5a2.6 2.6 0 0 1-2.6 2.4H8.5a2.6 2.6 0 0 1-2.6-2.4L5.1 7.6h-.9a.8.8 0 0 1 0-1.6H8V4.6C8 3.7 8.7 3 9.6 3Zm0 1.6V6h4.8V4.6H9.6Z"/></svg>',
  bubble:
    '<svg viewBox="0 0 24 24" width="24" height="24"><path fill="currentColor" d="M12 3.6c-5 0-9 3.3-9 7.4 0 2.4 1.4 4.6 3.6 5.9-.2 1.3-.9 2.6-2 3.4 2.1 0 4-.8 5.3-2 .7.1 1.4.2 2.1.2 5 0 9-3.3 9-7.5S17 3.6 12 3.6Z"/></svg>',
  bubbleBadge:
    '<svg viewBox="0 0 24 24" width="24" height="24"><path fill="currentColor" d="M15.1 4.1A10.6 10.6 0 0 0 12 3.6c-5 0-9 3.3-9 7.4 0 2.4 1.4 4.6 3.6 5.9-.2 1.3-.9 2.6-2 3.4 2.1 0 4-.8 5.3-2 .7.1 1.4.2 2.1.2 5 0 9-3.3 9-7.5 0-.6-.1-1.1-.2-1.6a5 5 0 0 1-5.7-5.3Z"/><circle cx="19.5" cy="4.5" r="3.3" fill="currentColor"/></svg>',
  logout:
    '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 4h3.4A2.6 2.6 0 0 1 20 6.6v10.8a2.6 2.6 0 0 1-2.6 2.6H14M10 16l-4-4 4-4M6 12h10"/></svg>',
  person:
    '<svg viewBox="0 0 40 40" width="100%" height="100%"><circle cx="20" cy="15.4" r="6.9" fill="#fff"/><path d="M7.2 33.6c2.1-5.8 7-8.9 12.8-8.9s10.7 3.1 12.8 8.9A18.7 18.7 0 0 1 20 38.7a18.7 18.7 0 0 1-12.8-5.1Z" fill="#fff"/></svg>',
  check:
    '<svg viewBox="0 0 22 22" width="22" height="22"><circle class="ok" cx="11" cy="11" r="11"/><path d="m6.6 11.3 3 3 5.9-6.3" fill="none" stroke="#fff" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  appIcon:
    '<svg viewBox="0 0 20 20" width="20" height="20"><rect class="app" width="20" height="20" rx="4.6"/><path fill="#fff" d="M10 4.4c-3.4 0-6.1 2.2-6.1 4.9 0 1.5.8 2.8 2.1 3.7-.1.9-.6 1.8-1.4 2.4 1.4 0 2.6-.5 3.5-1.3.6.1 1.2.2 1.9.2 3.4 0 6.1-2.2 6.1-5S13.4 4.4 10 4.4Z"/></svg>',
  emptyBubbles:
    '<svg viewBox="0 0 64 64" width="64" height="64" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linejoin="round"><path d="M27 10c-11.6 0-21 7.6-21 17 0 5.4 3.1 10.2 8 13.3-.4 2.8-1.9 5.6-4.4 7.4 4.6 0 8.8-1.8 11.6-4.5 1.9.5 3.8.8 5.8.8 11.6 0 21-7.6 21-17S38.6 10 27 10Z"/><path d="M51.6 26.5C55.5 29.3 58 33.2 58 37.6c0 4.4-2.4 8.4-6.3 11 .3 2.3 1.6 4.5 3.6 6-3.8 0-7.2-1.5-9.5-3.7-1.5.4-3.1.6-4.8.6-6 0-11.3-2.6-14.2-6.5"/></svg>',
  pulse:
    '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l2.5-6 4 12 2.5-6H21"/></svg>',
  stOk: '<svg viewBox="0 0 22 22" width="22" height="22"><circle class="st-ok" cx="11" cy="11" r="11"/><path d="m6.6 11.3 3 3 5.9-6.3" fill="none" stroke="#fff" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  stBad: '<svg viewBox="0 0 22 22" width="22" height="22"><circle class="st-bad" cx="11" cy="11" r="11"/><path d="m7.5 7.5 7 7m0-7-7 7" fill="none" stroke="#fff" stroke-width="2.1" stroke-linecap="round"/></svg>',
  stWarn: '<svg viewBox="0 0 22 22" width="22" height="22"><circle class="st-warn" cx="11" cy="11" r="11"/><path d="M11 6v6.4" fill="none" stroke="#fff" stroke-width="2.3" stroke-linecap="round"/><circle cx="11" cy="15.8" r="1.4" fill="#fff"/></svg>',
  stIdle: '<svg viewBox="0 0 22 22" width="22" height="22"><circle class="st-idle" cx="11" cy="11" r="11"/><path d="M7 11h8" fill="none" stroke="#fff" stroke-width="2.1" stroke-linecap="round"/></svg>',
  arrowCircle:
    '<svg viewBox="0 0 30 30" width="30" height="30"><circle class="go" cx="15" cy="15" r="15"/><path d="M10 15h10m-4-4.5 4.5 4.5-4.5 4.5" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
};

function appBody() {
  return `<div id="app" class="app">
  <section id="listPane" class="pane list-pane" aria-label="信息">
    <header class="topbar">
      <div class="edge"></div>
      <div class="bar">
        <span class="bar-side"></span>
        <h2 class="bar-title" aria-hidden="true">信息</h2>
        <span class="bar-side"><button id="moreBtn" class="glass glass-btn" type="button" aria-label="更多" aria-haspopup="menu">${ICONS.ellipsis}</button></span>
      </div>
    </header>
    <div id="listScroll" class="scroller list-scroll">
      <h1 class="large-title">信息</h1>
      <div class="search" role="search">
        <label class="search-field">${ICONS.search}<input id="search" type="search" placeholder="搜索" autocomplete="off" autocorrect="off" spellcheck="false" enterkeyhint="search" aria-label="搜索信息"><button id="searchClear" class="search-clear" type="button" aria-label="清除" hidden>${ICONS.xmarkFill}</button></label>
        <button id="searchCancel" class="search-cancel" type="button">取消</button>
      </div>
      <div id="codeCard" class="code-card glass" hidden>
        <button id="codeOpen" class="code-head" type="button"><span class="code-app">${ICONS.appIcon}</span><span id="codeFrom" class="code-from"></span><span id="codeAgo" class="code-ago"></span></button>
        <div class="code-row">
          <button id="codeValue" class="code-value" type="button"></button>
          <button id="codeCopy" class="code-copy" type="button">拷贝</button>
        </div>
      </div>
      <ul id="threadList" class="threads" aria-label="对话"></ul>
      <ul id="results" class="threads results" aria-label="搜索结果"></ul>
      <div id="listEmpty" class="empty" hidden>
        <span class="empty-icon">${ICONS.emptyBubbles}</span>
        <div class="empty-title">暂无信息</div>
        <div id="emptyText" class="empty-text"></div>
        <button id="emptyDiag" class="empty-btn" type="button">检查连接</button>
      </div>
    </div>
  </section>
  <section id="threadPane" class="pane thread-pane is-empty" aria-label="对话">
    <header class="topbar thread-top">
      <div class="edge"></div>
      <div class="bar">
        <button id="backBtn" class="glass glass-btn back" type="button" aria-label="返回">${ICONS.chevronLeft}<span id="backBadge" class="back-badge" hidden></span></button>
        <button id="peerBtn" class="peer" type="button"><span id="peerAvatar" class="avatar lg"></span><span class="peer-name glass"><span id="peerName"></span>${ICONS.chevronTiny}</span></button>
        <span class="bar-side"></span>
      </div>
    </header>
    <div id="threadScroll" class="scroller thread-scroll">
      <div id="bubbles" class="bubbles"></div>
    </div>
    <div id="quick" class="quick" hidden>
      <button id="quickBtn" class="quick-btn glass" type="button"><span class="quick-from">来自“信息”</span><span id="quickCode" class="quick-code"></span></button>
    </div>
    <div class="thread-empty">未选择对话</div>
  </section>
</div>
<div id="island" class="island" role="status" aria-live="polite"><span class="island-icon">${ICONS.check}</span><span class="island-text"><span id="islandTitle" class="island-title"></span><span id="islandDetail" class="island-detail"></span></span></div>
<div id="safeProbe" class="safe-probe" aria-hidden="true"></div>`;
}

/* ------------------------------------------------------------------ */
/* Styles                                                              */
/* ------------------------------------------------------------------ */

const TAIL_MASK =
  "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 21 20'%3E%3Cpath d='M6 0v10.5C6 15 4 18 .5 19.6c-.3.15-.2.4.1.4 4.9.2 8.6-1.4 11-3.6 2 2.4 5.4 3.6 9.4 3.6V0Z'/%3E%3C/svg%3E\")";

const BASE_CSS = String.raw`
:root{
  color-scheme:light dark;
  --bg:#fff;--bg-2:#f2f2f7;--label:#000;--label-2:rgba(60,60,67,.6);--label-3:rgba(60,60,67,.3);
  --sep:rgba(60,60,67,.29);--fill:rgba(118,118,128,.12);--press:#d1d1d6;--hover:rgba(0,0,0,.035);
  --blue:#007aff;--red:#ff3b30;--green:#34c759;--orange:#ff9500;
  --page:#f2f2f7;--cell:#fff;
  --bubble:#e9e9eb;--bubble-hl:#d1d1d6;
  --avatar:linear-gradient(180deg,#a5abb9,#858994);
  --glass:rgba(255,255,255,.6);--glass-solid:#f7f7f8;--glass-rim:rgba(255,255,255,.95);--glass-line:rgba(0,0,0,.07);
  --glass-shadow:0 6px 24px rgba(0,0,0,.08),0 1px 2px rgba(0,0,0,.05);
  --menu-bg:rgba(250,250,251,.8);--menu-hl:rgba(0,0,0,.07);--menu-dim:rgba(0,0,0,.1);--focus:rgba(0,0,0,.55);
  --sheet-bg:rgba(250,250,251,.88);--sheet-hl:rgba(0,0,0,.08);
  --scrim:rgba(0,0,0,.25);--edge:rgba(255,255,255,.92);
  --ease:cubic-bezier(.23,1,.32,1);
  --font:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC","Hiragino Sans GB","Microsoft YaHei","Noto Sans CJK SC","WenQuanYi Zen Hei","Helvetica Neue",Arial,sans-serif;
  --font-round:ui-rounded,"SF Pro Rounded",-apple-system,BlinkMacSystemFont,"PingFang SC","WenQuanYi Zen Hei",sans-serif;
}
@media (prefers-color-scheme:dark){:root{
  --bg:#000;--bg-2:#1c1c1e;--label:#fff;--label-2:rgba(235,235,245,.6);--label-3:rgba(235,235,245,.3);
  --sep:rgba(84,84,88,.6);--fill:rgba(118,118,128,.24);--press:#2c2c2e;--hover:rgba(255,255,255,.05);
  --blue:#0a84ff;--red:#ff453a;--green:#30d158;--orange:#ff9f0a;
  --page:#1c1c1e;--cell:#2c2c2e;
  --bubble:#262628;--bubble-hl:#3a3a3c;
  --avatar:linear-gradient(180deg,#6e6e73,#48484a);
  --glass:rgba(40,40,43,.55);--glass-solid:#1c1c1e;--glass-rim:rgba(255,255,255,.16);--glass-line:rgba(255,255,255,.08);
  --glass-shadow:0 6px 24px rgba(0,0,0,.5);
  --menu-bg:rgba(37,37,39,.82);--menu-hl:rgba(255,255,255,.1);--menu-dim:rgba(0,0,0,.4);--focus:rgba(255,255,255,.65);
  --sheet-bg:rgba(37,37,39,.88);--sheet-hl:rgba(255,255,255,.1);
  --scrim:rgba(0,0,0,.5);--edge:rgba(0,0,0,.9);
}}
html{font-size:17px;-webkit-text-size-adjust:100%;text-size-adjust:100%}
@supports (font:-apple-system-body){html{font:-apple-system-body}}
*,*::before,*::after{box-sizing:border-box}
html,body{height:100%;margin:0;background:var(--bg)}
body{font-family:var(--font);font-size:1rem;line-height:1.294;letter-spacing:-.024em;color:var(--label);-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;-webkit-tap-highlight-color:transparent;overflow:hidden}
button{font:inherit;color:inherit;letter-spacing:inherit;background:none;border:0;margin:0;padding:0;cursor:pointer;touch-action:manipulation;-webkit-user-select:none;user-select:none}
button:disabled{cursor:default}
a{touch-action:manipulation}
[hidden]{display:none!important}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
svg{display:block}
.glass{background:var(--glass);-webkit-backdrop-filter:blur(18px) saturate(180%);backdrop-filter:blur(18px) saturate(180%);box-shadow:inset 0 1px 0 var(--glass-rim),inset 0 0 0 .5px var(--glass-line),var(--glass-shadow)}
@media (prefers-reduced-transparency:reduce){.glass{background:var(--glass-solid);-webkit-backdrop-filter:none;backdrop-filter:none}}
@media (prefers-contrast:more){.glass{background:var(--glass-solid);box-shadow:inset 0 0 0 1px var(--label-3)}}
.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0;padding:0;margin:-1px}
`;

const APP_CSS = String.raw`
.app{position:fixed;inset:0;overflow:hidden;background:var(--bg)}
.pane{position:absolute;inset:0;display:flex;flex-direction:column;background:var(--bg);overflow:hidden}
.scroller{flex:1;min-height:0;overflow-x:hidden;overflow-y:auto;overscroll-behavior-y:contain;-webkit-overflow-scrolling:touch}
.list-pane::after{content:"";position:absolute;inset:0;z-index:10;background:#000;opacity:var(--dim,0);pointer-events:none}

/* 顶部浮动控件 + 滚动边缘效果 */
.topbar{position:absolute;z-index:4;top:0;left:0;right:0;padding-top:env(safe-area-inset-top);pointer-events:none}
.edge{position:absolute;left:0;right:0;top:0;bottom:-24px;background:linear-gradient(var(--edge),var(--edge) 40%,transparent);-webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px);-webkit-mask-image:linear-gradient(#000 45%,transparent);mask-image:linear-gradient(#000 45%,transparent);opacity:0;transition:opacity .25s ease}
.pane.scrolled .edge{opacity:1}
.bar{position:relative;height:56px;display:flex;align-items:center;justify-content:space-between;padding:0 16px}
.bar-side{display:flex;min-width:44px;justify-content:flex-end}
.bar-title{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);margin:0;font-size:1rem;font-weight:600;opacity:0;transition:opacity .2s ease}
.list-pane.collapsed .bar-title{opacity:1}
.glass-btn{pointer-events:auto;position:relative;min-width:44px;height:44px;border-radius:22px;display:inline-flex;align-items:center;justify-content:center;color:var(--label);transition:transform .3s var(--ease)}
.glass-btn:active{transform:scale(1.08)}

/* 列表 */
.list-scroll{padding-top:calc(env(safe-area-inset-top) + 56px);padding-bottom:calc(env(safe-area-inset-bottom) + 24px)}
.large-title{margin:0 16px 8px;font-size:2rem;line-height:1.206;font-weight:700;letter-spacing:.011em}
.search{display:flex;align-items:center;margin:0 16px 12px}
.search-field{flex:1;min-width:0;display:flex;align-items:center;min-height:38px;border-radius:999px;background:var(--fill);padding:0 6px 0 12px;color:var(--label-2);cursor:text}
.search-field input{flex:1;min-width:0;height:38px;border:0;outline:0;background:none;margin:0;padding:0 6px;font:inherit;font-size:1rem;letter-spacing:-.024em;color:var(--label);-webkit-appearance:none;appearance:none;border-radius:0}
.search-field input::placeholder{color:var(--label-2);opacity:1}
.search-field input::-webkit-search-cancel-button,.search-field input::-webkit-search-decoration{-webkit-appearance:none;display:none}
.search-clear{display:grid;place-items:center;width:30px;height:30px;color:var(--label-3)}
.search-clear .xm{stroke:var(--bg)}
.search-cancel{color:var(--blue);white-space:nowrap;max-width:0;opacity:0;overflow:hidden;padding-left:0;transition:max-width .35s var(--ease),opacity .2s ease,padding .35s var(--ease)}
.list-pane.searching .search-cancel{max-width:4em;opacity:1;padding-left:14px}

.threads{list-style:none;margin:0;padding:0}
.row{position:relative;overflow:hidden}
.row-main{position:relative;z-index:1;display:flex;align-items:center;min-height:76px;padding-left:4px;background:var(--bg);touch-action:pan-y pinch-zoom;-webkit-user-select:none;user-select:none;-webkit-touch-callout:none;cursor:default;outline-offset:-2px;transition:background-color .35s ease}
.row-main.pressed{background:var(--press);transition:none}
.dot{flex:none;width:10px;height:10px;margin:0 5px;border-radius:50%}
.row.unread .dot{background:var(--blue)}
.avatar{flex:none;position:relative;width:40px;height:40px;border-radius:50%;overflow:hidden;background:var(--avatar);color:#fff;display:grid;place-items:center;font:600 1.059rem/1 var(--font-round);letter-spacing:0;-webkit-user-select:none;user-select:none}
.avatar svg{width:100%;height:100%}
.row-text{flex:1;min-width:0;align-self:stretch;margin-left:12px;padding:10px 16px 11px 0;display:flex;flex-direction:column;justify-content:center;border-bottom:.5px solid var(--sep)}
.row:last-child .row-text{border-bottom-color:transparent}
.row-top{display:flex;align-items:center;gap:6px}
.name{flex:1;min-width:0;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.time{flex:none;font-size:.882rem;letter-spacing:-.016em;color:var(--label-2);font-variant-numeric:tabular-nums}
.chev{flex:none;color:var(--label-3);margin-left:2px}
.preview{margin-top:1px;font-size:.882rem;line-height:1.333;letter-spacing:-.016em;color:var(--label-2);display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;overflow-wrap:anywhere}
.preview mark,.name mark{background:none;color:var(--label);font-weight:600}
.swipe-bg{position:absolute;inset:0;visibility:hidden}
.swipe-bg.trailing{background:var(--red)}
.swipe-bg.leading{background:var(--blue)}
.swipe-btn{position:absolute;top:0;bottom:0;width:74px;display:grid;place-items:center;color:#fff}
.trailing .swipe-btn{right:0}
.leading .swipe-btn{left:0}
.swipe-btn.ease{transition:transform .25s var(--ease)}
.section-head{padding:14px 16px 4px;font-size:1.176rem;font-weight:700;letter-spacing:.019em}
.no-results{padding:16vh 32px 0;text-align:center;color:var(--label-2)}
.no-results b{display:block;font-size:1.294rem;color:var(--label);margin-bottom:6px;letter-spacing:.016em}
.list-pane.has-query #threadList,.list-pane.has-query #codeCard,.list-pane.has-query #listEmpty{display:none!important}
.list-pane:not(.has-query) #results{display:none}

/* 验证码卡片 */
.code-card{margin:2px 16px 14px;padding:12px 14px 14px 16px;border-radius:26px}
.code-head{display:flex;align-items:center;gap:8px;width:100%;text-align:left;min-height:28px}
.code-app .app{fill:var(--green)}
.code-from{flex:1;min-width:0;font-size:.882rem;font-weight:600;letter-spacing:-.016em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.code-ago{flex:none;font-size:.765rem;color:var(--label-2);letter-spacing:-.006em}
.code-row{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:4px;padding-left:28px}
.code-value{font-size:2rem;line-height:1.2;font-weight:600;letter-spacing:.1em;font-variant-numeric:tabular-nums;text-align:left;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;transition:transform .2s var(--ease)}
.code-value:active{transform:scale(.96)}
.code-copy{flex:none;min-height:36px;padding:0 18px;border-radius:999px;background:var(--blue);color:#fff;font-size:.882rem;font-weight:600;letter-spacing:-.016em;transition:transform .2s var(--ease)}
.code-copy:active{transform:scale(.96)}

/* 空状态 */
.empty{display:flex;flex-direction:column;align-items:center;text-align:center;padding:16vh 32px 0;color:var(--label-2)}
.empty-icon{color:var(--label-3);margin-bottom:14px}
.empty-title{font-size:1.294rem;font-weight:700;color:var(--label);letter-spacing:.016em}
.empty-text{margin-top:6px;font-size:.882rem;line-height:1.333;max-width:20em;letter-spacing:-.016em;overflow-wrap:anywhere}

/* 对话 */
.app:not(.split) .thread-pane{will-change:transform;box-shadow:-10px 0 30px rgba(0,0,0,.1)}
.thread-top .bar{height:88px;align-items:flex-start;padding-top:6px}
.back{gap:3px;padding:0 13px 0 15px;margin-top:6px}
.back-badge{font-size:.882rem;font-weight:600;letter-spacing:-.016em;font-variant-numeric:tabular-nums}
.peer{pointer-events:auto;position:absolute;left:50%;top:6px;transform:translateX(-50%);display:flex;flex-direction:column;align-items:center;max-width:calc(100% - 160px);transition:transform .25s var(--ease)}
.peer:active{transform:translateX(-50%) scale(.96)}
.avatar.lg{width:52px;height:52px;font-size:1.294rem;box-shadow:0 2px 10px rgba(0,0,0,.12)}
.peer-name{position:relative;margin-top:-6px;display:inline-flex;align-items:center;gap:4px;max-width:100%;padding:4px 9px 4px 11px;border-radius:999px;font-size:.765rem;line-height:1.25;font-weight:600;letter-spacing:-.006em}
.peer-name > span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.peer-name svg{flex:none;color:var(--label-3)}
.thread-scroll{padding-top:calc(env(safe-area-inset-top) + 98px);padding-bottom:calc(env(safe-area-inset-bottom) + 20px);touch-action:pan-y pinch-zoom}
.thread-pane.has-quick .thread-scroll{padding-bottom:calc(env(safe-area-inset-bottom) + 92px)}
.bubbles{position:relative;padding:0 16px;--reveal:0px;--reveal-o:0}
.thread-intro{text-align:center;font-size:.706rem;line-height:1.333;font-weight:500;color:var(--label-2);margin:2px 0 0}
.ts{text-align:center;font-size:.706rem;line-height:1.333;color:var(--label-2);margin:14px 0 6px;letter-spacing:0}
.ts b{font-weight:600}
.thread-intro + .ts{margin-top:0}
.msg{position:relative;display:flex;margin-top:2px}
.msg.end + .msg{margin-top:10px}
.bubble{position:relative;isolation:isolate;max-width:min(75%,34rem);padding:.412em .706em;border-radius:18px;background:var(--bubble);color:var(--label);white-space:pre-wrap;overflow-wrap:anywhere;-webkit-touch-callout:none;-webkit-user-select:none;user-select:none;transition:transform .3s var(--ease)}
.bubble.tail::before{content:"";position:absolute;z-index:-1;left:-6px;bottom:0;width:21px;height:20px;background:inherit;-webkit-mask:${TAIL_MASK} 0 0/100% 100% no-repeat;mask:${TAIL_MASK} 0 0/100% 100% no-repeat}
.bubble.pressing{transform:scale(.96)}
.bubble.flash{animation:flash 1.6s ease}
@keyframes flash{15%,55%{background-color:var(--bubble-hl)}}
.msg.in .bubble{animation:msg-in .5s var(--ease) both;transform-origin:0 100%}
@keyframes msg-in{from{opacity:0;transform:translateY(10px) scale(.9)}}
.msg-time{position:absolute;right:-16px;top:50%;width:76px;padding-right:16px;text-align:right;font-size:.706rem;letter-spacing:0;color:var(--label-2);font-variant-numeric:tabular-nums;white-space:nowrap;transform:translate(calc(76px + var(--reveal)),-50%);opacity:var(--reveal-o);pointer-events:none}
.dd{color:inherit;text-decoration:underline;text-decoration-thickness:1px;text-underline-offset:.15em}
.dd-code{cursor:pointer;border-radius:4px;-webkit-user-select:none;user-select:none}
.dd-code:active{background:var(--bubble-hl)}
.menu-source{visibility:hidden}
.quick{position:absolute;z-index:3;left:0;right:0;bottom:calc(env(safe-area-inset-bottom) + 14px);display:flex;justify-content:center;pointer-events:none}
.quick-btn{pointer-events:auto;display:flex;flex-direction:column;align-items:center;min-width:160px;padding:7px 30px 8px;border-radius:24px;transition:transform .25s var(--ease)}
.quick-btn:active{transform:scale(.96)}
.quick-from{font-size:.706rem;color:var(--label-2);letter-spacing:0}
.quick-code{font-size:1.176rem;line-height:1.3;font-weight:600;letter-spacing:.08em;font-variant-numeric:tabular-nums}
.thread-empty{position:absolute;inset:0;display:none;align-items:center;justify-content:center;color:var(--label-2);font-size:.882rem}
.thread-pane.is-empty .thread-top,.thread-pane.is-empty .thread-scroll,.thread-pane.is-empty .quick{visibility:hidden}
.app.split .thread-pane.is-empty .thread-empty{display:flex}

/* iPad / 桌面：左右分栏 */
.app.split .list-pane{right:auto;width:min(380px,40vw);border-right:.5px solid var(--sep);transform:none!important;visibility:visible!important}
.app.split .list-pane::after{display:none}
.app.split .thread-pane{left:min(380px,40vw);transform:none!important;visibility:visible!important}
.app.split .back{visibility:hidden}
.app.split .threads{padding:0 8px}
.app.split .row-main{border-radius:14px}
.app.split .row.selected .row-main{background:var(--blue);color:#fff}
.app.split .row.selected .time,.app.split .row.selected .preview,.app.split .row.selected .chev{color:rgba(255,255,255,.82)}
.app.split .row.selected.unread .dot{background:#fff}
.app.split .row.selected .row-text{border-bottom-color:transparent}

/* 上下文菜单 */
.menu-layer{position:fixed;inset:0;z-index:50}
.menu-backdrop{position:absolute;inset:0}
.menu-layer.lift .menu-backdrop{background:transparent;-webkit-backdrop-filter:blur(0px);backdrop-filter:blur(0px);transition:background-color .3s ease,-webkit-backdrop-filter .3s ease,backdrop-filter .3s ease}
.menu-layer.lift.open .menu-backdrop{background:var(--menu-dim);-webkit-backdrop-filter:blur(14px);backdrop-filter:blur(14px)}
.menu-preview{position:fixed;margin:0;z-index:1;transform-origin:0 50%;filter:drop-shadow(0 6px 18px rgba(0,0,0,.16))}
.menu{position:fixed;z-index:2;min-width:220px;max-width:280px;padding:6px;border-radius:26px;background:var(--menu-bg);opacity:0}
.menu-item{display:flex;align-items:center;gap:12px;width:100%;min-height:46px;padding:0 16px 0 12px;border-radius:20px;text-align:left;color:var(--label)}
.menu-item svg{flex:none;width:22px;height:22px}
.menu-item.danger{color:var(--red)}
.menu-item:disabled{color:var(--label-3)}
.menu-item:active,.menu-item:focus-visible{background:var(--menu-hl);outline:0}
.menu-layer.closing{pointer-events:none}
.menu-layer.closing .menu{opacity:0!important;transform:scale(.92)!important;transition:opacity .18s ease,transform .18s ease}
.menu-layer.closing .menu-preview{transform:none!important;transition:transform .2s var(--ease)}

/* 操作表 */
.sheet-layer{position:fixed;inset:0;z-index:55;display:flex;align-items:flex-end;justify-content:center}
.sheet-scrim{position:absolute;inset:0;background:transparent;transition:background-color .3s ease}
.sheet-layer.open .sheet-scrim{background:var(--scrim)}
.sheet{position:relative;width:min(calc(100% - 16px),420px);margin-bottom:calc(env(safe-area-inset-bottom) + 8px);display:flex;flex-direction:column;gap:8px}
.sheet-group,.sheet-cancel{border-radius:26px;overflow:hidden;background:var(--sheet-bg);-webkit-backdrop-filter:blur(30px) saturate(180%);backdrop-filter:blur(30px) saturate(180%)}
.sheet-head{padding:14px 20px 13px;text-align:center;border-bottom:.5px solid var(--sep)}
.sheet-title{font-size:.765rem;font-weight:600;color:var(--label-2);letter-spacing:-.006em}
.sheet-msg{font-size:.765rem;line-height:1.38;color:var(--label-2);letter-spacing:-.006em;overflow-wrap:anywhere}
.sheet-title + .sheet-msg{margin-top:2px}
.sheet-btn{display:block;width:100%;min-height:57px;padding:8px 16px;font-size:1.176rem;letter-spacing:.019em;color:var(--blue);text-align:center}
.sheet-btn + .sheet-btn{border-top:.5px solid var(--sep)}
.sheet-btn.danger{color:var(--red)}
.sheet-cancel{font-weight:600}
.sheet-btn:active{background:var(--sheet-hl)}

/* 连接诊断（iOS 页面式表单） */
.empty-btn{margin-top:18px;min-height:44px;padding:0 18px;color:var(--blue);font-size:.882rem;font-weight:600;letter-spacing:-.016em}
.page-layer{position:fixed;inset:0;z-index:52}
.page-scrim{position:absolute;inset:0;background:transparent;transition:background-color .3s ease}
.page-layer.open .page-scrim{background:var(--scrim)}
.page-sheet{position:absolute;left:0;right:0;bottom:0;top:calc(env(safe-area-inset-top) + 12px);max-width:640px;margin:0 auto;display:flex;flex-direction:column;background:var(--page);border-radius:26px 26px 0 0;box-shadow:0 -8px 40px rgba(0,0,0,.18);overflow:hidden}
.page-head{flex:none;position:relative;display:flex;align-items:center;justify-content:center;height:58px;touch-action:none;cursor:grab}
.page-grabber{position:absolute;top:6px;left:50%;width:36px;height:5px;margin-left:-18px;border-radius:3px;background:var(--label-3)}
.page-title{margin:0;font-size:1rem;font-weight:600}
.page-done{position:absolute;right:8px;top:7px;min-height:44px;padding:0 12px;color:var(--blue);font-weight:600}
.page-body{flex:1;min-height:0;overflow-y:auto;overscroll-behavior:contain;padding-bottom:calc(env(safe-area-inset-bottom) + 32px)}
.g-head{margin:22px 32px 7px;font-size:.765rem;color:var(--label-2);letter-spacing:-.006em}
.g{margin:0 16px;background:var(--cell);border-radius:22px;overflow:hidden}
.g-row{position:relative;display:flex;align-items:center;gap:12px;width:100%;min-height:46px;padding:11px 16px;text-align:left}
.g-row + .g-row::before{content:"";position:absolute;top:0;left:16px;right:0;border-top:.5px solid var(--sep)}
.g-row svg{flex:none}
.g-main{flex:1;min-width:0;overflow-wrap:anywhere}
.g-sub{display:block;margin-top:2px;font-size:.765rem;line-height:1.38;color:var(--label-2);letter-spacing:-.006em;overflow-wrap:anywhere}
.g-value{flex:none;max-width:60%;color:var(--label-2);text-align:right;overflow-wrap:anywhere}
.g-mono{font-family:ui-monospace,Menlo,monospace;font-size:.8rem;letter-spacing:0}
.g-foot{margin:7px 32px 0;font-size:.765rem;line-height:1.38;color:var(--label-2);letter-spacing:-.006em}
.g-action{color:var(--blue)}
.g-action:disabled{color:var(--label-3)}
button.g-row:active{background:var(--menu-hl)}
.g-code{flex:none;min-width:2.6em;padding:2px 6px;border-radius:6px;background:var(--fill);font:600 .765rem/1.3 ui-monospace,Menlo,monospace;text-align:center;color:var(--label-2)}
.diag-summary{display:flex;gap:12px;align-items:flex-start;margin:6px 16px 0;padding:14px 16px;border-radius:22px;background:var(--cell)}
.diag-summary b{display:block;font-weight:600}
.st-ok{fill:var(--green)}.st-bad{fill:var(--red)}.st-warn{fill:var(--orange)}.st-idle{fill:var(--label-3)}
.diag-loading{padding:40px 16px;text-align:center;color:var(--label-2);font-size:.882rem}

/* 灵动岛式提示 */
.island{position:fixed;z-index:60;left:50%;top:calc(env(safe-area-inset-top) + 10px);display:flex;align-items:center;gap:10px;min-width:150px;max-width:calc(100vw - 48px);padding:9px 20px 9px 10px;border-radius:999px;background:#000;color:#fff;box-shadow:0 10px 30px rgba(0,0,0,.25);opacity:0;transform:translate(-50%,-14px) scale(.6);pointer-events:none;transition:transform .5s cubic-bezier(.3,1.35,.5,1),opacity .2s ease}
.island.show{opacity:1;transform:translate(-50%,0) scale(1)}
.island .ok{fill:var(--green)}
.island-icon{flex:none}
.island-text{display:flex;flex-direction:column;min-width:0}
.island-title{font-size:.882rem;font-weight:600;letter-spacing:-.016em;white-space:nowrap}
.island-detail{font-size:.765rem;color:rgba(255,255,255,.62);font-variant-numeric:tabular-nums;letter-spacing:.02em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.island-detail:empty{display:none}
@media (prefers-color-scheme:dark){.island{box-shadow:0 0 0 .5px rgba(255,255,255,.18),0 10px 30px rgba(0,0,0,.6)}}
.safe-probe{position:fixed;visibility:hidden;pointer-events:none;padding:env(safe-area-inset-top) 0 env(safe-area-inset-bottom)}
.haptic{position:fixed;left:-100px;top:0;opacity:0;pointer-events:none}

@media (hover:hover) and (pointer:fine){
  .row-main:hover{background:var(--hover)}
  .row-main.pressed:hover{background:var(--press)}
  .menu-item:hover:not(:disabled){background:var(--menu-hl)}
  .sheet-btn:hover{background:var(--sheet-hl)}
  .bubble{-webkit-user-select:text;user-select:text}
}
@media (prefers-reduced-motion:reduce){
  .msg.in .bubble{animation:fade-in .2s ease both}
  @keyframes fade-in{from{opacity:0}}
  .island{transform:translate(-50%,0)!important;transition:opacity .2s ease}
  .bubble.pressing{transform:none}
  .search-cancel{transition:opacity .2s ease}
}
`;

const LOGIN_CSS = String.raw`
body{overflow:auto}
.login{min-height:100%;display:flex;align-items:center;justify-content:center;padding:calc(env(safe-area-inset-top) + 24px) 24px calc(env(safe-area-inset-bottom) + 64px)}
.login-card{width:100%;max-width:340px;display:flex;flex-direction:column;align-items:center;text-align:center}
.login-icon{width:76px;height:76px;border-radius:17px;box-shadow:0 6px 20px rgba(0,0,0,.12)}
.login-title{margin:18px 0 0;font-size:1.647rem;line-height:1.2;font-weight:700;letter-spacing:.013em}
.login-sub{margin:6px 0 26px;font-size:.882rem;color:var(--label-2);letter-spacing:-.016em}
.login-form{width:100%}
.login-field{display:flex;align-items:center;height:52px;padding:0 8px 0 20px;border-radius:999px}
.login-field input{flex:1;min-width:0;height:100%;border:0;outline:0;background:none;font:inherit;font-size:1rem;color:var(--label);letter-spacing:-.024em}
.login-field input::placeholder{color:var(--label-2)}
.login-go{flex:none;display:grid;place-items:center;width:44px;height:44px;transition:transform .2s var(--ease),opacity .2s ease}
.login-go .go{fill:var(--blue)}
.login-go:active{transform:scale(.92)}
.login-go:disabled{opacity:.4}
.login-msg{min-height:1.4em;margin:12px 0 0;font-size:.882rem;color:var(--red)}
.login-card.shake .login-field{animation:shake .5s cubic-bezier(.36,.07,.19,.97) both}
@keyframes shake{10%,90%{transform:translateX(-2px)}20%,80%{transform:translateX(5px)}30%,50%,70%{transform:translateX(-10px)}40%,60%{transform:translateX(10px)}}
@media (prefers-reduced-motion:reduce){.login-card.shake .login-field{animation:none}}
.setup-list{margin:0;padding:0;list-style:none;width:100%;text-align:left;font-size:.882rem;line-height:1.5}
.setup-list li{padding:12px 16px;border-radius:16px;background:var(--bg-2);margin-bottom:8px}
.setup-list code{font-family:ui-monospace,Menlo,monospace;font-size:.92em}
`;

const LOGIN_JS = String.raw`
(function () {
  'use strict';
  var form = document.getElementById('form');
  var input = document.getElementById('pw');
  var box = document.getElementById('box');
  var msg = document.getElementById('msg');
  var go = document.getElementById('go');
  var busy = false;
  function shake() { box.classList.remove('shake'); void box.offsetWidth; box.classList.add('shake'); }
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    if (busy || !input.value) return;
    busy = true; go.disabled = true; msg.textContent = '';
    fetch('/api/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'fetch' },
      body: JSON.stringify({ password: input.value })
    }).then(function (res) {
      if (res.ok) { location.replace('/' + location.hash); return; }
      msg.textContent = res.status === 429 ? '尝试次数过多，请 15 分钟后再试' : '密码不正确';
      shake(); input.select();
    }, function () {
      msg.textContent = '网络错误，请重试'; shake();
    }).then(function () { busy = false; go.disabled = false; });
  });
})();
`;

/* ------------------------------------------------------------------ */
/* Client app（纯字符串，不使用模板字符串插值）                         */
/* ------------------------------------------------------------------ */

const APP_JS = String.raw`
(function () {
'use strict';

var CFG = JSON.parse(document.getElementById('cfg').textContent || '{}');
var ICONS = CFG.icons || {};
var mqReduce = matchMedia('(prefers-reduced-motion: reduce)');
var mqSplit = matchMedia('(min-width: 900px)');
var standalone = navigator.standalone === true || matchMedia('(display-mode: standalone)').matches;
var CODE_TTL = 10 * 60 * 1000;
var QUICK_TTL = 15 * 60 * 1000;
var ACTION_W = 74;
var REVEAL_W = 76;
var POLL_MS = 4000;
function noop() {}

/* ---------- state ---------- */
var S = {
  loaded: false, version: -1, threads: [], latestCode: null, skew: 0,
  current: null, messages: [], hasMore: false, threadLoaded: false, loadingOlder: false, threadShown: false, pushed: false,
  query: '', resultsFor: null, results: [], searchSeq: 0
};

/* ---------- dom ---------- */
function $(id) { return document.getElementById(id); }
function el(tag, cls, text) {
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}
function icon(name, cls) {
  var s = el('span', cls || null);
  s.innerHTML = ICONS[name] || '';
  s.setAttribute('aria-hidden', 'true');
  return s;
}
var app = $('app'), listPane = $('listPane'), threadPane = $('threadPane');
var listScroll = $('listScroll'), threadScroll = $('threadScroll');
var listEl = $('threadList'), resultsEl = $('results'), emptyEl = $('listEmpty');
var searchInput = $('search'), searchClear = $('searchClear'), searchCancel = $('searchCancel');
var codeCard = $('codeCard'), bubblesEl = $('bubbles'), quickEl = $('quick');
var backBadge = $('backBadge'), peerAvatar = $('peerAvatar'), peerName = $('peerName');
var islandEl = $('island');

$('emptyText').textContent = CFG.inbox
  ? '转发到 ' + CFG.inbox + ' 的短信会显示在这里。'
  : '转发到收件邮箱的短信会显示在这里。';

/* ---------- formatting ---------- */
var clockFmt = new Intl.DateTimeFormat('zh-CN', { hour: 'numeric', minute: '2-digit', hour12: true });
var WEEK = ['星期日', '星期一', '星期二', '星期三', '星期四', '星期五', '星期六'];
var WEEK_SHORT = ['周日', '周一', '周二', '周三', '周四', '周五', '周六'];
function clock(ts) { return clockFmt.format(ts); }
function dayStart(ts) { var d = new Date(ts); d.setHours(0, 0, 0, 0); return d.getTime(); }
function daysAgo(ts) { return Math.round((dayStart(Date.now()) - dayStart(ts)) / 864e5); }
function listTime(ts) {
  var n = daysAgo(ts), d = new Date(ts);
  if (n <= 0) return clock(ts);
  if (n === 1) return '昨天';
  if (n < 7) return WEEK[d.getDay()];
  return d.getFullYear() + '/' + (d.getMonth() + 1) + '/' + d.getDate();
}
function sepDay(ts) {
  var n = daysAgo(ts), d = new Date(ts);
  if (n <= 0) return '今天';
  if (n === 1) return '昨天';
  if (n < 7) return WEEK[d.getDay()];
  if (d.getFullYear() === new Date().getFullYear()) return (d.getMonth() + 1) + '月' + d.getDate() + '日 ' + WEEK_SHORT[d.getDay()];
  return d.getFullYear() + '年' + (d.getMonth() + 1) + '月' + d.getDate() + '日';
}
function serverNow() { return Date.now() + S.skew; }
function ago(ms) { var m = Math.floor(ms / 60000); return m < 1 ? '刚刚' : m + ' 分钟前'; }

function signature(body) {
  var m = /^\s*【([^】\n]{1,20})】/.exec(body || '') || /【([^】\n]{1,20})】\s*$/.exec(body || '');
  return m ? m[1].trim() : '';
}
function prettyNumber(s) {
  var m = /^\+86(1\d{2})(\d{4})(\d{4})$/.exec(s);
  if (m) return '+86 ' + m[1] + ' ' + m[2] + ' ' + m[3];
  m = /^\+1(\d{3})(\d{3})(\d{4})$/.exec(s);
  if (m) return '+1 (' + m[1] + ') ' + m[2] + '-' + m[3];
  return s;
}
function isNumberish(s) { return /^\+?[\d\s()-]+$/.test(s); }
function nameFor(sender, body) { return signature(body) || prettyNumber(sender); }
function firstChar(s) { return Array.from(s)[0].toUpperCase(); }
function setAvatar(node, sender, body) {
  var sig = signature(body);
  var text = sig ? firstChar(sig) : isNumberish(sender) ? '' : firstChar(sender);
  if (node.dataset.k === (text || '#')) return;
  node.dataset.k = text || '#';
  if (text) node.textContent = text;
  else node.innerHTML = ICONS.person;
}
function threadFor(sender) {
  for (var i = 0; i < S.threads.length; i++) if (S.threads[i].sender === sender) return S.threads[i];
  return null;
}
function msgById(id) {
  for (var i = 0; i < S.messages.length; i++) if (S.messages[i].id === id) return S.messages[i];
  return null;
}
function cmpMsg(a, b) { return a.ts - b.ts || a.id - b.id; }
function isSplit() { return mqSplit.matches; }
function clamp(v, a, b) { return Math.max(a, Math.min(b, v)); }
function safeInsets() {
  var cs = getComputedStyle($('safeProbe'));
  return { top: parseFloat(cs.paddingTop) || 0, bottom: parseFloat(cs.paddingBottom) || 0 };
}

/* ---------- physics: springs, projection, rubber band ---------- */
// Apple 的参数化：response（秒）+ dampingRatio。可随时打断，从当前位置和速度继续。
function Spring(apply, init, eps) {
  this.apply = apply; this.x = init || 0; this.v = 0; this.target = this.x;
  this.k = 0; this.c = 0; this.raf = 0; this.last = 0; this.done = null; this.eps = eps || 0.25;
  var self = this;
  this.tick = function (t) { self.step(t); };
}
Spring.prototype.set = function (x) { this.stop(); this.x = this.target = x; this.v = 0; this.apply(x); };
Spring.prototype.stop = function () { if (this.raf) cancelAnimationFrame(this.raf); this.raf = 0; this.done = null; };
Spring.prototype.to = function (target, o, done) {
  o = o || {};
  var response = o.response || 0.4, damping = o.damping == null ? 1 : o.damping;
  this.target = target;
  if (o.velocity != null) this.v = o.velocity;
  this.k = Math.pow(2 * Math.PI / response, 2);
  this.c = 4 * Math.PI * damping / response;
  this.done = done || null;
  if (mqReduce.matches) {
    var d = this.done; this.stop(); this.x = target; this.v = 0; this.apply(target); if (d) d();
    return;
  }
  if (!this.raf) { this.last = performance.now(); this.raf = requestAnimationFrame(this.tick); }
};
Spring.prototype.step = function (t) {
  var dt = Math.min(0.05, Math.max(0.001, (t - this.last) / 1000));
  this.last = t;
  var n = Math.max(1, Math.ceil(dt / 0.004)), h = dt / n;
  for (var i = 0; i < n; i++) {
    var a = -this.k * (this.x - this.target) - this.c * this.v;
    this.v += a * h; this.x += this.v * h;
  }
  if (Math.abs(this.x - this.target) < this.eps && Math.abs(this.v) < this.eps * 20) {
    this.x = this.target; this.v = 0; this.raf = 0; this.apply(this.x);
    var d = this.done; this.done = null; if (d) d();
    return;
  }
  this.apply(this.x);
  this.raf = requestAnimationFrame(this.tick);
};
// 动量投射（与 UIScrollView 减速一致）
function project(v) { return (v / 1000) * 0.998 / (1 - 0.998); }
function rubber(over, dim) { return (over * dim * 0.55) / (dim + 0.55 * Math.abs(over)); }
function Tracker() { this.p = []; }
Tracker.prototype.add = function (x, t) { this.p.push({ x: x, t: t }); if (this.p.length > 8) this.p.shift(); };
Tracker.prototype.velocity = function () {
  var p = this.p; if (p.length < 2) return 0;
  var last = p[p.length - 1], first = last;
  for (var i = p.length - 2; i >= 0; i--) { if (last.t - p[i].t > 100) break; first = p[i]; }
  var dt = (last.t - first.t) / 1000;
  return dt > 0 ? (last.x - first.x) / dt : 0;
};

/* ---------- haptics ---------- */
var hapticLabel = (function () {
  try {
    var label = el('label', 'haptic'), input = el('input');
    input.type = 'checkbox'; input.setAttribute('switch', ''); input.tabIndex = -1;
    label.setAttribute('aria-hidden', 'true'); label.appendChild(input); document.body.appendChild(label);
    return label;
  } catch (e) { return null; }
})();
function haptic() {
  if (navigator.vibrate) { try { navigator.vibrate(10); } catch (e) {} return; }
  if (hapticLabel && /iPhone|iPad/.test(navigator.userAgent)) hapticLabel.click(); // iOS 18+：开关控件会触发系统触感
}

/* ---------- api ---------- */
function api(path, body) {
  var opts = { credentials: 'same-origin', headers: { 'X-Requested-With': 'fetch' } };
  if (body !== undefined) {
    opts.method = 'POST';
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  return fetch(path, opts).then(function (res) {
    if (res.status === 401) { location.reload(); throw new Error('unauthorized'); }
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return res.json();
  });
}

/* ---------- island toast ---------- */
var islandTimer = 0;
// 失败时用红色图标，免得「导入失败」配着绿色对勾
function toast(title, detail, failed) {
  islandEl.querySelector('.island-icon').innerHTML = failed ? ICONS.stBad : ICONS.check;
  $('islandTitle').textContent = title;
  $('islandDetail').textContent = detail || '';
  islandEl.classList.remove('show');
  void islandEl.offsetWidth;
  islandEl.classList.add('show');
  clearTimeout(islandTimer);
  islandTimer = setTimeout(function () { islandEl.classList.remove('show'); }, 1700);
}
function fallbackCopy(text) {
  var ta = el('textarea');
  ta.value = text; ta.setAttribute('readonly', '');
  ta.style.position = 'fixed'; ta.style.opacity = '0'; ta.style.top = '0';
  document.body.appendChild(ta);
  ta.select(); ta.setSelectionRange(0, text.length);
  var ok = false;
  try { ok = document.execCommand('copy'); } catch (e) {}
  ta.remove();
  return ok;
}
function copyText(text, title) {
  function done() { haptic(); toast(title || '已拷贝', text.length > 24 ? text.slice(0, 24) + '…' : text); }
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done, function () { if (fallbackCopy(text)) done(); else toast('无法拷贝', '', true); });
  } else if (fallbackCopy(text)) done();
  else toast('无法拷贝', '', true);
}

/* ---------- conversation list ---------- */
var rowMap = new Map();
var openRow = null;
var swallowClickUntil = 0;

function renderThreads() {
  var prev = null, seen = new Set();
  S.threads.forEach(function (t) {
    var li = rowMap.get(t.sender);
    if (!li) { li = createRow(); rowMap.set(t.sender, li); }
    updateRow(li, t);
    seen.add(t.sender);
    var want = prev ? prev.nextSibling : listEl.firstChild;
    if (li !== want) listEl.insertBefore(li, want);
    prev = li;
  });
  rowMap.forEach(function (li, key) {
    if (!seen.has(key)) { if (openRow === li) openRow = null; li.remove(); rowMap.delete(key); }
  });
  emptyEl.hidden = !S.loaded || S.threads.length > 0;
  updateBadges();
}

function createRow() {
  var li = el('li', 'row');
  var lead = el('div', 'swipe-bg leading'), leadBtn = el('button', 'swipe-btn');
  var trail = el('div', 'swipe-bg trailing'), trailBtn = el('button', 'swipe-btn');
  leadBtn.type = trailBtn.type = 'button';
  leadBtn.tabIndex = trailBtn.tabIndex = -1;
  trailBtn.setAttribute('aria-label', '删除');
  trailBtn.appendChild(icon('trashFill'));
  lead.appendChild(leadBtn); trail.appendChild(trailBtn);
  var main = el('div', 'row-main');
  main.tabIndex = 0; main.setAttribute('role', 'button');
  var dot = el('span', 'dot'), av = el('span', 'avatar'), text = el('div', 'row-text');
  var top = el('div', 'row-top'), name = el('span', 'name'), time = el('span', 'time'), preview = el('div', 'preview');
  top.appendChild(name); top.appendChild(time); top.appendChild(icon('chevronSmall', 'chev'));
  text.appendChild(top); text.appendChild(preview);
  main.appendChild(dot); main.appendChild(av); main.appendChild(text);
  li.appendChild(lead); li.appendChild(trail); li.appendChild(main);
  li._ = { main: main, lead: lead, trail: trail, leadBtn: leadBtn, trailBtn: trailBtn, av: av, name: name, time: time, preview: preview, x: 0, armed: 0, w: 0, t: null };
  li._.spring = new Spring(function (x) { setRowX(li, x); }, 0, 0.3);
  bindRow(li);
  return li;
}

function updateRow(li, t) {
  var r = li._, name = nameFor(t.sender, t.body), when = listTime(t.ts);
  var leadIcon = t.unread > 0 ? 'bubble' : 'bubbleBadge';
  r.t = t;
  if (r.name.textContent !== name) r.name.textContent = name;
  if (r.time.textContent !== when) r.time.textContent = when;
  if (r.preview.textContent !== t.body) r.preview.textContent = t.body;
  setAvatar(r.av, t.sender, t.body);
  li.classList.toggle('unread', t.unread > 0);
  li.classList.toggle('selected', isSplit() && S.current === t.sender);
  if (r.leadBtn.dataset.k !== leadIcon) {
    r.leadBtn.dataset.k = leadIcon;
    r.leadBtn.textContent = '';
    r.leadBtn.appendChild(icon(leadIcon));
    r.leadBtn.setAttribute('aria-label', t.unread > 0 ? '标为已读' : '标为未读');
  }
  r.main.setAttribute('aria-label', name + '，' + (t.unread > 0 ? '未读，' : '') + when + '，' + t.body);
}

function setRowX(li, x) {
  var r = li._;
  r.x = x;
  r.main.style.transform = x ? 'translate3d(' + x + 'px,0,0)' : '';
  r.trail.style.visibility = x < 0 ? 'visible' : 'hidden';
  r.lead.style.visibility = x > 0 ? 'visible' : 'hidden';
  if (x < 0) r.trailBtn.style.transform = 'translate3d(' + (r.armed < 0 ? x + ACTION_W : ACTION_W / 2 + x / 2) + 'px,0,0)';
  if (x > 0) r.leadBtn.style.transform = 'translate3d(' + (r.armed > 0 ? x - ACTION_W : x / 2 - ACTION_W / 2) + 'px,0,0)';
  li.classList.toggle('swiping', x !== 0);
}

function closeRow(li) {
  if (!li) return;
  li._.armed = 0;
  li._.spring.to(0, { response: 0.35, damping: 1 });
  if (openRow === li) openRow = null;
}

function setArmed(r, armed) {
  if (armed === r.armed) return;
  r.armed = armed;
  if (armed) haptic();
  r.trailBtn.classList.add('ease'); r.leadBtn.classList.add('ease');
  clearTimeout(r.easeT);
  r.easeT = setTimeout(function () { r.trailBtn.classList.remove('ease'); r.leadBtn.classList.remove('ease'); }, 260);
}

function bindRow(li) {
  var r = li._, main = r.main, g = null, pressT = 0;
  main.addEventListener('pointerdown', function (e) {
    if (e.button !== 0 || !e.isPrimary) return;
    r.spring.stop();
    g = { x: e.clientX, y: e.clientY, id: e.pointerId, mode: null, base: r.x, tr: new Tracker() };
    g.tr.add(e.clientX, e.timeStamp);
    clearTimeout(pressT);
    if (!r.x && !openRow) {
      pressT = setTimeout(function () {
        main.classList.add('pressed');
        if (r.t) fetchThread(r.t.sender).catch(noop); // 按住即预取，推入动画时内容已就绪
      }, e.pointerType === 'mouse' ? 0 : 90);
    }
  });
  main.addEventListener('pointermove', function (e) {
    if (!g || e.pointerId !== g.id) return;
    var dx = e.clientX - g.x, dy = e.clientY - g.y;
    g.tr.add(e.clientX, e.timeStamp);
    if (!g.mode) {
      if (Math.abs(dx) < 10 && Math.abs(dy) < 10) return;
      clearTimeout(pressT); main.classList.remove('pressed');
      if (Math.abs(dx) <= Math.abs(dy)) { g = null; return; }
      g.mode = 'swipe'; g.ox = e.clientX; r.w = li.offsetWidth;
      if (openRow && openRow !== li) closeRow(openRow);
      try { main.setPointerCapture(e.pointerId); } catch (err) {}
    }
    var w = r.w, x = g.base + (e.clientX - g.ox);
    if (x > w) x = w + rubber(x - w, w);
    else if (x < -w) x = -w - rubber(-w - x, w);
    setArmed(r, x < -w * 0.55 ? -1 : x > w * 0.55 ? 1 : 0);
    r.x = x; setRowX(li, x);
  });
  function end(e) {
    if (!g || e.pointerId !== g.id) return;
    clearTimeout(pressT);
    g.tr.add(e.clientX, e.timeStamp);
    var mode = g.mode, v = g.tr.velocity();
    g = null;
    if (mode !== 'swipe') { if (e.type === 'pointercancel') main.classList.remove('pressed'); return; }
    r.suppressUntil = Date.now() + 400;
    var cancelled = e.type === 'pointercancel';
    if (r.armed < 0 && !cancelled) { swipeDelete(li, v); return; }
    if (r.armed > 0 && !cancelled) {
      setArmed(r, 0);
      toggleRead(r.t);
      r.spring.to(0, { velocity: v, response: 0.4, damping: 1 });
      openRow = null;
      return;
    }
    setArmed(r, 0);
    var x = r.x, proj = x + project(v), target = 0;
    if (x < 0 && proj < -ACTION_W / 2) target = -ACTION_W;
    else if (x > 0 && proj > ACTION_W / 2) target = ACTION_W;
    if (target) openRow = li; else if (openRow === li) openRow = null;
    r.spring.to(target, { velocity: v, response: 0.38, damping: target ? 0.86 : 1 });
  }
  main.addEventListener('pointerup', end);
  main.addEventListener('pointercancel', end);
  main.addEventListener('click', function () {
    if (Date.now() < (r.suppressUntil || 0) || Date.now() < swallowClickUntil) { main.classList.remove('pressed'); return; }
    if (openRow) { closeRow(openRow); main.classList.remove('pressed'); return; }
    if (!r.t) return;
    if (isSplit()) main.classList.remove('pressed');
    else main.classList.add('pressed');
    openThread(r.t.sender);
  });
  main.addEventListener('keydown', function (e) {
    if (!r.t) return;
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openThread(r.t.sender); }
    else if (e.key === 'Delete' || e.key === 'Backspace') { e.preventDefault(); askDeleteThread(r.t.sender); }
  });
  main.addEventListener('contextmenu', function (e) {
    if (!r.t) return;
    e.preventDefault();
    clearTimeout(pressT); main.classList.remove('pressed');
    var t = r.t;
    openMenu({
      source: main, point: { x: e.clientX, y: e.clientY },
      items: [
        { label: t.unread > 0 ? '标为已读' : '标为未读', icon: t.unread > 0 ? 'bubble' : 'bubbleBadge', run: function () { toggleRead(t); } },
        { label: '删除对话', icon: 'trash', danger: true, run: function () { askDeleteThread(t.sender); } }
      ]
    });
  });
  r.trailBtn.addEventListener('click', function () { if (r.t) swipeDelete(li, 0, true); });
  r.leadBtn.addEventListener('click', function () { if (r.t) { toggleRead(r.t); closeRow(li); } });
}

// 点击空白处只收起已展开的行（与 iOS 一致，不触发点击）
document.addEventListener('pointerdown', function (e) {
  if (openRow && !openRow.contains(e.target)) { closeRow(openRow); swallowClickUntil = Date.now() + 450; }
}, true);

function collapse(li, done) {
  var h = li.offsetHeight;
  var anim = li.animate([{ height: h + 'px', opacity: 1 }, { height: '0px', opacity: 0 }], { duration: mqReduce.matches ? 1 : 300, easing: 'cubic-bezier(.2,.8,.2,1)', fill: 'forwards' });
  anim.onfinish = done;
}

function swipeDelete(li, v, fromButton) {
  var r = li._, t = r.t, w = li.offsetWidth;
  if (!fromButton) r.spring.to(-w, { velocity: v, response: 0.3, damping: 1 });
  confirmDeleteThread(t.sender).then(function (ok) {
    if (!ok) { setArmed(r, 0); r.spring.to(0, { response: 0.4, damping: 1 }); if (openRow === li) openRow = null; return; }
    if (openRow === li) openRow = null;
    r.spring.to(-w, { response: 0.3, damping: 1 });
    collapse(li, function () { deleteThread(t.sender); });
  });
}

function confirmDeleteThread(sender) {
  var t = threadFor(sender), name = t ? nameFor(t.sender, t.body) : prettyNumber(sender);
  return actionSheet({
    message: '与“' + name + '”的所有信息都将被删除。此操作无法撤销。',
    actions: [{ label: '删除对话', danger: true }]
  });
}

function askDeleteThread(sender) {
  confirmDeleteThread(sender).then(function (ok) {
    if (!ok) return;
    var li = rowMap.get(sender);
    if (li) collapse(li, function () { deleteThread(sender); });
    else deleteThread(sender);
  });
}

function deleteThread(sender) {
  S.threads = S.threads.filter(function (t) { return t.sender !== sender; });
  cache.delete(sender);
  renderThreads();
  if (S.current === sender) {
    if (isSplit()) { S.current = null; history.replaceState(null, '', '#/'); renderThreadState(); }
    else goBack();
  }
  api('/api/delete', { sender: sender }).then(refreshSoon, function () { toast('删除失败', '', true); refreshSoon(); });
}

function toggleRead(t) {
  var read = t.unread > 0;
  t.unread = read ? 0 : 1;
  renderThreads();
  api('/api/read', { sender: t.sender, read: read }).then(refreshSoon, refreshSoon);
}

function markAllRead() {
  S.threads.forEach(function (t) { t.unread = 0; });
  renderThreads();
  api('/api/read', { all: true }).then(refreshSoon, refreshSoon);
}

function updateBadges() {
  var n = 0;
  S.threads.forEach(function (t) { n += t.unread || 0; });
  document.title = n ? '信息 (' + n + ')' : '信息';
  try {
    if (n && navigator.setAppBadge) navigator.setAppBadge(n).catch(noop);
    else if (!n && navigator.clearAppBadge) navigator.clearAppBadge().catch(noop);
  } catch (e) {}
  if (S.current) renderThreadHeader();
}

/* ---------- verification code card ---------- */
function renderCodeCard() {
  var c = S.latestCode;
  var fresh = c && serverNow() - c.rx < CODE_TTL;
  codeCard.hidden = !fresh;
  if (!fresh) return;
  $('codeFrom').textContent = nameFor(c.sender, c.body);
  $('codeAgo').textContent = ago(serverNow() - c.rx);
  $('codeValue').textContent = c.code;
  $('codeValue').setAttribute('aria-label', '验证码 ' + c.code + '，点按拷贝');
}
$('codeValue').addEventListener('click', function () { if (S.latestCode) copyText(S.latestCode.code, '已拷贝验证码'); });
$('codeCopy').addEventListener('click', function () { if (S.latestCode) copyText(S.latestCode.code, '已拷贝验证码'); });
$('codeOpen').addEventListener('click', function () { if (S.latestCode) openThread(S.latestCode.sender, { focusId: S.latestCode.id }); });
setInterval(function () { renderCodeCard(); if (S.current) renderQuick(); }, 15000);

/* ---------- search ---------- */
var searchTimer = 0;
searchInput.addEventListener('focus', function () { listPane.classList.add('searching'); });
searchInput.addEventListener('blur', function () { if (!searchInput.value) listPane.classList.remove('searching'); });
searchInput.addEventListener('input', function () {
  S.query = searchInput.value.trim();
  searchClear.hidden = !searchInput.value;
  listPane.classList.toggle('has-query', !!S.query);
  clearTimeout(searchTimer);
  if (!S.query) { S.results = []; S.resultsFor = null; renderResults(); return; }
  searchTimer = setTimeout(runSearch, 160);
});
searchInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') searchInput.blur(); });
searchClear.addEventListener('click', function () {
  searchInput.value = '';
  searchInput.dispatchEvent(new Event('input'));
  searchInput.focus();
});
searchCancel.addEventListener('pointerdown', function (e) { e.preventDefault(); });
searchCancel.addEventListener('click', cancelSearch);
function cancelSearch() {
  searchInput.value = '';
  searchInput.dispatchEvent(new Event('input'));
  listPane.classList.remove('searching');
  searchInput.blur();
}
function runSearch() {
  var q = S.query, seq = ++S.searchSeq;
  api('/api/search?q=' + encodeURIComponent(q)).then(function (r) {
    if (seq !== S.searchSeq) return;
    S.results = r.results; S.resultsFor = q;
    renderResults();
  }, noop);
}
function highlight(node, text, q) {
  var lower = text.toLowerCase(), ql = q.toLowerCase(), i = 0, j;
  while (ql && (j = lower.indexOf(ql, i)) !== -1) {
    if (j > i) node.appendChild(document.createTextNode(text.slice(i, j)));
    node.appendChild(el('mark', null, text.slice(j, j + q.length)));
    i = j + q.length;
  }
  if (i < text.length) node.appendChild(document.createTextNode(text.slice(i)));
}
function snippet(text, q) {
  var flat = text.replace(/\s+/g, ' '), j = flat.toLowerCase().indexOf(q.toLowerCase());
  return j > 28 ? '…' + flat.slice(j - 20) : flat;
}
function renderResults() {
  resultsEl.textContent = '';
  if (!S.query || S.resultsFor === null) return;
  if (!S.results.length) {
    var none = el('li', 'no-results');
    none.appendChild(el('b', null, '无结果'));
    none.appendChild(document.createTextNode('没有找到包含“' + S.resultsFor + '”的信息'));
    resultsEl.appendChild(none);
    return;
  }
  resultsEl.appendChild(el('li', 'section-head', '信息'));
  S.results.forEach(function (m) {
    var li = el('li', 'row'), main = el('div', 'row-main');
    main.tabIndex = 0; main.setAttribute('role', 'button');
    var av = el('span', 'avatar'); setAvatar(av, m.sender, m.body);
    var text = el('div', 'row-text'), top = el('div', 'row-top'), name = el('span', 'name'), preview = el('div', 'preview');
    highlight(name, nameFor(m.sender, m.body), S.resultsFor);
    highlight(preview, snippet(m.body, S.resultsFor), S.resultsFor);
    top.appendChild(name); top.appendChild(el('span', 'time', listTime(m.ts))); top.appendChild(icon('chevronSmall', 'chev'));
    text.appendChild(top); text.appendChild(preview);
    main.appendChild(el('span', 'dot')); main.appendChild(av); main.appendChild(text);
    li.appendChild(main);
    function go() { searchInput.blur(); openThread(m.sender, { focusId: m.id }); }
    main.addEventListener('click', go);
    main.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } });
    resultsEl.appendChild(li);
  });
}

/* ---------- list chrome ---------- */
listScroll.addEventListener('scroll', function () {
  var y = listScroll.scrollTop;
  listPane.classList.toggle('scrolled', y > 2);
  listPane.classList.toggle('collapsed', y > 40);
  if (openRow) closeRow(openRow);
}, { passive: true });

$('moreBtn').addEventListener('click', function () {
  var anyUnread = S.threads.some(function (t) { return t.unread > 0; });
  openMenu({
    source: $('moreBtn'),
    items: [
      { label: '全部标为已读', icon: 'bubble', disabled: !anyUnread, run: markAllRead },
      { label: '连接诊断', icon: 'pulse', run: openDiagnostics },
      { label: '退出登录', icon: 'logout', run: function () { api('/api/logout', {}).then(function () { location.reload(); }, noop); } }
    ]
  });
});

/* ---------- navigation (push / pop) ---------- */
var navSpring = new Spring(applyNav, 1e4, 0.5);
var lastEdgeTouch = 0, expectPop = false;
function paneWidth() { return app.clientWidth || innerWidth; }
function applyNav(x) {
  if (isSplit()) return;
  var w = paneWidth(), p = clamp(x / w, 0, 1);
  threadPane.style.transform = 'translate3d(' + Math.max(0, x) + 'px,0,0)';
  listPane.style.transform = p < 1 ? 'translate3d(' + (-(1 - p) * w * 0.3) + 'px,0,0)' : '';
  listPane.style.setProperty('--dim', String((1 - p) * 0.1));
  var hideThread = p >= 1, hideList = p <= 0;
  threadPane.style.visibility = hideThread ? 'hidden' : '';
  listPane.style.visibility = hideList ? 'hidden' : '';
  if (threadPane.inert !== hideThread) threadPane.inert = hideThread;
  if (listPane.inert !== hideList) listPane.inert = hideList;
}
function applyLayout() {
  app.classList.toggle('split', isSplit());
  if (isSplit()) {
    navSpring.stop();
    threadPane.inert = listPane.inert = false;
    threadPane.style.visibility = listPane.style.visibility = '';
    listPane.style.setProperty('--dim', '0');
  } else {
    navSpring.set(S.threadShown ? 0 : paneWidth());
  }
  rowMap.forEach(function (li) { if (li._.t) updateRow(li, li._.t); });
  renderThreadState();
}
if (mqSplit.addEventListener) mqSplit.addEventListener('change', applyLayout);
else mqSplit.addListener(applyLayout);
addEventListener('resize', function () { if (!isSplit() && !navSpring.raf) navSpring.set(S.threadShown ? 0 : paneWidth()); });

function showThread(animate) {
  S.threadShown = true;
  renderThreadState();
  if (isSplit()) return;
  if (animate && !mqReduce.matches) navSpring.to(0, { response: 0.42, damping: 1 });
  else {
    navSpring.set(0);
    if (animate) threadPane.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 200 });
  }
}
function hideThread(animate, velocity) {
  S.threadShown = false;
  if (isSplit()) { afterHide(); return; }
  if (animate && !mqReduce.matches) navSpring.to(paneWidth(), { response: 0.42, damping: 1, velocity: velocity || 0 }, afterHide);
  else { navSpring.set(paneWidth()); afterHide(); }
}
function afterHide() {
  if (S.threadShown) return;
  S.current = null;
  rowMap.forEach(function (li) { li._.main.classList.remove('pressed'); });
  renderThreadState();
  markSelected();
}
function renderThreadState() {
  threadPane.classList.toggle('is-empty', !S.current);
}
function markSelected() {
  rowMap.forEach(function (li) { li.classList.toggle('selected', isSplit() && !!li._.t && li._.t.sender === S.current); });
}
function senderFromHash() {
  var m = /^#\/t\/(.+)$/.exec(location.hash);
  if (!m) return null;
  try { return decodeURIComponent(m[1]); } catch (e) { return null; }
}
function threadUrl(sender) { return '#/t/' + encodeURIComponent(sender); }

function openThread(sender, opts) {
  opts = opts || {};
  closeMenu(true);
  if (openRow) closeRow(openRow);
  var changed = S.current !== sender;
  S.current = sender;
  if (changed) {
    var cached = cache.get(sender);
    S.messages = cached ? cached.messages.slice() : [];
    S.hasMore = cached ? cached.hasMore : false;
    S.threadLoaded = !!cached;
    renderThreadHeader();
    renderMessages();
    if (!opts.focusId) scrollToBottom(false);
    loadThread(sender, opts.focusId);
  } else if (opts.focusId) {
    ensureFocus(opts.focusId);
  }
  if (opts.history !== false) {
    if (isSplit()) history.replaceState({ t: sender }, '', threadUrl(sender));
    else if (!S.pushed) { history.pushState({ t: sender }, '', threadUrl(sender)); S.pushed = true; }
    else history.replaceState({ t: sender }, '', threadUrl(sender));
  }
  markSelected();
  showThread(opts.animate !== false);
  maybeMarkRead();
}

function goBack() {
  if (isSplit() || !S.threadShown) return;
  if (S.pushed) { S.pushed = false; expectPop = true; history.back(); }
  else { history.replaceState(null, '', '#/'); hideThread(true); }
}
$('backBtn').addEventListener('click', goBack);

addEventListener('popstate', function () {
  var sender = senderFromHash();
  // Safari 自带的边缘返回手势已经播过动画，这里不再重复
  var animate = expectPop || standalone || Date.now() - lastEdgeTouch > 1000;
  expectPop = false;
  if (sender) { S.pushed = true; openThread(sender, { history: false, animate: animate }); }
  else { S.pushed = false; if (S.threadShown) hideThread(animate); }
});
document.addEventListener('touchstart', function (e) {
  var t = e.touches[0];
  if (t && (t.clientX < 24 || t.clientX > innerWidth - 24)) lastEdgeTouch = Date.now();
}, { passive: true, capture: true });

/* ---------- thread ---------- */
var cache = new Map(), inflight = new Map();
function remember(sender) {
  inflight.delete(sender);
  cache.delete(sender);
  cache.set(sender, { messages: S.messages.slice(), hasMore: S.hasMore });
  if (cache.size > 20) cache.delete(cache.keys().next().value);
}
function fetchThread(sender) {
  var f = inflight.get(sender);
  if (f && Date.now() - f.at < 3000) return f.p;
  var p = api('/api/messages?sender=' + encodeURIComponent(sender));
  inflight.set(sender, { p: p, at: Date.now() });
  p.catch(function () { inflight.delete(sender); });
  return p;
}
function loadThread(sender, focusId) {
  fetchThread(sender).then(function (r) {
    if (S.current !== sender) return;
    var atBottom = !S.messages.length || nearBottom();
    S.messages = r.messages; S.hasMore = r.hasMore; S.threadLoaded = true;
    remember(sender);
    renderMessages();
    renderThreadHeader();
    if (focusId) ensureFocus(focusId);
    else if (atBottom) scrollToBottom(false);
    maybeMarkRead();
  }, noop);
}
function ensureFocus(id) {
  var tries = 0;
  (function attempt() {
    if (msgById(id) || !S.hasMore || tries++ > 20) { focusMessage(id); return; }
    loadOlder().then(attempt, noop);
  })();
}
function focusMessage(id) {
  var row = bubblesEl.querySelector('.msg[data-id="' + id + '"]');
  if (!row) return;
  row.scrollIntoView({ block: 'center' });
  var b = row.querySelector('.bubble');
  b.classList.remove('flash'); void b.offsetWidth; b.classList.add('flash');
}
function nearBottom() { return threadScroll.scrollHeight - threadScroll.scrollTop - threadScroll.clientHeight < 120; }
function scrollToBottom(smooth) {
  threadScroll.scrollTo({ top: threadScroll.scrollHeight, behavior: smooth && !mqReduce.matches ? 'smooth' : 'auto' });
}
function loadOlder() {
  if (S.loadingOlder || !S.hasMore || !S.messages.length) return Promise.resolve();
  S.loadingOlder = true;
  var sender = S.current, first = S.messages[0];
  return api('/api/messages?sender=' + encodeURIComponent(sender) + '&before_ts=' + first.ts + '&before_id=' + first.id).then(function (r) {
    if (sender !== S.current) return;
    var h = threadScroll.scrollHeight, top = threadScroll.scrollTop;
    S.messages = r.messages.concat(S.messages); S.hasMore = r.hasMore;
    remember(sender);
    renderMessages();
    threadScroll.scrollTop = top + (threadScroll.scrollHeight - h);
  }).then(function () { S.loadingOlder = false; }, function () { S.loadingOlder = false; });
}
function syncThread() {
  var sender = S.current;
  if (!sender || !S.threadLoaded) return Promise.resolve();
  var lastId = 0;
  S.messages.forEach(function (m) { if (m.id > lastId) lastId = m.id; });
  return api('/api/messages?sender=' + encodeURIComponent(sender) + '&after=' + lastId).then(function (r) {
    if (sender !== S.current || !r.messages.length) return;
    var atBottom = nearBottom(), fresh = new Set();
    r.messages.forEach(function (m) { if (!msgById(m.id)) { fresh.add(m.id); S.messages.push(m); } });
    if (!fresh.size) return;
    S.messages.sort(cmpMsg);
    remember(sender);
    renderMessages(fresh);
    if (atBottom) scrollToBottom(true);
    maybeMarkRead();
  });
}
function threadVisible() {
  return !!S.current && document.visibilityState === 'visible' && (isSplit() || S.threadShown);
}
function maybeMarkRead() {
  var t = threadFor(S.current);
  if (!t || !(t.unread > 0) || !threadVisible()) return;
  t.unread = 0;
  renderThreads();
  api('/api/read', { sender: t.sender }).then(refreshSoon, noop);
}

function renderThreadHeader() {
  if (!S.current) return;
  var t = threadFor(S.current), last = S.messages[S.messages.length - 1];
  var body = t ? t.body : last ? last.body : '';
  var name = nameFor(S.current, body);
  peerName.textContent = name;
  setAvatar(peerAvatar, S.current, body);
  threadPane.setAttribute('aria-label', '与' + name + '的对话');
  var others = 0;
  S.threads.forEach(function (x) { if (x.sender !== S.current) others += x.unread || 0; });
  backBadge.textContent = others > 99 ? '99+' : String(others);
  backBadge.hidden = !others;
}

function renderMessages(fresh) {
  bubblesEl.textContent = '';
  var frag = document.createDocumentFragment();
  if (S.threadLoaded && !S.hasMore) frag.appendChild(el('div', 'thread-intro', '短信/彩信'));
  var list = S.messages;
  for (var i = 0; i < list.length; i++) {
    var m = list[i], prev = list[i - 1], next = list[i + 1];
    if (!prev || m.ts - prev.ts > 15 * 60000 || dayStart(m.ts) !== dayStart(prev.ts)) {
      var sep = el('div', 'ts'), day = el('b', null, sepDay(m.ts));
      sep.appendChild(day); sep.appendChild(document.createTextNode(' ' + clock(m.ts)));
      frag.appendChild(sep);
    }
    var nextBreaks = !next || next.ts - m.ts > 60000 || next.ts - m.ts > 15 * 60000 || dayStart(next.ts) !== dayStart(m.ts);
    var row = el('div', 'msg' + (nextBreaks ? ' end' : '') + (fresh && fresh.has(m.id) ? ' in' : ''));
    row.dataset.id = m.id;
    var b = el('div', 'bubble' + (nextBreaks ? ' tail' : ''));
    fillBubble(b, m);
    row.appendChild(b);
    row.appendChild(el('time', 'msg-time', clock(m.ts)));
    frag.appendChild(row);
  }
  bubblesEl.appendChild(frag);
  renderQuick();
}

// 数据检测：验证码、链接、电话号码（全部用 DOM 文本节点构建，杜绝 XSS）
function detect(text, code) {
  var found = [];
  function free(s, e) {
    for (var i = 0; i < found.length; i++) if (s < found[i].e && e > found[i].s) return false;
    return true;
  }
  if (code) {
    var j = 0;
    while ((j = text.indexOf(code, j)) !== -1) {
      if (!/[A-Za-z0-9]/.test(text.charAt(j - 1)) && !/[A-Za-z0-9]/.test(text.charAt(j + code.length))) {
        found.push({ s: j, e: j + code.length, type: 'code' });
        break;
      }
      j += code.length;
    }
  }
  var re = /(?:https?:\/\/|www\.)[^\s<>"'，。！？；、（）()【】“”‘’]+/gi, m;
  while ((m = re.exec(text))) {
    var url = m[0].replace(/[.,;:!?]+$/, '');
    if (free(m.index, m.index + url.length)) found.push({ s: m.index, e: m.index + url.length, type: 'url' });
  }
  re = /(^|[^\d+])(\+\d{6,15}|1[3-9]\d{9}|95\d{3,6}|400[- ]?\d{3}[- ]?\d{4}|800[- ]?\d{3}[- ]?\d{4}|0\d{2,3}-\d{7,8})(?!\d|\.\d)/g;
  while ((m = re.exec(text))) {
    var s = m.index + m[1].length, e = s + m[2].length;
    if (free(s, e)) found.push({ s: s, e: e, type: 'tel' });
  }
  return found.sort(function (a, b) { return a.s - b.s; });
}
function fillBubble(b, m) {
  var text = m.body, parts = detect(text, m.code), i = 0;
  parts.forEach(function (p) {
    if (p.s > i) b.appendChild(document.createTextNode(text.slice(i, p.s)));
    var v = text.slice(p.s, p.e), n;
    if (p.type === 'url') {
      n = el('a', 'dd', v);
      n.href = /^https?:/i.test(v) ? v : 'https://' + v;
      n.target = '_blank'; n.rel = 'noopener noreferrer';
    } else if (p.type === 'tel') {
      n = el('a', 'dd', v);
      n.href = 'tel:' + v.replace(/[^\d+]/g, '');
    } else {
      n = el('span', 'dd dd-code', v);
      n.dataset.code = m.code; n.tabIndex = 0;
      n.setAttribute('role', 'button');
      n.setAttribute('aria-label', '验证码 ' + v + '，点按拷贝');
    }
    b.appendChild(n);
    i = p.e;
  });
  if (i < text.length) b.appendChild(document.createTextNode(text.slice(i)));
}

function renderQuick() {
  var last = S.messages[S.messages.length - 1];
  var show = !!(last && last.code && serverNow() - (last.rx || last.ts) < QUICK_TTL);
  quickEl.hidden = !show;
  threadPane.classList.toggle('has-quick', show);
  if (show) { $('quickCode').textContent = last.code; quickEl.dataset.code = last.code; }
}
$('quickBtn').addEventListener('click', function () { if (quickEl.dataset.code) copyText(quickEl.dataset.code, '已拷贝验证码'); });

threadScroll.addEventListener('scroll', function () {
  threadPane.classList.toggle('scrolled', threadScroll.scrollTop > 2);
  if (threadScroll.scrollTop < 400 && S.hasMore && !S.loadingOlder && S.threadLoaded) loadOlder();
}, { passive: true });

$('peerBtn').addEventListener('click', function () {
  var sender = S.current;
  if (!sender) return;
  var t = threadFor(sender), name = peerName.textContent;
  var info = prettyNumber(sender) + (t ? ' · ' + t.total + ' 条信息' : '');
  actionSheet({
    title: name !== prettyNumber(sender) ? name : '',
    message: info,
    actions: [
      { label: '拷贝号码', run: function () { copyText(sender, '已拷贝号码'); } },
      { label: '标为未读', run: function () { if (t && !(t.unread > 0)) { toggleRead(t); goBack(); } } },
      { label: '删除对话', danger: true, run: function () { askDeleteThread(sender); } }
    ]
  });
});

/* ---------- thread gestures: swipe left = timestamps, swipe right = back ---------- */
var revealSpring = new Spring(function (r) {
  bubblesEl.style.setProperty('--reveal', r + 'px');
  bubblesEl.style.setProperty('--reveal-o', String(clamp(-r / 60, 0, 1)));
}, 0, 0.3);
(function () {
  var g = null;
  threadScroll.addEventListener('pointerdown', function (e) {
    if (e.pointerType === 'mouse' || !e.isPrimary) return;
    if (!standalone && e.clientX < 24) return; // 屏幕左缘留给 Safari 的返回手势
    g = { x: e.clientX, y: e.clientY, id: e.pointerId, mode: null, tr: new Tracker() };
    g.tr.add(e.clientX, e.timeStamp);
  });
  threadScroll.addEventListener('pointermove', function (e) {
    if (!g || e.pointerId !== g.id) return;
    var dx = e.clientX - g.x, dy = e.clientY - g.y;
    g.tr.add(e.clientX, e.timeStamp);
    if (!g.mode) {
      if (Math.abs(dx) < 10 && Math.abs(dy) < 10) return;
      if (Math.abs(dx) <= Math.abs(dy) * 1.2 || (dx > 0 && isSplit())) { g = null; return; }
      g.mode = dx > 0 ? 'pop' : 'reveal';
      g.ox = e.clientX;
      cancelLongPress();
      if (g.mode === 'pop') { navSpring.stop(); g.base = navSpring.x; listPane.style.visibility = ''; }
      else { revealSpring.stop(); g.base = revealSpring.x; }
      try { threadScroll.setPointerCapture(e.pointerId); } catch (err) {}
    }
    var d = e.clientX - g.ox;
    if (g.mode === 'pop') {
      navSpring.x = Math.max(0, g.base + d);
      applyNav(navSpring.x);
    } else {
      var r = g.base + d;
      if (r > 0) r = rubber(r, 300);
      else if (r < -REVEAL_W) r = -REVEAL_W - rubber(-REVEAL_W - r, 300);
      revealSpring.x = r;
      revealSpring.apply(r);
    }
  });
  function end(e) {
    if (!g || e.pointerId !== g.id) return;
    g.tr.add(e.clientX, e.timeStamp);
    var mode = g.mode, v = g.tr.velocity(), cancelled = e.type === 'pointercancel';
    g = null;
    if (mode === 'pop') {
      var w = paneWidth(), x = navSpring.x;
      if (!cancelled && x + project(v) > w / 2) {
        S.threadShown = false;
        navSpring.to(w, { response: 0.35, damping: 1, velocity: Math.max(v, 0) }, afterHide);
        if (S.pushed) { S.pushed = false; expectPop = true; history.back(); }
        else history.replaceState(null, '', '#/');
      } else {
        navSpring.to(0, { response: 0.35, damping: 1, velocity: v });
      }
    } else if (mode === 'reveal') {
      revealSpring.to(0, { response: 0.35, damping: 1, velocity: v });
    }
  }
  threadScroll.addEventListener('pointerup', end);
  threadScroll.addEventListener('pointercancel', end);
})();

/* ---------- bubble long-press menu ---------- */
var lp = null, suppressBubbleClick = 0;
function cancelLongPress() {
  if (!lp) return;
  clearTimeout(lp.t); clearTimeout(lp.t2);
  lp.b.classList.remove('pressing');
  lp = null;
}
bubblesEl.addEventListener('pointerdown', function (e) {
  var b = e.target.closest('.bubble');
  if (!b || e.button !== 0 || e.pointerType === 'mouse') return;
  cancelLongPress();
  lp = {
    b: b, x: e.clientX, y: e.clientY,
    t2: setTimeout(function () { if (lp) lp.b.classList.add('pressing'); }, 120),
    t: setTimeout(function () {
      if (!lp) return;
      var target = lp.b;
      cancelLongPress();
      suppressBubbleClick = Date.now() + 700;
      openBubbleMenu(target);
    }, 450)
  };
});
bubblesEl.addEventListener('pointermove', function (e) {
  if (lp && Math.abs(e.clientX - lp.x) + Math.abs(e.clientY - lp.y) > 8) cancelLongPress();
});
bubblesEl.addEventListener('pointerup', cancelLongPress);
bubblesEl.addEventListener('pointercancel', cancelLongPress);
bubblesEl.addEventListener('contextmenu', function (e) {
  var b = e.target.closest('.bubble');
  if (!b) return;
  e.preventDefault();
  cancelLongPress();
  openBubbleMenu(b);
});
bubblesEl.addEventListener('click', function (e) {
  if (Date.now() < suppressBubbleClick) { e.preventDefault(); e.stopPropagation(); return; }
  var c = e.target.closest('.dd-code');
  if (c) copyText(c.dataset.code, '已拷贝验证码');
}, true);
bubblesEl.addEventListener('keydown', function (e) {
  var c = e.target.closest && e.target.closest('.dd-code');
  if (c && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); copyText(c.dataset.code, '已拷贝验证码'); }
});

function openBubbleMenu(b) {
  if (menu) return;
  var m = msgById(Number(b.parentNode.dataset.id));
  if (!m) return;
  haptic();
  var items = [{ label: '拷贝', icon: 'copy', run: function () { copyText(m.body, '已拷贝'); } }];
  if (m.code) items.unshift({ label: '拷贝验证码', icon: 'key', run: function () { copyText(m.code, '已拷贝验证码'); } });
  items.push({ label: '删除', icon: 'trash', danger: true, run: function () { deleteMessage(m); } });
  openMenu({ source: b, lift: true, items: items });
}

function deleteMessage(m) {
  actionSheet({ message: '此信息将被删除。此操作无法撤销。', actions: [{ label: '删除信息', danger: true }] }).then(function (ok) {
    if (!ok) return;
    var sender = S.current;
    var row = bubblesEl.querySelector('.msg[data-id="' + m.id + '"]');
    function finish() {
      S.messages = S.messages.filter(function (x) { return x.id !== m.id; });
      remember(sender);
      renderMessages();
      if (!S.messages.length) deleteThreadLocal(sender);
    }
    if (row) collapse(row, finish); else finish();
    api('/api/delete', { id: m.id }).then(refreshSoon, function () { toast('删除失败', '', true); refreshSoon(); });
  });
}
function deleteThreadLocal(sender) {
  S.threads = S.threads.filter(function (t) { return t.sender !== sender; });
  cache.delete(sender);
  renderThreads();
  if (isSplit()) { S.current = null; history.replaceState(null, '', '#/'); renderThreadState(); }
  else goBack();
}

/* ---------- menu (context / pull-down) ---------- */
var menu = null;
function openMenu(o) {
  closeMenu(true);
  var layer = el('div', 'menu-layer' + (o.lift ? ' lift' : ''));
  var backdrop = el('div', 'menu-backdrop');
  layer.appendChild(backdrop);
  var rect = o.source.getBoundingClientRect(), preview = null, pv = null;
  if (o.lift) {
    // 按压时气泡正在缩小，用布局尺寸（不受 transform 影响）还原真实位置
    var w = o.source.offsetWidth, h = o.source.offsetHeight;
    rect = { left: rect.left + (rect.width - w) / 2, top: rect.top + (rect.height - h) / 2, width: w, height: h };
    rect.right = rect.left + w; rect.bottom = rect.top + h;
    preview = o.source.cloneNode(true);
    preview.classList.remove('pressing', 'flash');
    preview.classList.add('menu-preview');
    preview.style.left = rect.left + 'px';
    preview.style.top = rect.top + 'px';
    preview.style.width = w + 'px';
    preview.style.maxWidth = 'none';
    layer.appendChild(preview);
  }
  var box = el('div', 'menu glass');
  box.setAttribute('role', 'menu');
  o.items.forEach(function (it) {
    var b = el('button', 'menu-item' + (it.danger ? ' danger' : ''));
    b.type = 'button'; b.setAttribute('role', 'menuitem');
    if (it.disabled) b.disabled = true;
    b.appendChild(icon(it.icon));
    b.appendChild(el('span', null, it.label));
    b.addEventListener('click', function () { closeMenu(); it.run(); });
    box.appendChild(b);
  });
  layer.appendChild(box);
  document.body.appendChild(layer);

  var vw = innerWidth, vh = innerHeight, ins = safeInsets();
  var mw = box.offsetWidth, mh = box.offsetHeight;
  var top, left, originY;
  if (o.point) {
    left = o.point.x; top = o.point.y; originY = 'top';
    if (top + mh > vh - 12) { top = o.point.y - mh; originY = 'bottom'; }
  } else if (o.lift) {
    left = rect.left; top = rect.bottom + 10; originY = 'top';
    if (top + mh > vh - ins.bottom - 12) { top = rect.top - 10 - mh; originY = 'bottom'; }
    if (top < ins.top + 12) { top = vh - ins.bottom - 12 - mh; originY = 'bottom'; }
  } else {
    left = rect.right - mw; top = rect.bottom + 8; originY = 'top';
  }
  left = clamp(left, 12, vw - mw - 12);
  top = clamp(top, ins.top + 8, vh - ins.bottom - mh - 8);
  box.style.left = left + 'px';
  box.style.top = top + 'px';
  var ox = o.point ? o.point.x - left : clamp(rect.left + rect.width / 2 - left, 0, mw);
  box.style.transformOrigin = ox + 'px ' + (originY === 'top' ? '0' : '100%');

  var sp = new Spring(function (s) {
    box.style.transform = 'scale(' + s + ')';
    box.style.opacity = String(clamp((s - 0.4) / 0.5, 0, 1));
  }, 0.4, 0.002);
  sp.set(0.4);
  if (preview) {
    pv = new Spring(function (s) { preview.style.transform = 'scale(' + s + ')'; }, 0.96, 0.001);
    pv.set(0.96);
    o.source.classList.add('menu-source');
  }
  requestAnimationFrame(function () {
    layer.classList.add('open');
    sp.to(1, { response: 0.36, damping: 0.82 });
    if (pv) pv.to(1.02, { response: 0.35, damping: 0.72 });
  });

  backdrop.addEventListener('click', function () { closeMenu(); });
  backdrop.addEventListener('contextmenu', function (e) { e.preventDefault(); closeMenu(); });
  layer.addEventListener('keydown', function (e) {
    var items = Array.prototype.slice.call(box.querySelectorAll('.menu-item:not(:disabled)'));
    var i = items.indexOf(document.activeElement);
    if (e.key === 'ArrowDown' || (e.key === 'Tab' && !e.shiftKey)) { e.preventDefault(); items[(i + 1) % items.length].focus(); }
    else if (e.key === 'ArrowUp' || (e.key === 'Tab' && e.shiftKey)) { e.preventDefault(); items[(i - 1 + items.length) % items.length].focus(); }
  });
  menu = { layer: layer, source: o.source, prevFocus: document.activeElement, springs: [sp, pv] };
  var first = box.querySelector('.menu-item:not(:disabled)');
  if (first) first.focus({ preventScroll: true });
}
function closeMenu(instant) {
  if (!menu) return;
  var m = menu;
  menu = null;
  m.springs.forEach(function (s) { if (s) s.stop(); });
  m.layer.classList.remove('open');
  m.layer.classList.add('closing');
  setTimeout(function () { m.layer.remove(); m.source.classList.remove('menu-source'); }, instant ? 0 : 200);
  if (m.prevFocus && m.prevFocus.focus && document.contains(m.prevFocus)) m.prevFocus.focus({ preventScroll: true });
}

/* ---------- action sheet ---------- */
function actionSheet(o) {
  return new Promise(function (resolve) {
    closeMenu(true);
    var layer = el('div', 'sheet-layer'), scrim = el('div', 'sheet-scrim'), sheet = el('div', 'sheet');
    sheet.setAttribute('role', 'dialog');
    sheet.setAttribute('aria-modal', 'true');
    var group = el('div', 'sheet-group');
    if (o.title || o.message) {
      var head = el('div', 'sheet-head');
      if (o.title) head.appendChild(el('div', 'sheet-title', o.title));
      if (o.message) head.appendChild(el('div', 'sheet-msg', o.message));
      group.appendChild(head);
      sheet.setAttribute('aria-label', o.title || o.message);
    }
    o.actions.forEach(function (a) {
      var b = el('button', 'sheet-btn' + (a.danger ? ' danger' : ''), a.label);
      b.type = 'button';
      b.addEventListener('click', function () { done(a); });
      group.appendChild(b);
    });
    var cancel = el('button', 'sheet-btn sheet-cancel', '取消');
    cancel.type = 'button';
    cancel.addEventListener('click', function () { done(null); });
    sheet.appendChild(group); sheet.appendChild(cancel);
    layer.appendChild(scrim); layer.appendChild(sheet);
    document.body.appendChild(layer);
    scrim.addEventListener('click', function () { done(null); });

    var h = sheet.offsetHeight + 40;
    var sp = new Spring(function (y) { sheet.style.transform = 'translate3d(0,' + y + 'px,0)'; }, h, 0.5);
    sp.set(h);
    requestAnimationFrame(function () { layer.classList.add('open'); sp.to(0, { response: 0.4, damping: 1 }); });

    var prev = document.activeElement, finished = false;
    cancel.focus({ preventScroll: true });
    function onKey(e) {
      if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); done(null); }
      else if (e.key === 'Tab') {
        var btns = Array.prototype.slice.call(sheet.querySelectorAll('button'));
        var i = btns.indexOf(document.activeElement);
        e.preventDefault();
        btns[(i + (e.shiftKey ? -1 : 1) + btns.length) % btns.length].focus();
      }
    }
    document.addEventListener('keydown', onKey, true);
    function done(a) {
      if (finished) return;
      finished = true;
      document.removeEventListener('keydown', onKey, true);
      layer.classList.remove('open');
      layer.style.pointerEvents = 'none';
      sp.to(h, { response: 0.3, damping: 1 }, function () { layer.remove(); });
      if (prev && prev.focus && document.contains(prev)) prev.focus({ preventScroll: true });
      if (a && a.run) a.run();
      resolve(!!a);
    }
  });
}

/* ---------- connection diagnostics ---------- */
var RESULT_TEXT = {
  stored: '已保存', duplicate: '重复投递，已忽略', ignored_event: '不是收信事件，已忽略', ignored_recipient: '收件地址不在 INBOX 范围内',
  invalid_signature: '签名校验失败', invalid_json: '请求内容不是 JSON', resend_api_error: '读取邮件正文失败', not_configured: '配置缺失', error: 'Worker 出错'
};
var DETAIL_TEXT = {
  missing_headers: '缺少签名请求头', stale_timestamp: '时间戳超出 5 分钟', secret_not_base64: 'RESEND_WEBHOOK_SECRET 格式不对',
  signature_mismatch: 'RESEND_WEBHOOK_SECRET 与 Resend 后台的 Signing secret 不一致'
};
function stamp(ts) { return ts ? listTime(ts) + (daysAgo(ts) > 0 ? ' ' + clock(ts) : '') : ''; }
function verdict(d) {
  var c = d.config, r = d.resend, w = d.webhooks || [], last = w[0];
  var setup = d.setup || {}, sw = setup.webhooks, sd = setup.domains;
  if (c.apiKey === 'missing') return ['bad', 'RESEND_API_KEY 未设置', 'Worker 需要用它读取邮件正文。'];
  if (c.webhookSecret !== 'ok') return ['bad', 'Webhook 签名密钥有问题', '在 Resend → Webhooks → 你的 Endpoint 里复制 Signing secret（whsec_…），填到 RESEND_WEBHOOK_SECRET。'];
  if (r && !r.ok) return ['bad', '无法读取 Resend 收件箱', r.error + '。API Key 需要 Full access 权限；401 表示 Key 填错或已删除。'];
  var emails = r && r.ok ? r.emails : [];
  var allowed = emails.filter(function (e) { return e.allowed; });
  var missing = allowed.filter(function (e) { return e.state === 'missing'; }).length;
  // 先看实际效果：最新一封邮件已入库（或最近一次 Webhook 存进去了）就说明链路是通的，不再拿配置推测吓人
  var delivering = allowed.length ? allowed[0].state !== 'missing' : !!last && (last.result === 'stored' || last.result === 'duplicate');
  if (delivering) {
    return missing
      ? ['warn', missing + ' 封较早的邮件还没入库', '新邮件已经能正常到达。点下方「从 Resend 导入」把之前漏掉的补上。']
      : ['ok', '一切正常', '共 ' + d.messages + ' 条信息。新短信会通过 Webhook 实时到达。'];
  }
  if (sw && sw.ok) {
    var subscribed = function (x) { return x.status === 'enabled' && (!x.events || x.events.indexOf('email.received') >= 0); };
    var mine = sw.items.filter(function (x) { return x.matches; });
    if (!mine.length) {
      return sw.items.some(subscribed)
        ? ['warn', 'Webhook 地址和当前网址不同', '如果它也指向这个 Worker 可以忽略；否则在 Resend → Webhooks 添加 ' + c.webhookUrl + '。']
        : ['bad', 'Resend 里没有指向这里的 Webhook', '在 Resend → Webhooks 添加 ' + c.webhookUrl + '，事件勾选 email.received。'];
    }
    if (!mine.some(subscribed)) {
      return mine.some(function (x) { return x.status !== 'enabled'; })
        ? ['bad', 'Webhook 已被停用', '多半是之前连续失败被 Resend 自动停用了。在 Resend → Webhooks 里重新启用，然后点「从 Resend 导入」补回漏掉的。']
        : ['bad', 'Webhook 没有订阅 email.received', '在 Resend → Webhooks 编辑这个 Endpoint，勾选 email.received 事件。'];
    }
  }
  if (r && r.ok && !emails.length) {
    var recv = sd && sd.ok ? sd.items.filter(function (x) { return x.receiving === 'enabled'; }) : null;
    if (recv && !recv.length) return ['bad', '没有开启收信的域名', 'Resend → Domains → 选择域名 → 打开 Receiving，并按提示添加 MX 记录。'];
    if (recv && recv.every(function (x) { return x.mxRecord && x.mxRecord.status !== 'verified'; })) {
      return ['warn', '收信 MX 记录还没验证通过', '把 Resend 给出的 MX 记录添加到 ' + recv[0].name + '，且优先级数字要最小，然后等 DNS 生效。'];
    }
    var hosts = (recv || []).map(function (x) { return '…@' + x.name; });
    return ['warn', 'Resend 还没有收到任何邮件', hosts.length
      ? '手机要转发到 ' + hosts.join(' 或 ') + ' 这样的地址（注意 0901@cuven.us 和 …@0901.cuven.us 是不同的域名）。'
      : '检查 Resend → Domains 里的收信设置，以及手机转发的收件地址。'];
  }
  if (last && last.result === 'invalid_signature') return ['bad', 'Webhook 签名校验失败', (DETAIL_TEXT[last.detail] || last.detail) + '。'];
  if (last && last.result === 'resend_api_error') return ['bad', '读取邮件正文失败', last.detail];
  if (emails.length && !allowed.length) return ['warn', 'INBOX 过滤挡掉了所有邮件', '当前 INBOX = ' + c.inbox + '，而邮件发往 ' + emails[0].to + '。清空 INBOX 或改成实际地址。'];
  if (!w.length) return ['warn', 'Resend 收到了邮件，但从没调用过 Webhook', '在 Resend → Webhooks 添加下面的 Webhook 地址并勾选 email.received。可以先点「从 Resend 导入」。'];
  if (missing) return ['warn', missing + ' 封邮件还没入库', '点下方「从 Resend 导入」补上。'];
  return ['ok', '一切正常', '共 ' + d.messages + ' 条信息。新短信会通过 Webhook 实时到达。'];
}
function gRow(st, title, sub, value) {
  var row = el('div', 'g-row');
  if (st) row.appendChild(icon(st));
  var main = el('div', 'g-main', title);
  if (sub) main.appendChild(el('span', 'g-sub', sub));
  row.appendChild(main);
  if (value != null) row.appendChild(value.nodeType ? value : el('span', 'g-value', value));
  return row;
}
function varRow(st, title, name, value) {
  var row = gRow(st, title, null, value);
  row.querySelector('.g-main').appendChild(el('span', 'g-sub g-mono', name));
  return row;
}
function gSection(body, head, rows, foot) {
  body.appendChild(el('div', 'g-head', head));
  var g = el('div', 'g');
  rows.forEach(function (r) { g.appendChild(r); });
  body.appendChild(g);
  if (foot) body.appendChild(el('div', 'g-foot', foot));
}
var diagOpen = false;
function openDiagnostics() {
  if (diagOpen) return;
  diagOpen = true;
  closeMenu(true);
  var layer = el('div', 'page-layer'), scrim = el('div', 'page-scrim'), sheet = el('div', 'page-sheet');
  sheet.setAttribute('role', 'dialog'); sheet.setAttribute('aria-modal', 'true'); sheet.setAttribute('aria-label', '连接诊断');
  var head = el('div', 'page-head'), done = el('button', 'page-done', '完成'), body = el('div', 'page-body');
  done.type = 'button';
  head.appendChild(el('span', 'page-grabber')); head.appendChild(el('h2', 'page-title', '连接诊断')); head.appendChild(done);
  sheet.appendChild(head); sheet.appendChild(body);
  layer.appendChild(scrim); layer.appendChild(sheet);
  document.body.appendChild(layer);

  var h = sheet.offsetHeight + 40;
  var sp = new Spring(function (y) { sheet.style.transform = 'translate3d(0,' + y + 'px,0)'; }, h, 0.5);
  sp.set(h);
  requestAnimationFrame(function () { layer.classList.add('open'); sp.to(0, { response: 0.45, damping: 1 }); });

  var prev = document.activeElement, closed = false;
  app.inert = true; // 表单打开时，后面的页面不可聚焦、不可点
  done.focus({ preventScroll: true });
  function close(v) {
    if (closed) return;
    closed = true;
    diagOpen = false;
    app.inert = false;
    document.removeEventListener('keydown', onKey, true);
    layer.classList.remove('open');
    layer.style.pointerEvents = 'none';
    sp.to(sheet.offsetHeight + 40, { response: 0.35, damping: 1, velocity: v || 0 }, function () { layer.remove(); });
    if (prev && prev.focus && document.contains(prev)) prev.focus({ preventScroll: true });
  }
  function onKey(e) {
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(0); return; }
    if (e.key === 'Tab') {
      var items = Array.prototype.slice.call(sheet.querySelectorAll('button:not(:disabled)'));
      var i = items.indexOf(document.activeElement);
      e.preventDefault();
      if (items.length) items[(i + (e.shiftKey ? -1 : 1) + items.length) % items.length].focus();
      return;
    }
    e.stopPropagation(); // 别触发列表页的快捷键
  }
  document.addEventListener('keydown', onKey, true);
  done.addEventListener('click', function () { close(0); });
  scrim.addEventListener('click', function () { close(0); });

  // 下拉抓手关闭，跟手并继承速度
  var g = null;
  head.addEventListener('pointerdown', function (e) {
    if (e.target === done) return;
    sp.stop();
    g = { y: e.clientY, base: sp.x, id: e.pointerId, tr: new Tracker() };
    g.tr.add(e.clientY, e.timeStamp);
    try { head.setPointerCapture(e.pointerId); } catch (err) {}
  });
  head.addEventListener('pointermove', function (e) {
    if (!g || e.pointerId !== g.id) return;
    g.tr.add(e.clientY, e.timeStamp);
    var y = g.base + e.clientY - g.y;
    sp.x = y < 0 ? -rubber(-y, 400) : y;
    sp.apply(sp.x);
  });
  function release(e) {
    if (!g || e.pointerId !== g.id) return;
    g.tr.add(e.clientY, e.timeStamp);
    var v = g.tr.velocity();
    g = null;
    if (sp.x + project(v) > sheet.offsetHeight * 0.35) close(Math.max(v, 0));
    else sp.to(0, { response: 0.4, damping: 1, velocity: v });
  }
  head.addEventListener('pointerup', release);
  head.addEventListener('pointercancel', release);

  function load() {
    body.textContent = '';
    body.appendChild(el('div', 'diag-loading', '正在检查…'));
    api('/api/diagnostics').then(render, function (err) {
      body.textContent = '';
      body.appendChild(el('div', 'diag-loading', '检查失败：' + err.message));
    });
  }
  function render(d) {
    if (closed) return;
    body.textContent = '';
    var c = d.config, r = d.resend, w = d.webhooks || [], v = verdict(d);
    var sum = el('div', 'diag-summary');
    sum.appendChild(icon(v[0] === 'ok' ? 'stOk' : v[0] === 'bad' ? 'stBad' : 'stWarn'));
    var st = el('div', 'g-main');
    st.appendChild(el('b', null, v[1]));
    st.appendChild(el('span', 'g-sub', v[2]));
    sum.appendChild(st);
    body.appendChild(sum);

    var urlRow = el('button', 'g-row');
    urlRow.type = 'button';
    var urlMain = el('div', 'g-main', 'Webhook 地址');
    urlMain.appendChild(el('span', 'g-sub g-mono', c.webhookUrl));
    urlRow.appendChild(urlMain);
    urlRow.appendChild(el('span', 'g-value g-action', '拷贝'));
    urlRow.addEventListener('click', function () { copyText(c.webhookUrl, '已拷贝地址'); });
    gSection(body, '配置', [
      varRow(c.apiKey === 'ok' ? 'stOk' : c.apiKey === 'missing' ? 'stBad' : 'stWarn', 'API Key', 'RESEND_API_KEY', c.apiKey === 'ok' ? '已设置' : c.apiKey === 'missing' ? '未设置' : '格式不对'),
      varRow(c.webhookSecret === 'ok' ? 'stOk' : 'stBad', 'Webhook 签名密钥', 'RESEND_WEBHOOK_SECRET', c.webhookSecret === 'ok' ? '格式正确' : c.webhookSecret === 'missing' ? '未设置' : '格式不对'),
      varRow(null, '收件地址过滤', 'INBOX', c.inbox || '不限'),
      varRow(null, '时区', 'TZ_OFFSET', c.tz),
      urlRow
    ], '在 Resend → Webhooks 添加这个地址，事件勾选 email.received。');

    var inbox = [];
    if (!r) inbox.push(gRow('stBad', '无法读取', '没有设置 RESEND_API_KEY'));
    else if (!r.ok) inbox.push(gRow('stBad', '读取失败', r.error));
    else if (!r.emails.length) inbox.push(gRow('stWarn', 'Resend 还没有收到任何邮件', '检查域名收信设置和 MX 记录'));
    else r.emails.forEach(function (e) {
      var st = !e.allowed || e.state === 'deleted' ? 'stIdle' : e.state === 'stored' ? 'stOk' : 'stBad';
      var state = !e.allowed ? '已跳过' : { stored: '已入库', deleted: '已删除', missing: '未入库' }[e.state];
      inbox.push(gRow(st, e.subject || '（无主题）', e.to + (e.at ? ' · ' + stamp(e.at) : ''), state));
    });
    if (r && r.ok) {
      var imp = el('button', 'g-row g-action', '从 Resend 导入');
      imp.type = 'button';
      imp.addEventListener('click', function () {
        imp.disabled = true; imp.textContent = '正在导入…';
        var total = 0, rounds = 0, errors = [];
        // 一次请求最多补 25 封，没补完（more）就接着要
        (function step() {
          api('/api/import', { force: true }).then(function (res) {
            if (!res.ok) { done(res.error); return; }
            total += res.imported || 0;
            errors = errors.concat(res.errors || []);
            imp.textContent = '正在导入…（已导入 ' + total + ' 条）';
            if (res.more && (res.imported || !errors.length) && ++rounds < 40) step();
            else done();
          }, function (err) { done(err.message); });
        })();
        function done(failure) {
          if (failure) toast('导入失败', failure, true);
          else if (total) toast('已导入 ' + total + ' 条', errors[0] || '');
          else if (errors.length) toast('导入失败', errors[0], true);
          else toast('没有需要导入的邮件');
          refreshSoon();
          load();
        }
      });
      inbox.push(imp);
    }
    gSection(body, 'Resend 收件箱（最近 10 封）', inbox, '「未入库」表示 Resend 收到了，但 Webhook 没有成功送达。');

    var setup = d.setup;
    if (setup) {
      var rows = [];
      if (!setup.webhooks.ok) rows.push(gRow('stBad', 'Webhooks 读取失败', setup.webhooks.error));
      else if (!setup.webhooks.items.length) rows.push(gRow('stBad', '还没有创建 Webhook', null));
      else setup.webhooks.items.forEach(function (x) {
        var subscribed = !x.events || x.events.indexOf('email.received') >= 0;
        var good = x.matches && x.status === 'enabled' && subscribed;
        var note = x.status !== 'enabled' ? '已停用' : !subscribed ? '未勾选 email.received' : !x.matches ? '不是这个网址' : '正常';
        var row = gRow(good ? 'stOk' : x.matches ? 'stBad' : 'stIdle', 'Webhook', null, note);
        row.querySelector('.g-main').appendChild(el('span', 'g-sub g-mono', x.endpoint));
        rows.push(row);
      });
      if (!setup.domains.ok) rows.push(gRow('stBad', '域名读取失败', setup.domains.error));
      else if (!setup.domains.items.length) rows.push(gRow('stBad', '还没有添加域名', null));
      else setup.domains.items.forEach(function (x) {
        var on = x.receiving === 'enabled';
        var mxOk = x.mxRecord && x.mxRecord.status === 'verified';
        var dns = x.dns == null ? 'MX 查询失败' : x.dns.length ? 'MX → ' + x.dns.map(function (m) { return m.priority + ' ' + m.host; }).join('，') : '没有 MX 记录';
        var sub = (on ? '收件地址：…@' + x.name + ' · ' : '') + (x.mxRecord ? '收信记录 ' + x.mxRecord.status + ' · ' : '') + dns;
        rows.push(gRow(!on ? 'stIdle' : mxOk ? 'stOk' : 'stWarn', x.name, sub, on ? '收信已开启' : '未开启收信'));
      });
      gSection(body, 'Resend 设置', rows, '只有开启收信、MX 指向 Resend 的域名才能收到邮件。');
    }

    var hooks = w.length ? w.map(function (x) {
      var code = el('span', 'g-code', String(x.status));
      var row = gRow(null, RESULT_TEXT[x.result] || x.result, (x.detail ? (DETAIL_TEXT[x.detail] || x.detail) + ' · ' : '') + stamp(x.at));
      row.insertBefore(code, row.firstChild);
      return row;
    }) : [gRow('stIdle', '还没有收到过 Webhook 请求', '检查 Resend 里的 Webhook 地址和事件')];
    gSection(body, 'Webhook 请求（最近 20 次）', hooks);
  }
  load();
}
$('emptyDiag').addEventListener('click', openDiagnostics);

/* ---------- keyboard ---------- */
document.addEventListener('keydown', function (e) {
  if (e.key === 'Escape') {
    if (menu) { closeMenu(); return; }
    if (document.activeElement === searchInput) { cancelSearch(); return; }
    if (S.threadShown && !isSplit()) goBack();
    return;
  }
  var typing = /^(INPUT|TEXTAREA)$/.test((document.activeElement || {}).tagName || '');
  if (!typing && !menu && (e.key === '/' || (e.key === 'f' && (e.metaKey || e.ctrlKey)))) {
    e.preventDefault();
    if (S.threadShown && !isSplit()) goBack();
    searchInput.focus();
  }
});

/* ---------- sync ---------- */
var pollTimer = 0, refreshing = null;
function refresh() {
  if (refreshing) return refreshing;
  refreshing = api('/api/threads').then(function (r) {
    S.version = r.version; S.threads = r.threads; S.latestCode = r.latestCode;
    S.skew = r.now - Date.now(); S.loaded = true;
    renderThreads();
    renderCodeCard();
    if (S.current) { renderThreadHeader(); return syncThread(); }
  }).then(function () { refreshing = null; }, function (err) { refreshing = null; throw err; });
  return refreshing;
}
function refreshSoon() { refresh().catch(noop); }
function poll() {
  clearTimeout(pollTimer);
  if (document.visibilityState !== 'visible') return;
  api('/api/version').then(function (r) {
    if (r.version !== S.version) return refresh();
  }).catch(noop).then(function () { pollTimer = setTimeout(poll, POLL_MS); });
}
// Webhook 漏掉的邮件：打开页面时向 Resend 补拉一次（服务端限流）
function autoImport() {
  api('/api/import', {}).then(function (r) { if (r.imported) refreshSoon(); }, noop);
}
document.addEventListener('visibilitychange', function () {
  if (document.visibilityState === 'visible') { poll(); maybeMarkRead(); autoImport(); }
  else clearTimeout(pollTimer);
});

/* ---------- boot ---------- */
applyLayout();
refresh().then(function () {
  var sender = senderFromHash();
  if (sender) {
    if (!isSplit()) { history.replaceState(null, '', '#/'); history.pushState({ t: sender }, '', threadUrl(sender)); S.pushed = true; }
    openThread(sender, { history: false, animate: false });
  }
}, noop).then(function () { pollTimer = setTimeout(poll, POLL_MS); autoImport(); });
})();
`;

/* ------------------------------------------------------------------ */
/* Static assets                                                       */
/* ------------------------------------------------------------------ */

const ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 180 180"><defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#6AF57E"/><stop offset="1" stop-color="#0FBE30"/></linearGradient></defs><rect width="180" height="180" rx="40" fill="url(#g)"/><path fill="#fff" d="M90 35c-34.2 0-62 22.8-62 51 0 16.3 9.3 30.8 23.8 40.1-1.6 7.2-5.9 14.3-11.9 19.3 10.3.2 21.6-3.6 29.4-9.9 6.6 1.6 13.6 2.5 20.7 2.5 34.2 0 62-22.8 62-51S124.2 35 90 35Z"/></svg>`;

const APPLE_TOUCH_ICON_B64 = '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';

// 供单元测试使用（Worker 运行时只使用 default 导出）
export { parseSms, parseSmsTime, extractCode, messageFromEmail, verifyWebhookSignature, webhookSignatureProblem, webhookSecretState, recipientAllowed, normalizeSender, htmlToText, secret };
