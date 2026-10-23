import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import {
  parseSms,
  parseSmsTime,
  extractCode,
  messageFromEmail,
  verifyWebhookSignature,
  webhookSignatureProblem,
  webhookSecretState,
  recipientAllowed,
  normalizeSender,
  htmlToText,
  secret,
} from '../worker.js';

const CN = 480; // +08:00
const NOW = Date.UTC(2026, 9, 22, 12, 30); // 2026-10-22 20:30 +08:00
const at = (y, mo, d, h, mi) => Date.UTC(y, mo - 1, d, h - 8, mi); // wall clock in +08:00 → epoch

test('parses the documented 内容/发件人/时间 format', () => {
  const raw =
    '【招商银行】您账户8578于10月14日16:26在PP*1035CODE\\89 Neil Road, #03-01\\4029357完成扣款人民币13.05（交易预授权时间10月11日23:49）/+8615710653301/2026年10月22日 下午8:22';
  const r = parseSms(raw, CN, NOW);
  assert.equal(r.sender, '+8615710653301');
  assert.equal(r.sentAt, at(2026, 10, 22, 20, 22));
  assert.equal(r.rawTime, '2026年10月22日 下午8:22');
  assert.ok(r.body.startsWith('【招商银行】您账户8578'));
  assert.ok(r.body.endsWith('23:49）'));
  assert.ok(r.body.includes('\\89 Neil Road'));
});

test('content may itself contain slashes and newlines', () => {
  const r = parseSms('第一行 a/b/c\n见 https://x.cn/p/1\n/95555/2026年10月22日 上午9:05', CN, NOW);
  assert.equal(r.sender, '95555');
  assert.equal(r.body, '第一行 a/b/c\n见 https://x.cn/p/1');
  assert.equal(r.sentAt, at(2026, 10, 22, 9, 5));
});

test('time formats', () => {
  assert.equal(parseSmsTime('2026年10月22日 下午8:22', CN, NOW), at(2026, 10, 22, 20, 22));
  assert.equal(parseSmsTime('2026年10月22日 上午12:05', CN, NOW), at(2026, 10, 22, 0, 5));
  assert.equal(parseSmsTime('2026年10月22日 中午12:30', CN, NOW), at(2026, 10, 22, 12, 30));
  assert.equal(parseSmsTime('2026年10月22日 凌晨1:10', CN, NOW), at(2026, 10, 22, 1, 10));
  assert.equal(parseSmsTime('2026-10-22 20:22:15', CN, NOW), at(2026, 10, 22, 20, 22) + 15000);
  assert.equal(parseSmsTime('2026/10/22 20:22', CN, NOW), at(2026, 10, 22, 20, 22));
  assert.equal(parseSmsTime('2026-10-22T20:22:00+09:00', CN, NOW), Date.UTC(2026, 9, 22, 11, 22));
  assert.equal(parseSmsTime('10月22日 20:22', CN, NOW), at(2026, 10, 22, 20, 22));
  assert.equal(parseSmsTime('12月30日 20:22', CN, NOW), at(2025, 12, 30, 20, 22), 'year-less future date → last year');
  assert.equal(parseSmsTime('1792672920000', CN, NOW), 1792672920000);
  assert.equal(parseSmsTime('2026年2月31日 10:00', CN, NOW), null);
  assert.equal(parseSmsTime('+8615710653301', CN, NOW), null);
  assert.equal(parseSmsTime('明天见', CN, NOW), null);
});

test('time containing slashes is split correctly', () => {
  const r = parseSms('验证码 123456/10690000/2026/10/22 20:22', CN, NOW);
  assert.equal(r.sender, '10690000');
  assert.equal(r.body, '验证码 123456');
  assert.equal(r.sentAt, at(2026, 10, 22, 20, 22));
});

test('unparseable text returns null', () => {
  assert.equal(parseSms('just some text', CN, NOW), null);
  assert.equal(parseSms('no/time/here', CN, NOW), null);
  assert.equal(parseSms('/95555/2026年10月22日 下午8:22', CN, NOW), null);
});

test('normalizes Chinese mobile numbers', () => {
  assert.equal(normalizeSender('15710653301'), '+8615710653301');
  assert.equal(normalizeSender('+86 157-1065-3301'), '+8615710653301');
  assert.equal(normalizeSender('008615710653301'), '+8615710653301');
  assert.equal(normalizeSender('95555'), '95555');
  assert.equal(normalizeSender(' 招商银行 '), '招商银行');
});

test('verification code extraction', () => {
  const cases = [
    ['【京东】验证码：482910，您正在登录京东账号，5分钟内有效。', '482910'],
    ['【支付宝】校验码 731905，你正在使用支付宝付款', '731905'],
    ['731905是您的动态密码，请勿泄露', '731905'],
    ["Your Apple Account code is: 662817. Don't share it.", '662817'],
    ['G-482910 is your Google verification code.', '482910'],
    ['【Steam】您的 Steam 令牌验证码为 R7KQ2，请在 Steam 中输入。', 'R7KQ2'],
    ['【菜鸟驿站】您的包裹已到站，取件码 8-3-2041，请凭码领取', '8-3-2041'],
    ['【某银行】您尾号8578的卡验证码为 553201，金额100.00元', '553201'],
    ['【招商银行】您账户8578于10月14日16:26完成扣款人民币13.05', null],
    ['【中国移动】您本月话费账单已出，详询10086。', null],
    ['验证码将于2026年过期', null],
  ];
  for (const [text, expected] of cases) assert.equal(extractCode(text), expected, text);
});

test('messageFromEmail: text body, html fallback, subject fallback, trailing signature', () => {
  const r1 = messageFromEmail({ text: '【京东】验证码：482910/1069021112345/2026年10月22日 下午8:22\n\n-- \n发自我的手机' }, CN, NOW);
  assert.equal(r1.sender, '1069021112345');
  assert.equal(r1.code, '482910');

  const r2 = messageFromEmail({ text: null, html: '<div>【中国移动】话费账单&amp;详单</div><div>/10086/2026年10月21日 下午4:29</div>' }, CN, NOW);
  assert.equal(r2.sender, '10086');
  assert.equal(r2.body, '【中国移动】话费账单&详单');

  const r3 = messageFromEmail({ text: '', subject: '你好/95555/2026年10月22日 下午8:22' }, CN, NOW);
  assert.equal(r3.sender, '95555');

  const r4 = messageFromEmail({ text: '格式不对的内容', from: 'Phone <p@example.com>', created_at: '2026-10-22T12:00:00Z' }, CN, NOW);
  assert.equal(r4.sender, 'Phone');
  assert.equal(r4.body, '格式不对的内容');
  assert.equal(r4.sentAt, Date.parse('2026-10-22T12:00:00Z'));
});

test('htmlToText decodes entities and keeps line breaks', () => {
  assert.equal(htmlToText('<p>a&lt;b&gt;</p><br>c&#x4e2d;&#25991;'), 'a<b>\n\nc中文');
});

test('recipient filter', () => {
  const data = { to: ['"Me" <0901@cuven.us>'], received_for: ['0901@cuven.us'] };
  assert.equal(recipientAllowed('', data), true);
  assert.equal(recipientAllowed('0901@cuven.us', data), true);
  assert.equal(recipientAllowed('other@cuven.us, 0901@CUVEN.us', data), true);
  assert.equal(recipientAllowed('@cuven.us', data), true);
  assert.equal(recipientAllowed('@0901.cuven.us', data), false);
  assert.equal(recipientAllowed('cuven.us', data), true, 'bare domain rule');
  assert.equal(recipientAllowed('0901.cuven.us', data), false, 'subdomain is a different domain');
  assert.equal(recipientAllowed('0901.cuven.us', { to: ['a@0901.cuven.us'] }), true);
  assert.equal(recipientAllowed('someone@cuven.us', data), false);
});

test('Resend (Svix) webhook signature verification', async () => {
  const key = crypto.randomBytes(24);
  const secret = 'whsec_' + key.toString('base64');
  const body = JSON.stringify({ type: 'email.received', data: { email_id: 'abc' } });
  const id = 'msg_1';
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = crypto.createHmac('sha256', key).update(`${id}.${ts}.${body}`).digest('base64');
  const headers = (s, t = ts) => new Headers({ 'svix-id': id, 'svix-timestamp': t, 'svix-signature': s });

  assert.equal(await verifyWebhookSignature(body, headers(`v1,${sig}`), secret), true);
  assert.equal(await verifyWebhookSignature(body, headers(`v1,old v1,${sig}`), secret), true, 'multiple signatures');
  assert.equal(await verifyWebhookSignature(body + ' ', headers(`v1,${sig}`), secret), false, 'tampered body');
  assert.equal(await verifyWebhookSignature(body, headers(`v1,${sig}`, String(Number(ts) - 3600)), secret), false, 'stale timestamp');
  assert.equal(await verifyWebhookSignature(body, new Headers(), secret), false, 'missing headers');
});

test('webhook signature failures are classified for diagnostics', async () => {
  const key = crypto.randomBytes(24);
  const secret = 'whsec_' + key.toString('base64');
  const body = '{"type":"email.received"}';
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = 'v1,' + crypto.createHmac('sha256', key).update(`m.${ts}.${body}`).digest('base64');
  const h = (t = ts, s = sig) => new Headers({ 'svix-id': 'm', 'svix-timestamp': t, 'svix-signature': s });

  assert.equal(await webhookSignatureProblem(body, h(), secret), '');
  assert.equal(await webhookSignatureProblem(body, h(), ` ${secret}\n`), '', 'pasted secret with whitespace');
  assert.equal(await webhookSignatureProblem(body, new Headers(), secret), 'missing_headers');
  assert.equal(await webhookSignatureProblem(body, h(String(Number(ts) - 600)), secret), 'stale_timestamp');
  assert.equal(await webhookSignatureProblem(body, h(), 'whsec_' + crypto.randomBytes(24).toString('base64')), 'signature_mismatch');
  assert.equal(await webhookSignatureProblem(body, h(), 'whsec_###'), 'secret_not_base64');

  assert.equal(webhookSecretState(secret), 'ok');
  assert.equal(webhookSecretState(''), 'missing');
  assert.equal(webhookSecretState('whsec_abc'), 'format');
});

test('secrets pasted with whitespace or quotes are normalized', () => {
  assert.equal(secret({ K: '  re_abc\n' }, 'K'), 're_abc');
  assert.equal(secret({ K: '"whsec_x+/="' }, 'K'), 'whsec_x+/=');
  assert.equal(secret({ K: " 're_abc' " }, 'K'), 're_abc');
  assert.equal(secret({}, 'K'), '');
});

// 诊断页的判断逻辑在前端字符串里，这里直接取出来跑
function loadVerdict() {
  const src = fs.readFileSync(new URL('../worker.js', import.meta.url), 'utf8');
  const start = src.indexOf('var RESULT_TEXT = {');
  const fn = src.indexOf('function verdict(d) {');
  const end = src.indexOf('\n}\n', fn) + 2;
  const body = src.slice(start, src.indexOf('function stamp', start)) + src.slice(fn, end);
  return new Function(`${body}; return verdict;`)();
}

test('diagnostics verdict trusts delivery evidence over setup heuristics', () => {
  const verdict = loadVerdict();
  const base = { config: { apiKey: 'ok', webhookSecret: 'ok', inbox: '', webhookUrl: 'https://x/webhooks/resend' }, messages: 3 };
  const stored = { ...base, resend: { ok: true, emails: [{ allowed: true, state: 'stored', to: 'a@x' }] }, webhooks: [{ result: 'stored' }] };
  // 收信域名列表为空（比如用的是 *.resend.app）但邮件已入库 → 正常
  assert.equal(verdict({ ...stored, setup: { webhooks: { ok: true, items: [] }, domains: { ok: true, items: [] } } })[0], 'ok');
  // 最新的已入库、较早的漏了 → 提示导入，而不是报错
  const older = { ...base, resend: { ok: true, emails: [{ allowed: true, state: 'stored' }, { allowed: true, state: 'missing' }] }, webhooks: [] };
  assert.deepEqual(verdict(older).slice(0, 1), ['warn']);
  // 最新的没入库 + Webhook 被停用 → 报 Webhook 已被停用
  const disabled = { ...base, resend: { ok: true, emails: [{ allowed: true, state: 'missing', to: 'a@x' }] }, webhooks: [],
    setup: { webhooks: { ok: true, items: [{ matches: true, status: 'disabled', events: ['email.received'] }] }, domains: { ok: true, items: [] } } };
  assert.equal(verdict(disabled)[1], 'Webhook 已被停用');
  // Resend 一封都没收到 + 没有开启收信的域名
  const none = { ...base, resend: { ok: true, emails: [] }, webhooks: [],
    setup: { webhooks: { ok: true, items: [{ matches: true, status: 'enabled', events: null }] }, domains: { ok: true, items: [{ name: 'cuven.us', receiving: 'disabled' }] } } };
  assert.equal(verdict(none)[1], '没有开启收信的域名');
  // 读不到收件箱
  assert.equal(verdict({ ...base, resend: { ok: false, error: '401 restricted_api_key' }, webhooks: [] })[0], 'bad');
  // 最新一次是签名失败，且没有入库证据
  const sig = { ...base, resend: { ok: true, emails: [{ allowed: true, state: 'missing', to: 'a@x' }] }, webhooks: [{ result: 'invalid_signature', detail: 'signature_mismatch' }], setup: null };
  assert.equal(verdict(sig)[1], 'Webhook 签名校验失败');
});
