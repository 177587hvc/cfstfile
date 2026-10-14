// =====================================================================
// filehub - 中科云 S3 文件分发系统 (Cloudflare Worker)
// 架构：浏览器 --分片--> Worker --SigV4签名转发--> s3.cstcloud.cn
//       下载：分享链接 -> Worker 代理(Range透传) -> 中科云
// 特性：5.1MB分片突破100MB限制 / 并发5 / 断点续传 / HMAC限时分享链接
// Secrets: S3_AK / S3_SK / S3_BUCKET / ADMIN_TOKEN / SHARE_SECRET
// Vars(可选): S3_ENDPOINT(默认s3.cstcloud.cn) / S3_REGION(默认cn-north-1)
// =====================================================================

const VERSION = 'v4.15';                       // 版本号（页脚显示；改动时同步 +1）
const DEFAULT_ENDPOINT = 's3.cstcloud.cn';
const DEFAULT_REGION = 'cn-north-1';
const CHUNK_SIZE = 5.1 * 1024 * 1024;        // 5.1MB/片（>S3单片5MB下限，留余量）
const MAX_PARTS = 9000;                       // S3上限10000，留余量
const MAX_FILE = 20 * 1024 * 1024 * 1024;    // 单文件上限 20GB（受免费额度约束）
const QUOTA = 20 * 1024 * 1024 * 1024;        // 中科云免费总额度 20GB（所有桶共享）

// ---------------- SigV4 (Web Crypto) ----------------
const TE = new TextEncoder();
function hex(buf) { return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join(''); }
async function sha256Hex(data) {
  const buf = typeof data === 'string' ? TE.encode(data) : data;
  return hex(await crypto.subtle.digest('SHA-256', buf));
}
async function hmac(keyBytes, data) {
  const k = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, typeof data === 'string' ? TE.encode(data) : data));
}
async function s3Fetch(env, method, rawKeyPath, query, opts) {
  opts = opts || {};
  const endpoint = env.S3_ENDPOINT || DEFAULT_ENDPOINT;
  const region = env.S3_REGION || DEFAULT_REGION;
  const bucket = opts.bucket || env.S3_BUCKET;
  const host = endpoint.startsWith('http') ? new URL(endpoint).host : endpoint;
  const proto = endpoint.startsWith('http://') ? (endpoint.startsWith('https://') ? 'https:' : 'http:') : 'https:';
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const EMPTY_SHA = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'; // 空 body 的 SHA-256
  const payloadHash = opts.payloadHash || (opts.body ? 'UNSIGNED-PAYLOAD' : EMPTY_SHA);
  // canonical URI: root 模式为 /，否则 path-style /bucket/key，每段 RFC3986 编码（key 为原始未编码文本）
  const segs = opts.root ? '/' : ('/' + bucket + '/' + rawKeyPath).split('/').map(s => encodeURIComponent(s)).join('/');
  const qs = Object.entries(query || {}).filter(([k, v]) => v !== undefined).sort().map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(String(v))).join('&');
  const headers = { 'host': host, 'x-amz-date': amzDate, 'x-amz-content-sha256': payloadHash };
  if (opts.contentType) headers['content-type'] = opts.contentType;
  if (opts.contentLength != null) headers['content-length'] = String(opts.contentLength);
  const hkeys = Object.keys(headers).sort();
  const canonicalHeaders = hkeys.map(k => k + ':' + headers[k] + '\n').join('');
  const signedHeaders = hkeys.join(';');
  const canonicalRequest = [method, segs, qs, canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const scope = dateStamp + '/' + region + '/s3/aws4_request';
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, await sha256Hex(canonicalRequest)].join('\n');
  let sk = await hmac(TE.encode('AWS4' + env.S3_SK), dateStamp);
  sk = await hmac(sk, region); sk = await hmac(sk, 's3'); sk = await hmac(sk, 'aws4_request');
  const signature = hex(await hmac(sk, stringToSign));
  const auth = 'AWS4-HMAC-SHA256 Credential=' + env.S3_AK + '/' + scope + ', SignedHeaders=' + signedHeaders + ', Signature=' + signature;
  const url = proto + '//' + host + segs + (qs ? '?' + qs : '');
  const sendHeaders = { ...headers, 'authorization': auth, ...(opts.extraHeaders || {}) };
  return fetch(url, { method, headers: sendHeaders, body: opts.body || undefined });
}

// ---------------- 工具 ----------------
function json(status, obj) { return new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json; charset=utf-8' } }); }
function xmlUnescape(s) { return s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&'); }
function safeName(name) {
  return String(name).replace(/[\r\n\t\0\\/]/g, '_').replace(/\.{2,}/g, '.').replace(/[<>:"|?*]/g, '_').replace(/\(/g, '（').replace(/\)/g, '）').slice(0, 180) || 'unnamed';
}
function randId(n) { const b = crypto.getRandomValues(new Uint8Array(n)); return [...b].map(x => x.toString(16).padStart(2, '0')).join('').slice(0, n * 2); }
function buildKey(name) {
  const d = new Date();
  const ym = d.getFullYear() + String(d.getMonth() + 1).padStart(2, '0');
  return 'files/' + ym + '/' + randId(4) + '-' + safeName(name);
}
function decodeKeyPath(segs) { return segs.map(s => { try { return decodeURIComponent(s); } catch { return s; } }).join('/'); }
async function shareSig(env, key, exp) {
  return hex(await hmac(TE.encode(env.SHARE_SECRET), 'dl|' + key + '|' + exp)).slice(0, 32);
}
const INLINE_MIME = /^(image\/|video\/|audio\/|text\/|application\/pdf$)/;
function guessMime(name, provided) {
  if (provided && provided !== 'application/octet-stream' && provided !== '') return provided;
  const ext = ((name.match(/\.([a-z0-9]+)$/i) || [])[1] || '').toLowerCase();
  const map = { pdf: 'application/pdf', zip: 'application/zip', '7z': 'application/x-7z-compressed', rar: 'application/vnd.rar', doc: 'application/msword', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', xls: 'application/vnd.ms-excel', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', ppt: 'application/vnd.ms-powerpoint', pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation', mp4: 'video/mp4', mkv: 'video/x-matroska', mov: 'video/quicktime', mp3: 'audio/mpeg', wav: 'audio/wav', jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif', webp: 'image/webp', txt: 'text/plain; charset=utf-8', csv: 'text/csv; charset=utf-8', json: 'application/json' };
  return (ext && map[ext]) || 'application/octet-stream';
}
function fmtG(b) { return b >= 1024 * 1024 * 1024 ? (b / 1024 / 1024 / 1024).toFixed(2) + 'GB' : (b / 1024 / 1024).toFixed(1) + 'MB'; }
async function accountUsage(env) {
  // 实时统计：ListBuckets 列出账号下所有桶，逐桶累加（不缓存，保证跨实例准确）
  try {
    const r = await s3Fetch(env, 'GET', '', null, { root: true });
    if (r.status !== 200) return -1;
    const t = await r.text();
    const buckets = [];
    const re = /<Bucket>([\s\S]*?)<\/Bucket>/g;
    let m;
    while ((m = re.exec(t)) !== null) {
      const nm = m[1].match(/<Name>([^<]+)<\/Name>/);
      if (nm) buckets.push(nm[1]);
    }
    let total = 0;
    for (const b of buckets) {
      let token = null, pages = 0;
      do {
        const q = { 'list-type': '2', 'max-keys': '1000' };
        if (token) q['continuation-token'] = token;
        const br = await s3Fetch(env, 'GET', '', q, { bucket: b });
        if (br.status !== 200) break;
        const bt = await br.text();
        const cre = /<Contents>([\s\S]*?)<\/Contents>/g;
        let cm;
        while ((cm = cre.exec(bt)) !== null) {
          const sm = cm[1].match(/<Size>(\d+)<\/Size>/);
          total += Number(sm ? sm[1] : 0);
        }
        token = (bt.match(/<NextContinuationToken>([^<]+)<\/NextContinuationToken>/) || [])[1] || null;
        pages++;
      } while (token && pages < 10);
    }
    return total;
  } catch { return -1; }
}
let __usageCacheT = 0; let __usageCacheV = -1;
async function usageCached(env) {
  const now = Date.now();
  if (now - __usageCacheT < 60000 && __usageCacheV >= 0) return __usageCacheV;
  const v = await accountUsage(env);
  if (v >= 0) { __usageCacheT = now; __usageCacheV = v; return v; }
  return (__usageCacheV >= 0) ? __usageCacheV : v;
}
// ---------------- UA 解析 + D1 ----------------
function parseUA(ua) {
  ua = ua || '';
  let os = '未知';
  if (/Windows NT 10/.test(ua)) os = 'Windows';
  else if (/Windows NT/.test(ua)) os = 'Windows(旧)';
  else if (/iPhone|iPad|iPod/.test(ua)) os = 'iOS';
  else if (/Android/.test(ua)) os = 'Android';
  else if (/Mac OS X|Macintosh/.test(ua)) os = 'macOS';
  else if (/Linux/.test(ua)) os = 'Linux';
  let browser = '未知';
  if (/Edg\//.test(ua)) browser = 'Edge';
  else if (/Chrome\//.test(ua) && !/Chromium\//.test(ua)) browser = 'Chrome';
  else if (/Firefox\//.test(ua)) browser = 'Firefox';
  else if (/Safari\//.test(ua) && !/Chrome\//.test(ua)) browser = 'Safari';
  else if (/Chromium\//.test(ua)) browser = 'Chromium';
  return { os, browser };
}
async function ensureDB(env) {
  if (!env.DB) return;
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS uploads (file_key TEXT PRIMARY KEY, ip TEXT, os TEXT, browser TEXT, ua TEXT, upload_time TEXT)').run();
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS downloads (id INTEGER PRIMARY KEY AUTOINCREMENT, file_key TEXT, ip TEXT, os TEXT, browser TEXT, ua TEXT, dl_time TEXT)').run();
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_dl_key ON downloads(file_key)').run();
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, file_name TEXT, action TEXT, ip TEXT, os TEXT, browser TEXT, ua TEXT, log_time TEXT)').run();
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS shares (code TEXT PRIMARY KEY, file_key TEXT, expire INTEGER, days INTEGER)').run();
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS hashes (hash TEXT PRIMARY KEY, file_key TEXT, size INTEGER, file_name TEXT, hash_time TEXT)').run();
  // 虚拟目录：文件在 S3 上永不搬家，目录归属与显示名只记在这两张表
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS file_meta (file_key TEXT PRIMARY KEY, path TEXT, name TEXT, updated TEXT)').run();
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS folders (path TEXT PRIMARY KEY, name TEXT, created TEXT)').run();
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_meta_path ON file_meta(path)').run();
  try { await env.DB.prepare('ALTER TABLE shares ADD COLUMN days INTEGER').run(); } catch (e) {}
  try { await env.DB.prepare('ALTER TABLE shares ADD COLUMN kind TEXT').run(); } catch (e) {} // 'file' | 'dir'
  try { await env.DB.prepare('CREATE TABLE IF NOT EXISTS share_batches (code TEXT PRIMARY KEY, expire INTEGER, created TEXT)').run(); } catch (e) {}
  try { await env.DB.prepare('CREATE TABLE IF NOT EXISTS share_batch_items (batch_code TEXT, file_code TEXT, file_key TEXT, name TEXT, size INTEGER, days INTEGER, expire INTEGER)').run(); } catch (e) {}
  // (file_key, days) 唯一索引：① 复制链接查询走索引不再全表扫 ② 同文件+同时长强制唯一，并发也不会重复生成
  await env.DB.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_shares_key_days ON shares(file_key, days)').run();
}

// ---------------- DPI 拦截识别 ----------------
// 运营商审查设备劫持回源链路时返回 405 + attack.jinxibei.com 攻击页，与 S3 真实错误截然不同
async function isDpiBlocked(r) {
  if (r.status !== 405) return false;
  try {
    const t = await r.clone().text();
    return t.includes('attack.jinxibei.com') || (t.includes('<html') && /saved from url/.test(t) && !t.includes('<?xml'));
  } catch { return false; }
}
const DPI_ERR = { error: '文件内容被运营商安全设备拦截（检测到脚本类特征），请将文件压缩成 zip 后重新上传' };

// ---------------- API handlers ----------------
async function handleInit(request, env) {
  const body = await request.json();
  const name = String(body.name || ''), size = Number(body.size || 0);
  if (!name || !Number.isFinite(size)) return json(400, { error: '参数错误' });
  if (size > MAX_FILE) return json(400, { error: '单文件超过20GB上限（中科云免费额度限制）' });
  const used = await accountUsage(env);
  if (used >= 0 && size + used > QUOTA) return json(400, { error: '中科云免费额度共20GB，本系统已用 ' + fmtG(used) + '，放不下此文件（' + fmtG(size) + '），请先删除旧文件' });
  const mime = guessMime(name, body.mime);
  const vDir = normPath(body.dir);
  // 秒传查重：同 SHA-256 直接复用已存在文件（校验 S3 上对象仍在，防删除后误判）
  const hash = String(body.hash || '');
  if (hash.length === 64 && env.DB) {
    try {
      await ensureDB(env);
      const dup = await env.DB.prepare('SELECT file_key, size FROM hashes WHERE hash=?').bind(hash).first();
      if (dup) {
        // 用 Range GET 校验对象存在（中科云对 HEAD 签名返回 401，Range GET 是下载代理已验证可行的路径）
        const head = await s3Fetch(env, 'GET', dup.file_key, {}, { extraHeaders: { range: 'bytes=0-0' } });
        if (head.status === 200 || head.status === 206) { await upsertMeta(env, dup.file_key, vDir, safeName(name)); return json(200, { dup: true, key: dup.file_key, mode: 'dup', size: dup.size }); }
        await env.DB.prepare('DELETE FROM hashes WHERE hash=?').bind(hash).run(); // 对象已删，清理登记
      }
    } catch (e) {}
  }
  let chunkSize = CHUNK_SIZE;
  while (Math.ceil(size / chunkSize) > MAX_PARTS) chunkSize = Math.round(chunkSize * 1.5);
  const partCount = size === 0 ? 0 : Math.ceil(size / chunkSize);
  const mode = partCount <= 1 ? 'direct' : 'mpu';
  if (mode === 'mpu') {
    // 断点续传：复用上次会话（key+uploadId），分片边界由 size 决定，恒一致
    const resume = body.resume || {};
    if (resume.key && resume.uploadId && String(resume.key).startsWith('files/') && String(resume.key).length < 500) {
      return json(200, { key: String(resume.key), uploadId: String(resume.uploadId), chunkSize, partCount, mode });
    }
    const key = buildKey(name);
    await upsertMeta(env, key, vDir, safeName(name));
    const r = await s3Fetch(env, 'POST', key, { uploads: '' }, { contentType: mime });
    if (r.status !== 200) return json(502, { error: '中科云创建上传失败', detail: (await r.text()).slice(0, 200) });
    const t = await r.text();
    const uploadId = (t.match(/<UploadId>([^<]+)<\/UploadId>/) || [])[1];
    if (!uploadId) return json(502, { error: '中科云未返回uploadId' });
    return json(200, { key, uploadId, chunkSize, partCount, mode });
  }
  const dk = buildKey(name);
  await upsertMeta(env, dk, vDir, safeName(name));
  return json(200, { key: dk, mode, partCount, chunkSize });
}

async function handleDirect(request, env, url) {
  const key = url.searchParams.get('key') || '';
  if (!key.startsWith('files/')) return json(400, { error: '非法key' });
  const len = Number(request.headers.get('content-length') || '0');
  if (len > CHUNK_SIZE * 2) return json(413, { error: 'direct模式仅限小文件' });
  const mime = guessMime(key, request.headers.get('x-file-mime') || '');
  const r = await s3Fetch(env, 'PUT', key, {}, { body: request.body, contentLength: len, contentType: mime });
  if (r.status !== 200) {
    if (await isDpiBlocked(r)) return json(502, DPI_ERR);
    return json(502, { error: '上传失败', s3: r.status, detail: (await r.text()).slice(0, 200) });
  }
  const dHash = String(url.searchParams.get('hash') || '');
  try { await ensureDB(env); if (env.DB) { const ua = request.headers.get('user-agent') || ''; const { os, browser } = parseUA(ua); const ip = request.headers.get('CF-Connecting-IP') || ''; await env.DB.prepare('INSERT OR REPLACE INTO uploads (file_key, ip, os, browser, ua, upload_time) VALUES (?,?,?,?,?,?)').bind(key, ip, os, browser, ua, new Date().toISOString()).run(); if (dHash.length === 64) { const fn6=(key.split('/').pop()||'').replace(/^[0-9a-f]{8}-/,''); await env.DB.prepare('INSERT OR REPLACE INTO hashes (hash, file_key, size, file_name, hash_time) VALUES (?,?,?,?,?)').bind(dHash, key, len, fn6, new Date().toISOString()).run(); } } } catch {}
  try { const fn=(key.split('/').pop()||'').replace(/^[0-9a-f]{8}-/,''); const ua2=request.headers.get('user-agent')||''; const{os:os2,browser:br2}=parseUA(ua2); const ip2=request.headers.get('CF-Connecting-IP')||''; await env.DB.prepare('INSERT INTO logs (file_name, action, ip, os, browser, ua, log_time) VALUES (?,?,?,?,?,?,?)').bind(fn, 'upload', ip2, os2, br2, ua2, new Date().toISOString()).run(); } catch {}
  return json(200, { ok: true, key });
}

async function handlePart(request, env, url) {
  const key = url.searchParams.get('key') || '';
  const uploadId = url.searchParams.get('uploadId') || '';
  const partNumber = Number(url.searchParams.get('partNumber') || '0');
  if (!key.startsWith('files/') || !uploadId || !Number.isInteger(partNumber) || partNumber < 1 || partNumber > 10000) return json(400, { error: '参数错误' });
  const len = Number(request.headers.get('content-length') || '0');
  if (len > 100 * 1024 * 1024) return json(413, { error: '分片超过100MB限制' });
  const r = await s3Fetch(env, 'PUT', key, { uploadId, partNumber }, { body: request.body, contentLength: len });
  const etag = r.headers.get('etag');
  if (r.status !== 200 || !etag) {
    if (r.status === 405 && await isDpiBlocked(r)) return json(502, DPI_ERR);
    return json(502, { error: '分片上传失败', s3: r.status, detail: (await r.text()).slice(0, 200) });
  }
  return json(200, { etag });
}

async function handleComplete(request, env) {
  const body = await request.json();
  const { key, uploadId, parts, mode } = body;
  const cHash = String(body.hash || ''); const cSize = Number(body.size || 0);
  if (!key || !String(key).startsWith('files/')) return json(400, { error: '非法key' });
  if (mode === 'direct') return json(200, { ok: true, key });
  if (!uploadId || !Array.isArray(parts) || parts.length === 0) return json(400, { error: '参数错误' });
  const xmlBody = '<CompleteMultipartUpload>' + parts.map(p => '<Part><PartNumber>' + Number(p[0]) + '</PartNumber><ETag>' + String(p[1]).replace(/"/g, '') + '</ETag></Part>').join('') + '</CompleteMultipartUpload>';
  const r = await s3Fetch(env, 'POST', key, { uploadId }, { body: xmlBody, contentType: 'application/xml', payloadHash: await sha256Hex(xmlBody) });
  const t = await r.text();
  if (r.status !== 200 || !/<CompleteMultipartUploadResult/.test(t) || /<Error>/.test(t)) return json(502, { error: '合并失败', s3: r.status, detail: t.slice(0, 250) });
  try { await ensureDB(env); if (env.DB) { const ua = request.headers.get('user-agent') || ''; const { os, browser } = parseUA(ua); const ip = request.headers.get('CF-Connecting-IP') || ''; if (cHash.length === 64) { const fn7=(key.split('/').pop()||'').replace(/^[0-9a-f]{8}-/,''); await env.DB.prepare('INSERT OR REPLACE INTO hashes (hash, file_key, size, file_name, hash_time) VALUES (?,?,?,?,?)').bind(cHash, key, cSize, fn7, new Date().toISOString()).run(); } } } catch {}
  try { const fn2=(key.split('/').pop()||'').replace(/^[0-9a-f]{8}-/,''); const ua3=request.headers.get('user-agent')||''; const{os:os3,browser:br3}=parseUA(ua3); const ip3=request.headers.get('CF-Connecting-IP')||''; await env.DB.prepare('INSERT INTO logs (file_name, action, ip, os, browser, ua, log_time) VALUES (?,?,?,?,?,?,?)').bind(fn2, 'upload', ip3, os3, br3, ua3, new Date().toISOString()).run(); } catch {}
  return json(200, { ok: true, key });
}

async function handleAbort(request, env) {
  const body = await request.json();
  const { key, uploadId } = body;
  if (!key || !uploadId) return json(400, { error: '参数错误' });
  const r = await s3Fetch(env, 'DELETE', key, { uploadId }, {});
  // 上传取消：清掉 init 阶段预先写入的目录登记，避免留下孤儿记录
  try { await ensureDB(env); if (env.DB) await env.DB.prepare('DELETE FROM file_meta WHERE file_key=?').bind(key).run(); } catch (e) {}
  return json(200, { ok: true, status: r.status });
}

// ---------------- 虚拟目录 ----------------
// 约定：path 以 / 结尾，根目录为空字符串 ''，子目录形如 'A/' 'A/B/'
function normPath(p) {
  let s = String(p == null ? '' : p);
  s = s.replace(/^\/+/, '').replace(/\/+$/, '');
  return s ? s + '/' : '';
}
function parentOf(p) {
  const s = normPath(p).replace(/\/$/, '');
  const i = s.lastIndexOf('/');
  return i < 0 ? '' : normPath(s.slice(0, i));
}
function baseOf(key) { const s = String(key).split('/'); return s[s.length - 1] || ''; }
function dispName(base) { return base.replace(/^[0-9a-f]{8}-/, ''); }
async function upsertMeta(env, key, path, name) {
  if (!env.DB) return;
  try {
    const ex = await env.DB.prepare('SELECT 1 FROM file_meta WHERE file_key=?').bind(key).first();
    if (ex) await env.DB.prepare('UPDATE file_meta SET path=?, name=?, updated=? WHERE file_key=?').bind(path, name, new Date().toISOString(), key).run();
    else await env.DB.prepare('INSERT INTO file_meta (file_key, path, name, updated) VALUES (?,?,?,?)').bind(key, path, name, new Date().toISOString()).run();
  } catch (e) {}
}
async function handleMkdir(request, env) {
  await ensureDB(env);
  if (!env.DB) return json(400, { error: '未绑定数据库，用不了文件夹' });
  const body = await request.json().catch(() => ({}));
  const parent = normPath(body.parent);
  const name = safeName(String(body.name == null ? '' : body.name).trim());
  if (!name) return json(400, { error: '文件夹名不能为空' });
  const path = parent + name + '/';
  const ex = await env.DB.prepare('SELECT 1 FROM folders WHERE path=?').bind(path).first();
  if (ex) return json(400, { error: '这个文件夹已经存在了' });
  await env.DB.prepare('INSERT INTO folders (path, name, created) VALUES (?,?,?)').bind(path, name, new Date().toISOString()).run();
  try { const ua = request.headers.get('user-agent') || ''; const { os, browser } = parseUA(ua); const ip = request.headers.get('CF-Connecting-IP') || ''; await env.DB.prepare('INSERT INTO logs (file_name, action, ip, os, browser, ua, log_time) VALUES (?,?,?,?,?,?,?)').bind(name, 'mkdir', ip, os, browser, ua, new Date().toISOString()).run(); } catch (e) {}
  return json(200, { ok: true, path: path, name: name });
}
async function handleRmdir(request, env) {
  await ensureDB(env);
  if (!env.DB) return json(400, { error: '未绑定数据库' });
  const body = await request.json().catch(() => ({}));
  const path = normPath(body.path != null ? body.path : body.key);
  if (!path) return json(400, { error: '根目录不能删' });
  // 用与列表同一套逻辑判断：界面上看着是空的，就得能删
  // （不能只查 file_meta —— 上传中断会留下指向不存在文件的孤儿记录）
  const got = await listFilesAt(env, path);
  if (got.items.length > 0) return json(400, { error: '文件夹里还有文件，先移走或删掉' });
  const hasSub = await env.DB.prepare('SELECT 1 FROM folders WHERE path LIKE ? AND path<>? LIMIT 1').bind(path + '%', path).first();
  if (hasSub) return json(400, { error: '先删掉里面的子文件夹' });
  await env.DB.prepare('DELETE FROM folders WHERE path=?').bind(path).run();
  // 顺带清掉这个目录（含子目录）下可能残留的孤儿记录
  try {
    await env.DB.prepare('DELETE FROM file_meta WHERE path=? OR path LIKE ?').bind(path, path + '%').run();
  } catch (e) {}
  // 目录没了，它的分享链接要一起作废，否则点开是个空壳页
  try {
    await env.DB.prepare('DELETE FROM shares WHERE file_key=? AND kind=?').bind(path, 'dir').run();
    await env.DB.prepare('DELETE FROM shares WHERE file_key LIKE ? AND kind=?').bind(path + '%', 'dir').run();
  } catch (e) {}
  return json(200, { ok: true });
}
async function handleRename(request, env) {
  await ensureDB(env);
  if (!env.DB) return json(400, { error: '未绑定数据库' });
  const body = await request.json().catch(() => ({}));
  // 文件夹重命名：改 folders 自身，并把子文件 / 子文件夹的 path 前缀一起换掉
  if (body.path !== undefined && body.path !== null && String(body.path) !== '') {
    const oldP = normPath(body.path);
    if (!oldP) return json(400, { error: '根目录不能改名' });
    const nn = safeName(String(body.name == null ? '' : body.name).trim());
    if (!nn) return json(400, { error: '名称不能为空' });
    const newP = parentOf(oldP) + nn + '/';
    if (newP === oldP) return json(200, { ok: true, name: nn, path: newP });
    const ex = await env.DB.prepare('SELECT 1 FROM folders WHERE path=?').bind(newP).first();
    if (ex) return json(400, { error: '已经有同名文件夹了' });
    const cut = oldP.length + 1;
    await env.DB.prepare('UPDATE folders SET path=?, name=? WHERE path=?').bind(newP, nn, oldP).run();
    await env.DB.prepare('UPDATE folders SET path = ? || substr(path, ?) WHERE path LIKE ? AND path <> ?').bind(newP, cut, oldP + '%', oldP).run();
    await env.DB.prepare('UPDATE file_meta SET path = ? || substr(path, ?) WHERE path LIKE ?').bind(newP, cut, oldP + '%').run();
    // 分享记录里存的也是目录路径，改名后要跟着换前缀，否则链接指向旧目录变空壳
    try {
      await env.DB.prepare('UPDATE shares SET file_key=? WHERE file_key=? AND kind=?').bind(newP, oldP, 'dir').run();
      await env.DB.prepare('UPDATE shares SET file_key = ? || substr(file_key, ?) WHERE file_key LIKE ? AND kind=?').bind(newP, cut, oldP + '%', 'dir').run();
    } catch (e) {}
    try { const ua = request.headers.get('user-agent') || ''; const { os, browser } = parseUA(ua); const ip = request.headers.get('CF-Connecting-IP') || ''; await env.DB.prepare('INSERT INTO logs (file_name, action, ip, os, browser, ua, log_time) VALUES (?,?,?,?,?,?,?)').bind(nn, 'rename', ip, os, browser, ua, new Date().toISOString()).run(); } catch (e) {}
    return json(200, { ok: true, name: nn, path: newP });
  }
  const key = String(body.key || '');
  const name = String(body.name == null ? '' : body.name).trim();
  if (!key.startsWith('files/')) return json(400, { error: '非法key' });
  if (!name) return json(400, { error: '名称不能为空' });
  const nn = safeName(name);
  const cur = await env.DB.prepare('SELECT path FROM file_meta WHERE file_key=?').bind(key).first();
  const keepPath = cur ? normPath(cur.path) : '';
  await upsertMeta(env, key, keepPath, nn);
  try {
    const ua = request.headers.get('user-agent') || '';
    const { os, browser } = parseUA(ua);
    await env.DB.prepare('INSERT INTO logs (file_name, action, ip, os, browser, ua, log_time) VALUES (?,?,?,?,?,?,?)').bind(nn, 'rename', request.headers.get('CF-Connecting-IP') || '', os, browser, ua, new Date().toISOString()).run();
  } catch (e) {}
  return json(200, { ok: true, name: nn });
}
async function handleMove(request, env) {
  await ensureDB(env);
  if (!env.DB) return json(400, { error: '未绑定数据库' });
  const body = await request.json().catch(() => ({}));
  const keys = Array.isArray(body.keys) ? body.keys : [];
  const dest = normPath(body.dest);
  if (!keys.length) return json(400, { error: '没选文件' });
  let ok = 0, fail = 0;
  const errors = [];
  for (const key of keys) {
    if (typeof key !== 'string' || !key.startsWith('files/')) { fail++; continue; }
    try {
      const cur = await env.DB.prepare('SELECT name FROM file_meta WHERE file_key=?').bind(key).first();
      const nm = (cur && cur.name) ? cur.name : dispName(baseOf(key));
      if (cur) await env.DB.prepare('UPDATE file_meta SET path=?, updated=? WHERE file_key=?').bind(dest, new Date().toISOString(), key).run();
      else await env.DB.prepare('INSERT INTO file_meta (file_key, path, name, updated) VALUES (?,?,?,?)').bind(key, dest, nm, new Date().toISOString()).run();
      ok++;
    } catch (e) { fail++; errors.push(dispName(baseOf(key)) + '：' + String((e && e.message) || e).slice(0, 60)); }
  }
  try {
    const ua = request.headers.get('user-agent') || '';
    const { os, browser } = parseUA(ua);
    await env.DB.prepare('INSERT INTO logs (file_name, action, ip, os, browser, ua, log_time) VALUES (?,?,?,?,?,?,?)').bind(ok + '个文件 → ' + (dest || '根目录'), 'move', request.headers.get('CF-Connecting-IP') || '', os, browser, ua, new Date().toISOString()).run();
  } catch (e) {}
  return json(200, { ok: ok, fail: fail, total: keys.length, errors: errors.slice(0, 5) });
}
async function listFilesAt(env, want) {
  let token = null, raw = [], pages = 0;
  do {
    const q = { 'list-type': '2', 'max-keys': '1000', prefix: 'files/' };
    if (token) q['continuation-token'] = token;
    const r = await s3Fetch(env, 'GET', '', q, {});
    if (r.status !== 200) return { err: '列取失败', s3: r.status, items: [], folders: [], total: 0 };
    const t = await r.text();
    const re = /<Contents>([\s\S]*?)<\/Contents>/g;
    let m;
    while ((m = re.exec(t)) !== null) {
      const km = m[1].match(/<Key>([\s\S]*?)<\/Key>/);
      const sm = m[1].match(/<Size>(\d+)<\/Size>/);
      const lm = m[1].match(/<LastModified>([\s\S]*?)<\/LastModified>/);
      if (!km) continue;
      const key = xmlUnescape(km[1]);
      if (key.endsWith('/')) continue;
      raw.push({ key: key, size: Number(sm ? sm[1] : 0), mtime: lm ? lm[1] : '' });
    }
    token = (t.match(/<NextContinuationToken>([^<]+)<\/NextContinuationToken>/) || [])[1] || null;
    pages++;
  } while (token && pages < 5);
  let metaMap = {}, folderRows = [];
  try {
    await ensureDB(env);
    if (env.DB) {
      const mr = await env.DB.prepare('SELECT file_key, path, name FROM file_meta').all();
      for (const r of (mr.results || [])) metaMap[r.file_key] = r;
      const fr = await env.DB.prepare('SELECT path, name, created FROM folders').all();
      folderRows = fr.results || [];
    }
  } catch (e) {}
  const items = [];
  let total = 0;
  for (const it of raw) {
    const meta = metaMap[it.key];
    const p = meta ? normPath(meta.path) : '';
    if (p !== want) continue;
    const nm = (meta && meta.name) ? meta.name : dispName(baseOf(it.key));
    items.push({ key: it.key, name: nm, size: it.size, mtime: it.mtime });
    total += it.size;
  }
  items.sort((a, b) => (b.mtime || '').localeCompare(a.mtime || ''));
  const folders = folderRows.filter(f => parentOf(f.path) === want)
    .map(f => ({ path: f.path, name: f.name || (normPath(f.path).replace(/\/$/, '').split('/').pop() || ''), created: f.created || '' }))
    .sort((a, b) => String(a.name).localeCompare(String(b.name)));
  return { items: items, folders: folders, total: total };
}

async function handleList(env, url) {
  const want = normPath(url.searchParams.get('path'));
  const got = await listFilesAt(env, want);
  if (got.err) return json(502, { error: got.err, s3: got.s3 });
  const items = got.items, folders = got.folders, total = got.total;
  try { await ensureDB(env); if (env.DB && items.length) { const keys = items.map(i => i.key); const ph = keys.map(() => '?').join(','); const rows = await env.DB.prepare('SELECT file_key, ip, os, browser, upload_time FROM uploads WHERE file_key IN (' + ph + ')').bind(...keys).all(); const umap = {}; for (const r of rows.results) umap[r.file_key] = r; const dlCnt = await env.DB.prepare('SELECT file_key, COUNT(*) as c FROM downloads WHERE file_key IN (' + ph + ') GROUP BY file_key').bind(...keys).all(); const dcnt = {}; for (const r of dlCnt.results) dcnt[r.file_key] = r.c; for (const it of items) { const u = umap[it.key]; if (u) it.uploader = { ip: u.ip, os: u.os, browser: u.browser, time: u.upload_time }; it.dl_count = dcnt[it.key] || 0; } } } catch {}
  return json(200, { items: items.slice(0, 2000), folders: folders, total: total, count: items.length, path: want, db: !!env.DB });
}

// 目录分享页：只列文件，点文件即下载（文件夹本身不支持整体下载）
async function serveDirShare(env, dirPath, url, exp) {
  const want = normPath(dirPath);
  const got = await listFilesAt(env, want);
  const dirName = want.replace(/\/$/, '').split('/').pop() || '文件夹';
  const rows = [];
  for (const it of got.items) {
    const sig = await shareSig(env, it.key, exp);
    const kp = it.key.split('/').map(encodeURIComponent).join('/');
    rows.push('<tr><td class="nm">' + escHtml(it.name) + '</td><td class="sz">' + fmtG(it.size) + '</td>'
      + '<td><a class="dl" href="/f/' + kp + '?e=' + exp + '&amp;s=' + sig + '&amp;dl=1">下载</a></td></tr>');
  }
  const listHtml = rows.length ? rows.join('') : '<tr><td colspan="3" class="empty">这个文件夹现在是空的</td></tr>';
  const html = '<!DOCTYPE html>\n<html lang="zh-CN">\n<head>\n<meta charset="UTF-8">\n'
    + '<meta name="viewport" content="width=device-width, initial-scale=1">\n<title>' + escHtml(dirName) + ' - 文件夹分享</title>\n'
    + '<style>\n*{box-sizing:border-box;margin:0;padding:0}\n'
    + 'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;background:#f0f2f5;color:#1f2329;min-height:100vh}\n'
    + '.wrap{max-width:760px;margin:0 auto;padding:28px 16px}\n'
    + '.card{background:#fff;border-radius:10px;padding:22px;box-shadow:0 1px 3px rgba(0,0,0,.08)}\n'
    + 'h1{font-size:19px;margin-bottom:4px}\n.sub{color:#6b7280;font-size:13px;margin-bottom:16px}\n'
    + 'table{width:100%;border-collapse:collapse;font-size:14px}\n'
    + 'th{background:#f9fafb;text-align:left;padding:10px 8px;font-weight:600;border-bottom:1px solid #e5e7eb}\n'
    + 'td{padding:10px 8px;border-bottom:1px solid #f3f4f6}\ntr:hover td{background:#f9fafb}\n'
    + '.nm{max-width:430px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}\n'
    + '.sz{color:#6b7280;white-space:nowrap}\n.empty{color:#9ca3af;text-align:center;padding:24px 0}\n'
    + '.dl{display:inline-block;padding:5px 14px;border-radius:6px;background:#2563eb;color:#fff;font-size:13px;text-decoration:none}\n'
    + '.dl:hover{background:#1d4ed8}\n'
    + '</style>\n</head>\n<body>\n<div class="wrap">\n  <div class="card">\n'
    + '    <h1>' + escHtml(dirName) + '</h1>\n'
    + '    <div class="sub">共 ' + got.items.length + ' 个文件 · 点文件即可下载</div>\n'
    + '    <table><thead><tr><th>文件名</th><th>大小</th><th>操作</th></tr></thead><tbody>' + listHtml + '</tbody></table>\n'
    + '  </div>\n</div>\n</body>\n</html>';
  return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store, no-cache, must-revalidate, max-age=0' } });
}

async function genCode(env, prefix) {
  const CH = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < 24; i++) {
    const b = crypto.getRandomValues(new Uint8Array(7));
    let s = prefix;
    for (const x of b) s += CH[x % 62];
    const a = await env.DB.prepare('SELECT 1 FROM shares WHERE code=?').bind(s).first();
    const c = await env.DB.prepare('SELECT 1 FROM share_batches WHERE code=?').bind(s).first();
    if (!a && !c) return s;
  }
  return null;
}
async function handleBatchShare(request, env, url) {
  await ensureDB(env);
  if (!env.DB) return json(400, { error: '未绑定数据库' });
  const body = await request.json().catch(() => ({}));
  const items = Array.isArray(body.items) ? body.items : [];
  if (!items.length) return json(400, { error: '没选文件' });
  const now = Math.floor(Date.now() / 1000);
  const rows = [];
  for (const it of items) {
    const key = String(it.key || '');
    if (!key.startsWith('files/')) continue;
    let days = Number(it.days);
    if (!Number.isFinite(days) || days < 0) days = 30;
    const exp = days > 0 ? now + days * 86400 : 0;
    // 幂等：同文件+同时长固定一码；旧码已过期则重写有效期（与单文件分享 v4.13 行为一致）
    let exist = await env.DB.prepare('SELECT code, expire FROM shares WHERE file_key=? AND days=?').bind(key, days).first();
    let code = exist ? exist.code : null;
    if (!code) code = await genCode(env, 'F');
    let effExp = exp;
    if (exist && !(exist.expire && exist.expire < now)) {
      effExp = exist.expire || 0;
    } else {
      try {
        await saveShare(env, code, key, exp, days, 'file');
      } catch (e) {
        const dup = await env.DB.prepare('SELECT code FROM shares WHERE file_key=? AND days=?').bind(key, days).first();
        code = dup ? dup.code : null;
      }
    }
    if (!code) continue;
    let nm = '', sz = 0;
    try { const m = await env.DB.prepare('SELECT name FROM file_meta WHERE file_key=?').bind(key).first(); nm = m ? m.name : ''; } catch (e) {}
    try { const r = await s3Fetch(env, 'GET', key, {}, { extraHeaders: { range: 'bytes=0-0' } }); if (r.status === 206 || r.status === 200) { const cr = r.headers.get('content-range'); if (cr) { const mm = cr.match(/\/(\d+)$/); if (mm) sz = Number(mm[1]); } if (!sz) { const cl = r.headers.get('content-length'); sz = Number(cl || 0); } } } catch (e) {}
    if (!nm) nm = dispName(baseOf(key));
    rows.push({ code: code, key: key, name: nm, size: sz, days: days, expire: effExp });
  }
  if (!rows.length) return json(400, { error: '没有可分享的文件' });
  let maxExp = 0, hasPerm = false;
  for (const r of rows) { if (r.expire === 0) hasPerm = true; else if (r.expire > maxExp) maxExp = r.expire; }
  if (hasPerm) maxExp = 0;
  // 幂等复用：完全相同的文件集合+时长 → 复用已有分享页（顺带刷新各项有效期），不再生成重复记录
  const sig = rows.map(function (r) { return r.key + '|' + Number(r.days); }).sort().join('&');
  let bcode = null;
  try {
    const bs = await env.DB.prepare('SELECT code, expire FROM share_batches').all();
    for (const b of (bs.results || [])) {
      if (b.expire && b.expire < now) continue;
      const bis = await env.DB.prepare('SELECT file_key, days FROM share_batch_items WHERE batch_code=?').bind(b.code).all();
      const bsig = (bis.results || []).map(function (x) { return x.file_key + '|' + Number(x.days); }).sort().join('&');
      if (bsig === sig) { bcode = b.code; break; }
    }
  } catch (e) {}
  if (bcode) {
    for (const r of rows) { try { await env.DB.prepare('UPDATE share_batch_items SET file_code=?, expire=? WHERE batch_code=? AND file_key=?').bind(r.code, r.expire, bcode, r.key).run(); } catch (e) {} }
    try { await env.DB.prepare('UPDATE share_batches SET expire=? WHERE code=?').bind(maxExp, bcode).run(); } catch (e) {}
    return json(200, { link: 'https://' + url.host + '/' + bcode, codes: rows.map(function (x) { return x.code; }), expire: maxExp });
  }
  bcode = await genCode(env, 'S');
  if (!bcode) return json(500, { error: '生成分享页失败' });
  await env.DB.prepare('INSERT INTO share_batches (code, expire, created) VALUES (?,?,?)').bind(bcode, maxExp, new Date().toISOString()).run();
  for (const r of rows) { await env.DB.prepare('INSERT INTO share_batch_items (batch_code, file_code, file_key, name, size, days, expire) VALUES (?,?,?,?,?,?,?)').bind(bcode, r.code, r.key, r.name, r.size, r.days, r.expire).run(); }
  let bMaxDays = 0, bPerm = false;
  for (const r of rows) { const bd = Number(r.days); if (bd === 0) bPerm = true; else if (bd > bMaxDays) bMaxDays = bd; }
  try { const ua = request.headers.get('user-agent') || ''; const { os, browser } = parseUA(ua); const ip = request.headers.get('CF-Connecting-IP') || ''; await env.DB.prepare('INSERT INTO logs (file_name, action, ip, os, browser, ua, log_time) VALUES (?,?,?,?,?,?,?)').bind('批量分享（' + rows.length + '个文件' + (bPerm ? '，永久' : (bMaxDays > 0 ? '，' + bMaxDays + '天' : '')) + '）', 'share', ip, os, browser, ua, new Date().toISOString()).run(); } catch (e) {}
  return json(200, { link: 'https://' + url.host + '/' + bcode, codes: rows.map(function (x) { return x.code; }), expire: maxExp });
}
async function serveBatchShare(env, code) {
  await ensureDB(env);
  if (!env.DB) return new Response('未绑定数据库', { status: 400, headers: { 'content-type': 'text/plain; charset=utf-8' } });
  const b = await env.DB.prepare('SELECT code, expire FROM share_batches WHERE code=?').bind(code).first();
  if (!b) return new Response('分享页不存在或已失效', { status: 410, headers: { 'content-type': 'text/plain; charset=utf-8' } });
  const now = Math.floor(Date.now() / 1000);
  if (b.expire && b.expire < now) return new Response('分享页已过期', { status: 410, headers: { 'content-type': 'text/plain; charset=utf-8' } });
  const its = await env.DB.prepare('SELECT file_code, name, size, expire FROM share_batch_items WHERE batch_code=?').bind(code).all();
  const valid = [];
  for (const it of (its.results || [])) {
    const sh = await env.DB.prepare('SELECT 1 FROM shares WHERE code=?').bind(it.file_code).first();
    if (!sh) continue;
    if (it.expire && it.expire < now) continue;
    valid.push(it);
  }
  if (!valid.length) return new Response('分享页已失效', { status: 410, headers: { 'content-type': 'text/plain; charset=utf-8' } });
  const rr = [];
  for (const it of valid) {
    rr.push('<tr><td class="nm">' + escHtml(it.name) + '</td><td class="sz">' + fmtG(it.size || 0) + '</td><td><a class="dl" href="/' + it.file_code + '?dl=1">下载</a></td></tr>');
  }
  const html = '<!DOCTYPE html>\n<html lang="zh-CN">\n<head>\n<meta charset="UTF-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n<title>文件分享</title>\n<style>\n*{box-sizing:border-box;margin:0;padding:0}\nbody{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;background:#f0f2f5;color:#1f2329;min-height:100vh}\n.wrap{max-width:760px;margin:0 auto;padding:28px 16px}\n.card{background:#fff;border-radius:10px;padding:22px;box-shadow:0 1px 3px rgba(0,0,0,.08)}\nh1{font-size:19px;margin-bottom:4px}\n.sub{color:#6b7280;font-size:13px;margin-bottom:16px}\ntable{width:100%;border-collapse:collapse;font-size:14px}\nth{background:#f9fafb;text-align:left;padding:10px 8px;font-weight:600;border-bottom:1px solid #e5e7eb}\ntd{padding:10px 8px;border-bottom:1px solid #f3f4f6}\ntr:hover td{background:#f9fafb}\n.nm{max-width:430px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}\n.sz{color:#6b7280;white-space:nowrap}\n.dl{display:inline-block;padding:5px 14px;border-radius:6px;background:#2563eb;color:#fff;font-size:13px;text-decoration:none}\n.dl:hover{background:#1d4ed8}\n</style>\n</head>\n<body>\n<div class="wrap">\n<div class="card">\n<h1>文件分享</h1>\n<div class="sub">共 ' + valid.length + ' 个文件 . 点文件即可下载</div>\n<table><thead><tr><th>文件名</th><th>大小</th><th>操作</th></tr></thead><tbody>' + rr.join('') + '</tbody></table>\n</div>\n</div>\n</body>\n</html>';
  return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store, no-cache, must-revalidate, max-age=0' } });
}

async function handleShare(request, env, url) {
  const rawKey = url.searchParams.get('key') || '';
  const rawPath = url.searchParams.get('path');
  const isDir = rawPath !== null && String(rawPath) !== '';
  if (isDir) return json(400, { error: '文件夹分享已停用，请勾选文件后点批量分享' });
  const key = isDir ? normPath(rawPath) : rawKey;
  const days = Number(url.searchParams.get('days') || '30');
  if (!isDir && !key.startsWith('files/')) return json(400, { error: '非法key' });
  if (isDir && !key) return json(400, { error: '根目录不用分享，进去选中文件再分享' });
  let exp = 0;
  if (days > 0) exp = Math.floor(Date.now() / 1000) + days * 86400;
  // 短链用于所有时长的分享（含永久 days=0）；仅「下载」请求(dl=1)走 HMAC 长链，与前端 &dl=1 拼接兼容
  if (env.DB && url.searchParams.get('dl') !== '1') {
    await ensureDB(env);
    // 幂等复用：同文件+同时长固定一码。旧码已过期的必须重写有效期——否则复用的是死链（访问410、分享管理里被过滤掉）
    let exist = await env.DB.prepare('SELECT code, expire FROM shares WHERE file_key=? AND days=?').bind(key, days).first();
    let code = exist ? exist.code : null;
    if (!code) code = await genShareCode(env);
    if (code) {
      const nowSec = Math.floor(Date.now() / 1000);
      if (!exist || (exist.expire && exist.expire < nowSec)) {
        try {
          await saveShare(env, code, key, exp, days, isDir ? 'dir' : 'file');
        } catch (e) {
          // 唯一索引冲突：别的请求已先写入同一(file_key, days)，取它那行
          const dup = await env.DB.prepare('SELECT code FROM shares WHERE file_key=? AND days=?').bind(key, days).first();
          code = dup ? dup.code : null;
        }
      }
    }
    if (code) {
      const link = 'https://' + url.host + '/' + code;
      try { const ua = request.headers.get('user-agent') || ''; const { os, browser } = parseUA(ua); const ip = request.headers.get('CF-Connecting-IP') || ''; let snm = ''; try { const m = await env.DB.prepare('SELECT name FROM file_meta WHERE file_key=?').bind(key).first(); snm = m ? m.name : ''; } catch (e) {} await env.DB.prepare('INSERT INTO logs (file_name, action, ip, os, browser, ua, log_time) VALUES (?,?,?,?,?,?,?)').bind((snm || baseOf(key)) + '（' + (days > 0 ? days + '天' : '永久') + '）', 'share', ip, os, browser, ua, new Date().toISOString()).run(); } catch (e) {}
      return json(200, { link, expire: exp, short: true });
    }
  }
  // 回退：无 D1 或生成失败时用 HMAC 限时签名长链
  const sig = await shareSig(env, key, exp);
  const keyPath = key.split('/').map(encodeURIComponent).join('/');
  const link = 'https://' + url.host + '/f/' + keyPath + '?e=' + exp + '&s=' + sig + (url.searchParams.get('dl') === '1' ? '&dl=1' : '');
  if (url.searchParams.get('dl') !== '1') {
  try { const ua = request.headers.get('user-agent') || ''; const { os, browser } = parseUA(ua); const ip = request.headers.get('CF-Connecting-IP') || ''; let snm = ''; try { const m = await env.DB.prepare('SELECT name FROM file_meta WHERE file_key=?').bind(key).first(); snm = m ? m.name : ''; } catch (e) {} await env.DB.prepare('INSERT INTO logs (file_name, action, ip, os, browser, ua, log_time) VALUES (?,?,?,?,?,?,?)').bind((snm || baseOf(key)) + '（' + (days > 0 ? days + '天' : '永久') + '）', 'share', ip, os, browser, ua, new Date().toISOString()).run(); } catch (e) {}
  }
  return json(200, { link, expire: exp, short: false });
}

async function handleDelete(request, env, url) {
  const key = url.searchParams.get('key') || '';
  if (!key.startsWith('files/')) return json(400, { error: '非法key' });
  const r = await s3Fetch(env, 'DELETE', key, {}, {});
  if (r.status !== 204 && r.status !== 200 && r.status !== 404) return json(502, { error: '删除失败', s3: r.status });
  try { await ensureDB(env); if (env.DB) { await env.DB.prepare('DELETE FROM uploads WHERE file_key=?').bind(key).run(); await env.DB.prepare('DELETE FROM downloads WHERE file_key=?').bind(key).run(); await env.DB.prepare('DELETE FROM shares WHERE file_key=?').bind(key).run(); await env.DB.prepare('DELETE FROM hashes WHERE file_key=?').bind(key).run(); await env.DB.prepare('DELETE FROM file_meta WHERE file_key=?').bind(key).run(); } } catch {}
  try { const uaD=request.headers.get('user-agent')||''; const{os:osD,browser:brD}=parseUA(uaD); const ipD=request.headers.get('CF-Connecting-IP')||''; const fn4=(key.split('/').pop()||'').replace(/^[0-9a-f]{8}-/,''); await env.DB.prepare('INSERT INTO logs (file_name, action, ip, os, browser, ua, log_time) VALUES (?,?,?,?,?,?,?)').bind(fn4, 'delete', ipD, osD, brD, uaD, new Date().toISOString()).run(); } catch {}
  return json(200, { ok: true });
}

async function handleBatchDelete(request, env) {
  const body = await request.json().catch(() => ({}));
  const keys = Array.isArray(body.keys) ? body.keys : [];
  if (!keys.length) return json(400, { error: '未提供key列表' });
  let ok = 0, fail = 0;
  for (const key of keys) {
    if (typeof key !== 'string' || !key.startsWith('files/')) { fail++; continue; }
    const r = await s3Fetch(env, 'DELETE', key, {}, {});
    if (r.status === 204 || r.status === 200 || r.status === 404) {
      try { await ensureDB(env); if (env.DB) { await env.DB.prepare('DELETE FROM uploads WHERE file_key=?').bind(key).run(); await env.DB.prepare('DELETE FROM downloads WHERE file_key=?').bind(key).run(); await env.DB.prepare('DELETE FROM shares WHERE file_key=?').bind(key).run(); await env.DB.prepare('DELETE FROM hashes WHERE file_key=?').bind(key).run(); await env.DB.prepare('DELETE FROM file_meta WHERE file_key=?').bind(key).run(); } } catch {}
      try { const uaD=request.headers.get('user-agent')||''; const{os:osD,browser:brD}=parseUA(uaD); const ipD=request.headers.get('CF-Connecting-IP')||''; const fn4=(key.split('/').pop()||'').replace(/^[0-9a-f]{8}-/,''); await env.DB.prepare('INSERT INTO logs (file_name, action, ip, os, browser, ua, log_time) VALUES (?,?,?,?,?,?,?)').bind(fn4, 'delete', ipD, osD, brD, uaD, new Date().toISOString()).run(); } catch {}
      ok++;
    } else { fail++; }
  }
  return json(200, { ok, fail, total: keys.length });
}

async function handleStats(env, url) {
  const key = url.searchParams.get('key') || '';
  if (!key.startsWith('files/')) return json(400, { error: '非法key' });
  await ensureDB(env);
  if (!env.DB) return json(200, { uploader: null, downloaders: [] });
  const up = await env.DB.prepare('SELECT ip, os, browser, ua, upload_time FROM uploads WHERE file_key=?').bind(key).first();
  const dlRows = await env.DB.prepare('SELECT ip, os, browser, COUNT(*) as times, MIN(dl_time) as first, MAX(dl_time) as last FROM downloads WHERE file_key=? GROUP BY ip, os, browser ORDER BY last DESC LIMIT 100').bind(key).all();
  return json(200, { uploader: up, downloaders: dlRows.results });
}

async function handleLog(env, url) {
  await ensureDB(env);
  if (!env.DB) return json(200, { items: [], total: 0 });
  const limit = Math.min(Number(url.searchParams.get('limit') || '10'), 500);
  const offset = Math.max(Number(url.searchParams.get('offset') || '0'), 0);
  const SORTABLE = ['id', 'file_name', 'action', 'ip', 'log_time'];
  const sp = url.searchParams.get('sort') || 'id';
  const sortCol = SORTABLE.includes(sp) ? sp : 'id';
  const dir = url.searchParams.get('dir') === 'asc' ? 'ASC' : 'DESC';
  const cnt = await env.DB.prepare('SELECT COUNT(*) as c FROM logs').first();
  const rows = await env.DB.prepare('SELECT id, file_name, action, ip, os, browser, log_time FROM logs ORDER BY ' + sortCol + ' ' + dir + ', id ' + dir + ' LIMIT ? OFFSET ?').bind(limit, offset).all();
  return json(200, { items: rows.results, total: cnt ? cnt.c : 0 });
}

// ---------------- 短链分享 ----------------
const SHORT_RE = /^\/([A-Za-z0-9]{8}|[FS][A-Za-z0-9]{7})$/;
const SHORT_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
async function genShareCode(env) {
  if (!env.DB) return null;
  for (let i = 0; i < 8; i++) {
    const b = crypto.getRandomValues(new Uint8Array(8));
    let code = '';
    for (const x of b) code += SHORT_CHARS[x % 62];
    const ex = await env.DB.prepare('SELECT 1 FROM shares WHERE code=?').bind(code).first();
    if (!ex) return code;
  }
  return null;
}
async function saveShare(env, code, key, exp, days, kind) {
  const k = kind || 'file';
  try {
    await env.DB.prepare('INSERT OR REPLACE INTO shares (code, file_key, expire, days, kind) VALUES (?,?,?,?,?)').bind(code, key, exp, days, k).run();
  } catch (e) {
    // 极老的库可能还没加 kind 列，回退四列写法
    await env.DB.prepare('INSERT OR REPLACE INTO shares (code, file_key, expire, days) VALUES (?,?,?,?)').bind(code, key, exp, days).run();
  }
}

async function handleListShares(env) {
  await ensureDB(env);
  if (!env.DB) return json(400, { error: '未绑定数据库' });
  const items = [];
  const now = Math.floor(Date.now() / 1000);
  try {
    const fs = await env.DB.prepare("SELECT code, file_key, expire, days FROM shares WHERE (kind IS NULL OR kind='file')").all();
    for (const r of (fs.results || [])) {
      let nm = '';
      try { const m = await env.DB.prepare('SELECT name FROM file_meta WHERE file_key=?').bind(r.file_key).first(); nm = m ? m.name : ''; } catch (e) {}
      if (!nm) nm = baseOf(r.file_key);
      if (r.expire && r.expire < now) continue;
      items.push({ type: 'file', code: r.code, name: nm, key: r.file_key, expire: r.expire || 0, days: r.days, created: null });
    }
  } catch (e) {}
  try {
    const bs = await env.DB.prepare('SELECT code, expire, created FROM share_batches').all();
    for (const r of (bs.results || [])) {
      if (r.expire && r.expire < now) continue;
      let names = [];
      try { const its = await env.DB.prepare('SELECT name FROM share_batch_items WHERE batch_code=?').bind(r.code).all(); names = (its.results || []).map(function(x){return x.name;}); } catch (e) {}
      const label = names.length ? (names.length + '个文件：' + names.slice(0,3).join('、') + (names.length>3?(' 等'+names.length+'个'):'')) : (r.code + ' 分享页');
      items.push({ type: 'batch', code: r.code, name: label, key: '', expire: r.expire || 0, days: 0, created: r.created });
    }
  } catch (e) {}
  return json(200, { items: items });
}
async function handleRevokeShare(request, env) {
  await ensureDB(env);
  if (!env.DB) return json(400, { error: '未绑定数据库' });
  const body = await request.json().catch(() => ({}));
  const codes = Array.isArray(body.codes) ? body.codes.map(function(x){return String(x);}) : (body.code ? [String(body.code)] : []);
  if (!codes.length) return json(400, { error: '缺少code' });
  try {
    for (const c of codes) {
      let lbl = c;
      const b = await env.DB.prepare('SELECT 1 FROM share_batches WHERE code=?').bind(c).first();
      if (b) {
        const its = await env.DB.prepare('SELECT file_code, days FROM share_batch_items WHERE batch_code=?').bind(c).all();
        const rows = its.results || [];
        let maxDays = 0, perm = false;
        for (const it of rows) { const dd = Number(it.days); if (dd === 0) perm = true; else if (dd > maxDays) maxDays = dd; }
        lbl = '批量分享（' + rows.length + '个文件' + (perm ? '，永久' : (maxDays > 0 ? '，' + maxDays + '天' : '')) + '）';
        for (const it of rows) { await env.DB.prepare('DELETE FROM shares WHERE code=?').bind(it.file_code).run(); }
        await env.DB.prepare('DELETE FROM share_batch_items WHERE batch_code=?').bind(c).run();
        await env.DB.prepare('DELETE FROM share_batches WHERE code=?').bind(c).run();
      } else {
        const srow = await env.DB.prepare('SELECT file_key, days FROM shares WHERE code=?').bind(c).first();
        if (srow) {
          let nm = '';
          try { const m = await env.DB.prepare('SELECT name FROM file_meta WHERE file_key=?').bind(srow.file_key).first(); nm = m ? m.name : ''; } catch (e) {}
          if (!nm) nm = baseOf(srow.file_key);
          lbl = nm + '（' + (Number(srow.days) > 0 ? Number(srow.days) + '天' : '永久') + '）';
        }
        await env.DB.prepare('DELETE FROM shares WHERE code=?').bind(c).run();
      }
      try { const ua = request.headers.get('user-agent') || ''; const { os, browser } = parseUA(ua); const ip = request.headers.get('CF-Connecting-IP') || ''; await env.DB.prepare('INSERT INTO logs (file_name, action, ip, os, browser, ua, log_time) VALUES (?,?,?,?,?,?,?)').bind(lbl, 'unshare', ip, os, browser, ua, new Date().toISOString()).run(); } catch (e) {}
    }
    return json(200, { ok: true });
  } catch (e) {
    return json(500, { error: '取消失败', detail: String((e && e.message) || e).slice(0,200) });
  }
}

async function lookupShare(env, code) {
  const row = await env.DB.prepare('SELECT file_key, expire, kind FROM shares WHERE code=?').bind(code).first();
  if (!row) return null;
  if (row.expire && row.expire < Math.floor(Date.now() / 1000)) {
    try { await env.DB.prepare('DELETE FROM shares WHERE code=?').bind(code).run(); } catch {}
    return null;
  }
  return { key: row.file_key, kind: row.kind || 'file', expire: row.expire || 0 };
}
function escHtml(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ---------------- 分享下载代理 ----------------
async function handleDownload(request, env, url) {
  const keyPath = url.pathname.replace(/^\/f\//, '');
  const key = decodeKeyPath(keyPath.split('/'));
  if (!key.startsWith('files/')) return new Response('Not Found', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8' } });
  const e = Number(url.searchParams.get('e') || '0');
  const s = url.searchParams.get('s') || '';
  if (e !== 0 && e < Math.floor(Date.now() / 1000)) return new Response('链接已过期', { status: 410, headers: { 'content-type': 'text/plain; charset=utf-8' } });
  const expectSig = await shareSig(env, key, e);
  if (s !== expectSig) return new Response('无效链接', { status: 403, headers: { 'content-type': 'text/plain; charset=utf-8' } });
  return await serveFile(request, env, key, !!url.searchParams.get('dl'));
}
async function serveFile(request, env, key, dl) {
  const range = request.headers.get('range');
  const r = await s3Fetch(env, 'GET', key, {}, { extraHeaders: range ? { range } : undefined });
  if (r.status !== 200 && r.status !== 206) {
    const fname = (key.split('/').pop() || 'file').replace(/^[0-9a-f]{8}-/, '');
    try { if (await isDpiBlocked(r.clone())) return new Response(DPI_ERR.error, { status: 502, headers: { 'content-type': 'text/plain; charset=utf-8' } }); } catch (e) {}
    let detail = '';
    try { detail = String((await r.clone().text()) || '').replace(/\s+/g, ' ').trim().slice(0, 300); } catch (e) {}
    const msg = '文件「' + fname + '」读取失败：源站返回 ' + r.status + (detail ? '\n' + detail : '');
    return new Response(msg, { status: r.status === 404 ? 404 : 502, headers: { 'content-type': 'text/plain; charset=utf-8' } });
  }
  const fileName = (key.split('/').pop() || 'file').replace(/^[0-9a-f]{8}-/, '');
  const ct = r.headers.get('content-type') || 'application/octet-stream';
  const disposition = (INLINE_MIME.test(ct) && !dl) ? 'inline' : 'attachment';
  const h = new Headers();
  for (const name of ['content-type', 'content-length', 'etag', 'last-modified', 'accept-ranges', 'content-range']) {
    const v = r.headers.get(name); if (v != null) h.set(name, v);
  }
  h.set('content-disposition', disposition + "; filename*=UTF-8''" + encodeURIComponent(fileName));
  h.set('cache-control', 'no-store');
  try { await ensureDB(env); if (env.DB) { const ua = request.headers.get('user-agent') || ''; const { os, browser } = parseUA(ua); const ip = request.headers.get('CF-Connecting-IP') || ''; const ago = new Date(Date.now() - 60000).toISOString(); const exist = await env.DB.prepare('SELECT 1 FROM downloads WHERE file_key=? AND ip=? AND dl_time>?').bind(key, ip, ago).first(); if (!exist) { await env.DB.prepare('INSERT INTO downloads (file_key, ip, os, browser, ua, dl_time) VALUES (?,?,?,?,?,?)').bind(key, ip, os, browser, ua, new Date().toISOString()).run(); try { const fn3=(key.split('/').pop()||'').replace(/^[0-9a-f]{8}-/,''); await env.DB.prepare('INSERT INTO logs (file_name, action, ip, os, browser, ua, log_time) VALUES (?,?,?,?,?,?,?)').bind(fn3, 'download', ip, os, browser, ua, new Date().toISOString()).run(); } catch {} } } } catch {}
  return new Response(r.body, { status: r.status, headers: h });
}

// ---------------- 前端页面 ----------------
const HTML_PAGE = '<!DOCTYPE html>\n<html lang="zh-CN">\n<head>\n<meta charset="UTF-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n<title>老默文件分发系统</title>\n<link rel="icon" href="https://pic1.imgdb.cn/i/64qON4MrPqTEcrmBNQGfw4.ico">\n<style>\n*{box-sizing:border-box;margin:0;padding:0}\nbody{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;background:#f0f2f5;color:#1f2329;min-height:100vh}\n.wrap{max-width:980px;margin:0 auto;padding:24px 16px}\nh1{font-size:22px;margin-bottom:4px}\n.sub{color:#6b7280;font-size:13px;margin-bottom:20px}\n.card{background:#fff;border-radius:10px;padding:20px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.08)}\n.card h2{font-size:16px;margin-bottom:14px}\n.btn{display:inline-block;padding:8px 18px;border:none;border-radius:6px;background:#2563eb;color:#fff;font-size:14px;cursor:pointer}\n.btn:hover{background:#1d4ed8}\n.btn.ghost{background:#e5e7eb;color:#374151}.btn.ghost:hover{background:#d1d5db}\n.btn.danger{background:#dc2626}.btn.danger:hover{background:#b91c1c}\n.btn.ok{background:#16a34a;color:#fff}.btn.ok:hover{background:#15803d}\n.btn.small{padding:4px 10px;font-size:12px}.btn:disabled{background:#e5e7eb;color:#9ca3af;cursor:not-allowed;opacity:1}.btn:disabled:hover{background:#e5e7eb;color:#9ca3af}\n.mono{font-family:ui-monospace,Menlo,Consolas,monospace}.qrmask{position:fixed;left:0;top:0;right:0;bottom:0;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;z-index:99}\n.qrbox{background:#fff;border-radius:10px;padding:22px 24px;text-align:center;box-shadow:0 4px 24px rgba(0,0,0,.25);max-width:92vw}\ninput[type=password]{padding:8px 10px;border:1px solid #d1d5db;border-radius:6px;font-size:14px;width:100%}\n.drop{border:2px dashed #9ca3af;border-radius:10px;padding:36px;text-align:center;color:#6b7280;cursor:pointer;transition:all .15s}\n.drop.on{border-color:#2563eb;background:#eff6ff;color:#2563eb}\ntable{width:100%;border-collapse:collapse;font-size:13px}\nth{background:#f9fafb;text-align:left;padding:9px 8px;font-weight:600;border-bottom:1px solid #e5e7eb;white-space:nowrap}\ntd{padding:9px 8px;border-bottom:1px solid #f3f4f6;vertical-align:middle}\ntr:hover td{background:#f9fafb}\n.fname{max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}\n.bar{height:14px;background:#e5e7eb;border-radius:7px;overflow:hidden;margin:8px 0}\n.bar>div{height:100%;background:#2563eb;border-radius:7px;transition:width .2s}\n.mono{font-family:Consolas,monospace;font-size:12px;word-break:break-all}\n.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap} .mask{position:fixed;inset:0;background:rgba(0,0,0,.45);display:none;align-items:center;justify-content:center;z-index:80}.modal{background:#fff;border-radius:12px;width:min(680px,92vw);max-height:84vh;overflow:auto;box-shadow:0 10px 40px rgba(0,0,0,.25)}.mhdr{display:flex;justify-content:space-between;align-items:center;padding:14px 18px;border-bottom:1px solid #eee;font-size:16px;font-weight:600}.mbody{padding:14px 18px}.shr-row{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid #f3f4f6;font-size:14px}.shr-info{flex:1;min-width:0}.shr-name{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.shr-meta{color:#6b7280;font-size:12px;margin-top:2px}.dotmenu{position:relative;display:inline-block;vertical-align:middle}.dotbtn{cursor:pointer}.menu{position:absolute;right:0;top:100%;z-index:60;background:#fff;border:1px solid #d1d5db;border-radius:8px;box-shadow:0 6px 20px rgba(0,0,0,.15);min-width:112px;padding:6px;display:none}.menu.show{display:block}.menu button{display:block;width:100%;text-align:left;margin:0;padding:7px 12px;border:0;background:none;color:#374151;border-radius:6px;font-size:14px;cursor:pointer;white-space:nowrap}.menu button:hover{background:#f3f4f6}.menu button.danger{color:#dc2626;background:none}.menu button.danger:hover{background:#fef2f2}\n.up{margin-bottom:14px;padding:12px;border:1px solid #e5e7eb;border-radius:8px;font-size:13px}\n#loginBox{max-width:400px;margin:80px auto}\n.hide{display:none!important}\nselect{padding:8px;border:1px solid #d1d5db;border-radius:6px;font-size:13px}\n.msg{padding:10px 14px;border-radius:6px;font-size:13px;margin-bottom:12px}\n.msg.ok{background:#ecfdf5;color:#065f46}.msg.err{background:#fef2f2;color:#991b1b}\n.tip{position:relative;cursor:help}\n.tip:hover .tip-bubble{display:block}\n.tip-bubble{display:none;position:absolute;bottom:100%;left:50%;transform:translateX(-50%);background:#1f2329;color:#fff;padding:8px 12px;border-radius:6px;font-size:12px;line-height:1.6;z-index:100;box-shadow:0 2px 8px rgba(0,0,0,.2);margin-bottom:4px;text-align:left;max-height:320px;overflow-y:auto}\n.tip-bubble::after{content:\'\';position:absolute;top:100%;left:50%;transform:translateX(-50%);border:5px solid transparent;border-top-color:#1f2329}\n.tip-ico{font-size:15px}\n</style>\n</head>\n<body>\n<div id="loginBox" class="card">\n  <h2>登录文件分发系统</h2>\n  <div style="margin:12px 0"><input type="password" id="tk" placeholder="请输入管理口令" onkeydown="if(event.key===\'Enter\')doLogin()"></div>\n  <button class="btn" onclick="doLogin()">进入</button>\n  <div id="loginMsg" style="margin-top:10px"></div>\n</div>\n<div id="main" class="wrap hide">\n  <div class="brand" style="display:flex;align-items:flex-start;gap:14px;margin-bottom:18px"><img src="https://pic1.imgdb.cn/i/0341LkAqetyPYhg6eLe2lh.webp" alt="" style="width:52px;height:52px;border-radius:10px;flex:none;box-shadow:0 1px 4px rgba(0,0,0,.12)"><div style="min-width:0"><h1 style="margin:0 0 4px">老默文件分发系统</h1><div class="sub" style="margin:0 0 4px">依托cloudflare部署无服务端分片直传S3对象存储系统</div><div style="color:#9ca3af;font-size:12px;line-height:1.5">当前存储依托中科云数据胶囊 · 免费额度20GB</div></div></div>\n  <div id="gmsg"></div>\n  <div class="card">\n    <h2>上传文件</h2>\n    <div class="drop" id="drop" onclick="document.getElementById(\'fi\').click()">点击选择 或 拖拽文件到此处<br><span style="font-size:12px">支持任意类型，超过5.1MB自动分片并发上传 · 大文件建议压缩成zip后上传</span></div>\n    <input type="file" id="fi" style="display:none" multiple>\n    <div id="ups"></div>\n  </div>\n  <div class="card">\n    <h2 class="row" style="justify-content:space-between">文件列表 <span><button class="btn small ghost" onclick="doMkdir()">新建文件夹</button> <button class="btn small ghost" onclick="openShareMgr()">分享管理</button> <button class="btn small ghost" onclick="refresh()">刷新</button></span></h2>\n    <div id="crumb" class="row" style="margin-bottom:8px;font-size:13px;flex-wrap:wrap;gap:2px"></div>\n    <div style="margin-bottom:8px;color:#6b7280;font-size:12px" id="stat"></div>\n    <div style="overflow-x:auto">\n    <div id="batchBar" style="margin-bottom:8px;display:none"><label style="font-size:13px;cursor:pointer"><input type="checkbox" id="selAll"> 全选</label> <button class="btn small ghost" id="moveSel">移动到…</button> <button class="btn small danger" id="delSel">批量删除选中</button> <button class="btn small ghost" id="batchShare">批量分享</button> <span id="selCount" style="color:#6b7280;font-size:12px"></span></div><div id="shareMgrMask" class="mask"><div class="modal"><div class="mhdr"><span>分享管理</span><span><button class="btn small danger" id="revokeSelBtn" disabled onclick="revokeSelected()">批量取消选中</button> <button class="btn small ghost" onclick="closeShareMgr()">关闭</button></span></div><div id="shareMgrBody" class="mbody"></div></div></div>\n    <div id="moveBox" style="display:none;margin-bottom:8px;padding:10px;border:1px solid #e5e7eb;border-radius:8px;font-size:13px"><span>移动到：</span><select id="moveDest" style="margin:0 8px"></select><button class="btn small" id="moveGo">确定</button> <button class="btn small ghost" onclick="document.getElementById(\'moveBox\').style.display=\'none\'">取消</button></div>\n    <table id="tbl"><thead><tr><th style="width:36px"><input type="checkbox" id="selAll2" title="全选"></th><th>文件名</th><th>大小</th><th>时间</th><th>操作</th></tr></thead><tbody id="tb"></tbody></table>\n    </div>\n  </div>\n  <div class="card">\n    <h2 class="row" style="justify-content:space-between">使用记录 <span><button class="btn small ghost" onclick="loadLog(true)">刷新</button></span></h2>\n    <div style="overflow-x:auto">\n    <table id="logTbl"><thead><tr><th>序号</th><th id="th-file_name">文件名<span id="sa-file_name" style="color:#2563eb"></span></th><th id="th-action">动作<span id="sa-action" style="color:#2563eb"></span></th><th id="th-log_time">时间<span id="sa-log_time" style="color:#2563eb"></span></th><th id="th-ip">IP地址<span id="sa-ip" style="color:#2563eb"></span></th><th>设备</th></tr></thead><tbody id="logTb"></tbody></table>\n    </div>\n    <div style="text-align:center;margin-top:12px"><button class="btn small ghost" id="logMoreBtn" onclick="loadMoreLog()">加载更多</button></div>\n  </div>\n  <div class="sub" style="text-align:center;margin-top:8px"><a href="https://github.com/QingSiHuang/cfst-file" target="_blank" rel="noopener" style="color:#2563eb;text-decoration:none">GitHub</a> · Cloudflare Worker + 中科云S3 · <a href="https://nav.ctyun2026.de5.net" target="_blank" rel="noopener" style="color:#2563eb;text-decoration:none">老默导航</a> · __VER__</div>\n</div>\n<script>var TOKEN=localStorage.getItem("fh_token")||"";\nvar CONC=5,RETRY=3;\nfunction api(method,url,body,rawBody){var h={"x-auth-token":TOKEN};var opt={method:method,headers:h};if(body){h["content-type"]="application/json";opt.body=JSON.stringify(body);}if(rawBody){opt.body=rawBody;}return fetch(url,opt).then(function(r){return r.json().then(function(j){if(!r.ok)throw new Error(j.error||("HTTP"+r.status));return j;})});}\nfunction doLogin(){var v=document.getElementById("tk").value.trim();if(!v)return;fetch("/api/login",{method:"POST",headers:{"content-type":"application/json","x-auth-token":v},body:"{}"}).then(function(r){return r.json()}).then(function(j){if(j.ok){TOKEN=v;localStorage.setItem("fh_token",v);enter();}else{document.getElementById("loginMsg").innerHTML=\'<span style="color:#dc2626">口令错误</span>\';}}).catch(function(){document.getElementById("loginMsg").innerHTML=\'<span style="color:#dc2626">网络错误</span>\';});}\nfunction enter(){document.getElementById("loginBox").classList.add("hide");document.getElementById("main").classList.remove("hide");refresh();loadLog(true);}\nfunction fmtSize(n){if(n<1024)return n+"B";var u=["KB","MB","GB","TB"],i=-1;do{n/=1024;i++;}while(n>=1024&&i<3);return n.toFixed(n>=100?0:1)+u[i];}\nfunction fmtTime(s){if(!s)return "-";var d=new Date(s);if(isNaN(d))return s;var p=function(x){return (x<10?"0":"")+x;};return d.getFullYear()+"-"+p(d.getMonth()+1)+"-"+p(d.getDate())+" "+p(d.getHours())+":"+p(d.getMinutes())+":"+p(d.getSeconds());}\nfunction gmsg(t,ok){document.getElementById("gmsg").innerHTML=t?\'<div class="msg \'+(ok?"ok":"err")+\'">\'+t+"</div>":"";}\nfunction tryClip(link,okFn,noFn){try{if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(link).then(okFn,function(){noFn();});return;}}catch(e){}noFn();}\nfunction copyFeedback(b,txt,bad){try{clearTimeout(b.__ct);}catch(e){}if(b.__ot==null){b.__ot=b.textContent;b.__oc=b.className;}b.disabled=false;b.textContent=txt;b.className="btn small "+(bad?"danger":"ok");b.__ct=setTimeout(function(){b.disabled=false;b.textContent=b.__ot;b.className=b.__oc;},bad?2600:1800);}function makeDots(items){var w=document.createElement("span");w.className="dotmenu";var b=document.createElement("button");b.className="btn small ghost dotbtn";b.type="button";b.textContent="⋯";var m=document.createElement("span");m.className="menu";items.forEach(function(it){var mb=document.createElement("button");mb.className="btn small "+(it.danger?"danger":"");mb.textContent=it.label;mb.onclick=function(e){e.stopPropagation();m.classList.remove("show");it.onclick();};m.appendChild(mb);});b.onclick=function(e){e.stopPropagation();var on=m.className.indexOf("show")>=0;document.querySelectorAll(".menu.show").forEach(function(x){if(x!==m)x.classList.remove("show");});m.classList.toggle("show");};w.appendChild(b);w.appendChild(m);return w;}document.addEventListener("click",function(){document.querySelectorAll(".menu.show").forEach(function(x){x.classList.remove("show");});});\nfunction esc(s){var d={"&":"&amp;","<":"&lt;",">":"&gt;",\'"\':"&quot;"};return String(s).replace(/[&<>"]/g,function(c){return d[c];});}\nfunction fmtEta(sec){sec=Math.round(sec||0);if(sec<=0)return"即将完成";if(sec<60)return sec+"秒";if(sec<3600)return Math.floor(sec/60)+"分"+(sec%60>0?sec%60+"秒":"");return Math.floor(sec/3600)+"时"+Math.floor(sec%3600/60)+"分";}\n// QR Code Generator for JavaScript (c) 2009 Kazuhiko Arase, MIT license\nvar qrcode = function() {\n/**\n* qrcode\n* @param typeNumber 1 to 40\n* @param errorCorrectionLevel \'L\',\'M\',\'Q\',\'H\'\n*/\nvar qrcode = function(typeNumber, errorCorrectionLevel) {\nvar PAD0 = 0xEC;\nvar PAD1 = 0x11;\nvar _typeNumber = typeNumber;\nvar _errorCorrectionLevel = QRErrorCorrectionLevel[errorCorrectionLevel];\nvar _modules = null;\nvar _moduleCount = 0;\nvar _dataCache = null;\nvar _dataList = [];\nvar _this = {};\nvar makeImpl = function(test, maskPattern) {\n_moduleCount = _typeNumber * 4 + 17;\n_modules = function(moduleCount) {\nvar modules = new Array(moduleCount);\nfor (var row = 0; row < moduleCount; row += 1) {\nmodules[row] = new Array(moduleCount);\nfor (var col = 0; col < moduleCount; col += 1) {\nmodules[row][col] = null;\n}\n}\nreturn modules;\n}(_moduleCount);\nsetupPositionProbePattern(0, 0);\nsetupPositionProbePattern(_moduleCount - 7, 0);\nsetupPositionProbePattern(0, _moduleCount - 7);\nsetupPositionAdjustPattern();\nsetupTimingPattern();\nsetupTypeInfo(test, maskPattern);\nif (_typeNumber >= 7) {\nsetupTypeNumber(test);\n}\nif (_dataCache == null) {\n_dataCache = createData(_typeNumber, _errorCorrectionLevel, _dataList);\n}\nmapData(_dataCache, maskPattern);\n};\nvar setupPositionProbePattern = function(row, col) {\nfor (var r = -1; r <= 7; r += 1) {\nif (row + r <= -1 || _moduleCount <= row + r) continue;\nfor (var c = -1; c <= 7; c += 1) {\nif (col + c <= -1 || _moduleCount <= col + c) continue;\nif ( (0 <= r && r <= 6 && (c == 0 || c == 6) )\n|| (0 <= c && c <= 6 && (r == 0 || r == 6) )\n|| (2 <= r && r <= 4 && 2 <= c && c <= 4) ) {\n_modules[row + r][col + c] = true;\n} else {\n_modules[row + r][col + c] = false;\n}\n}\n}\n};\nvar getBestMaskPattern = function() {\nvar minLostPoint = 0;\nvar pattern = 0;\nfor (var i = 0; i < 8; i += 1) {\nmakeImpl(true, i);\nvar lostPoint = QRUtil.getLostPoint(_this);\nif (i == 0 || minLostPoint > lostPoint) {\nminLostPoint = lostPoint;\npattern = i;\n}\n}\nreturn pattern;\n};\nvar setupTimingPattern = function() {\nfor (var r = 8; r < _moduleCount - 8; r += 1) {\nif (_modules[r][6] != null) {\ncontinue;\n}\n_modules[r][6] = (r % 2 == 0);\n}\nfor (var c = 8; c < _moduleCount - 8; c += 1) {\nif (_modules[6][c] != null) {\ncontinue;\n}\n_modules[6][c] = (c % 2 == 0);\n}\n};\nvar setupPositionAdjustPattern = function() {\nvar pos = QRUtil.getPatternPosition(_typeNumber);\nfor (var i = 0; i < pos.length; i += 1) {\nfor (var j = 0; j < pos.length; j += 1) {\nvar row = pos[i];\nvar col = pos[j];\nif (_modules[row][col] != null) {\ncontinue;\n}\nfor (var r = -2; r <= 2; r += 1) {\nfor (var c = -2; c <= 2; c += 1) {\nif (r == -2 || r == 2 || c == -2 || c == 2\n|| (r == 0 && c == 0) ) {\n_modules[row + r][col + c] = true;\n} else {\n_modules[row + r][col + c] = false;\n}\n}\n}\n}\n}\n};\nvar setupTypeNumber = function(test) {\nvar bits = QRUtil.getBCHTypeNumber(_typeNumber);\nfor (var i = 0; i < 18; i += 1) {\nvar mod = (!test && ( (bits >> i) & 1) == 1);\n_modules[Math.floor(i / 3)][i % 3 + _moduleCount - 8 - 3] = mod;\n}\nfor (var i = 0; i < 18; i += 1) {\nvar mod = (!test && ( (bits >> i) & 1) == 1);\n_modules[i % 3 + _moduleCount - 8 - 3][Math.floor(i / 3)] = mod;\n}\n};\nvar setupTypeInfo = function(test, maskPattern) {\nvar data = (_errorCorrectionLevel << 3) | maskPattern;\nvar bits = QRUtil.getBCHTypeInfo(data);\nfor (var i = 0; i < 15; i += 1) {\nvar mod = (!test && ( (bits >> i) & 1) == 1);\nif (i < 6) {\n_modules[i][8] = mod;\n} else if (i < 8) {\n_modules[i + 1][8] = mod;\n} else {\n_modules[_moduleCount - 15 + i][8] = mod;\n}\n}\nfor (var i = 0; i < 15; i += 1) {\nvar mod = (!test && ( (bits >> i) & 1) == 1);\nif (i < 8) {\n_modules[8][_moduleCount - i - 1] = mod;\n} else if (i < 9) {\n_modules[8][15 - i - 1 + 1] = mod;\n} else {\n_modules[8][15 - i - 1] = mod;\n}\n}\n_modules[_moduleCount - 8][8] = (!test);\n};\nvar mapData = function(data, maskPattern) {\nvar inc = -1;\nvar row = _moduleCount - 1;\nvar bitIndex = 7;\nvar byteIndex = 0;\nvar maskFunc = QRUtil.getMaskFunction(maskPattern);\nfor (var col = _moduleCount - 1; col > 0; col -= 2) {\nif (col == 6) col -= 1;\nwhile (true) {\nfor (var c = 0; c < 2; c += 1) {\nif (_modules[row][col - c] == null) {\nvar dark = false;\nif (byteIndex < data.length) {\ndark = ( ( (data[byteIndex] >>> bitIndex) & 1) == 1);\n}\nvar mask = maskFunc(row, col - c);\nif (mask) {\ndark = !dark;\n}\n_modules[row][col - c] = dark;\nbitIndex -= 1;\nif (bitIndex == -1) {\nbyteIndex += 1;\nbitIndex = 7;\n}\n}\n}\nrow += inc;\nif (row < 0 || _moduleCount <= row) {\nrow -= inc;\ninc = -inc;\nbreak;\n}\n}\n}\n};\nvar createBytes = function(buffer, rsBlocks) {\nvar offset = 0;\nvar maxDcCount = 0;\nvar maxEcCount = 0;\nvar dcdata = new Array(rsBlocks.length);\nvar ecdata = new Array(rsBlocks.length);\nfor (var r = 0; r < rsBlocks.length; r += 1) {\nvar dcCount = rsBlocks[r].dataCount;\nvar ecCount = rsBlocks[r].totalCount - dcCount;\nmaxDcCount = Math.max(maxDcCount, dcCount);\nmaxEcCount = Math.max(maxEcCount, ecCount);\ndcdata[r] = new Array(dcCount);\nfor (var i = 0; i < dcdata[r].length; i += 1) {\ndcdata[r][i] = 0xff & buffer.getBuffer()[i + offset];\n}\noffset += dcCount;\nvar rsPoly = QRUtil.getErrorCorrectPolynomial(ecCount);\nvar rawPoly = qrPolynomial(dcdata[r], rsPoly.getLength() - 1);\nvar modPoly = rawPoly.mod(rsPoly);\necdata[r] = new Array(rsPoly.getLength() - 1);\nfor (var i = 0; i < ecdata[r].length; i += 1) {\nvar modIndex = i + modPoly.getLength() - ecdata[r].length;\necdata[r][i] = (modIndex >= 0)? modPoly.getAt(modIndex) : 0;\n}\n}\nvar totalCodeCount = 0;\nfor (var i = 0; i < rsBlocks.length; i += 1) {\ntotalCodeCount += rsBlocks[i].totalCount;\n}\nvar data = new Array(totalCodeCount);\nvar index = 0;\nfor (var i = 0; i < maxDcCount; i += 1) {\nfor (var r = 0; r < rsBlocks.length; r += 1) {\nif (i < dcdata[r].length) {\ndata[index] = dcdata[r][i];\nindex += 1;\n}\n}\n}\nfor (var i = 0; i < maxEcCount; i += 1) {\nfor (var r = 0; r < rsBlocks.length; r += 1) {\nif (i < ecdata[r].length) {\ndata[index] = ecdata[r][i];\nindex += 1;\n}\n}\n}\nreturn data;\n};\nvar createData = function(typeNumber, errorCorrectionLevel, dataList) {\nvar rsBlocks = QRRSBlock.getRSBlocks(typeNumber, errorCorrectionLevel);\nvar buffer = qrBitBuffer();\nfor (var i = 0; i < dataList.length; i += 1) {\nvar data = dataList[i];\nbuffer.put(data.getMode(), 4);\nbuffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber) );\ndata.write(buffer);\n}\nvar totalDataCount = 0;\nfor (var i = 0; i < rsBlocks.length; i += 1) {\ntotalDataCount += rsBlocks[i].dataCount;\n}\nif (buffer.getLengthInBits() > totalDataCount * 8) {\nthrow \'code length overflow. (\'\n+ buffer.getLengthInBits()\n+ \'>\'\n+ totalDataCount * 8\n+ \')\';\n}\nif (buffer.getLengthInBits() + 4 <= totalDataCount * 8) {\nbuffer.put(0, 4);\n}\nwhile (buffer.getLengthInBits() % 8 != 0) {\nbuffer.putBit(false);\n}\nwhile (true) {\nif (buffer.getLengthInBits() >= totalDataCount * 8) {\nbreak;\n}\nbuffer.put(PAD0, 8);\nif (buffer.getLengthInBits() >= totalDataCount * 8) {\nbreak;\n}\nbuffer.put(PAD1, 8);\n}\nreturn createBytes(buffer, rsBlocks);\n};\n_this.addData = function(data, mode) {\nmode = mode || \'Byte\';\nvar newData = null;\nswitch(mode) {\ncase \'Numeric\' :\nnewData = qrNumber(data);\nbreak;\ncase \'Alphanumeric\' :\nnewData = qrAlphaNum(data);\nbreak;\ncase \'Byte\' :\nnewData = qr8BitByte(data);\nbreak;\ncase \'Kanji\' :\nnewData = qrKanji(data);\nbreak;\ndefault :\nthrow \'mode:\' + mode;\n}\n_dataList.push(newData);\n_dataCache = null;\n};\n_this.isDark = function(row, col) {\nif (row < 0 || _moduleCount <= row || col < 0 || _moduleCount <= col) {\nthrow row + \',\' + col;\n}\nreturn _modules[row][col];\n};\n_this.getModuleCount = function() {\nreturn _moduleCount;\n};\n_this.make = function() {\nif (_typeNumber < 1) {\nvar typeNumber = 1;\nfor (; typeNumber < 40; typeNumber++) {\nvar rsBlocks = QRRSBlock.getRSBlocks(typeNumber, _errorCorrectionLevel);\nvar buffer = qrBitBuffer();\nfor (var i = 0; i < _dataList.length; i++) {\nvar data = _dataList[i];\nbuffer.put(data.getMode(), 4);\nbuffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber) );\ndata.write(buffer);\n}\nvar totalDataCount = 0;\nfor (var i = 0; i < rsBlocks.length; i++) {\ntotalDataCount += rsBlocks[i].dataCount;\n}\nif (buffer.getLengthInBits() <= totalDataCount * 8) {\nbreak;\n}\n}\n_typeNumber = typeNumber;\n}\nmakeImpl(false, getBestMaskPattern() );\n};\n_this.createTableTag = function(cellSize, margin) {\ncellSize = cellSize || 2;\nmargin = (typeof margin == \'undefined\')? cellSize * 4 : margin;\nvar qrHtml = \'\';\nqrHtml += \'<table style="\';\nqrHtml += \' border-width: 0px; border-style: none;\';\nqrHtml += \' border-collapse: collapse;\';\nqrHtml += \' padding: 0px; margin: \' + margin + \'px;\';\nqrHtml += \'">\';\nqrHtml += \'<tbody>\';\nfor (var r = 0; r < _this.getModuleCount(); r += 1) {\nqrHtml += \'<tr>\';\nfor (var c = 0; c < _this.getModuleCount(); c += 1) {\nqrHtml += \'<td style="\';\nqrHtml += \' border-width: 0px; border-style: none;\';\nqrHtml += \' border-collapse: collapse;\';\nqrHtml += \' padding: 0px; margin: 0px;\';\nqrHtml += \' width: \' + cellSize + \'px;\';\nqrHtml += \' height: \' + cellSize + \'px;\';\nqrHtml += \' background-color: \';\nqrHtml += _this.isDark(r, c)? \'#000000\' : \'#ffffff\';\nqrHtml += \';\';\nqrHtml += \'"/>\';\n}\nqrHtml += \'</tr>\';\n}\nqrHtml += \'</tbody>\';\nqrHtml += \'</table>\';\nreturn qrHtml;\n};\n_this.createSvgTag = function(cellSize, margin, alt, title) {\nvar opts = {};\nif (typeof arguments[0] == \'object\') {\nopts = arguments[0];\ncellSize = opts.cellSize;\nmargin = opts.margin;\nalt = opts.alt;\ntitle = opts.title;\n}\ncellSize = cellSize || 2;\nmargin = (typeof margin == \'undefined\')? cellSize * 4 : margin;\nalt = (typeof alt === \'string\') ? {text: alt} : alt || {};\nalt.text = alt.text || null;\nalt.id = (alt.text) ? alt.id || \'qrcode-description\' : null;\ntitle = (typeof title === \'string\') ? {text: title} : title || {};\ntitle.text = title.text || null;\ntitle.id = (title.text) ? title.id || \'qrcode-title\' : null;\nvar size = _this.getModuleCount() * cellSize + margin * 2;\nvar c, mc, r, mr, qrSvg=\'\', rect;\nrect = \'l\' + cellSize + \',0 0,\' + cellSize +\n\' -\' + cellSize + \',0 0,-\' + cellSize + \'z \';\nqrSvg += \'<svg version="1.1" xmlns="http://www.w3.org/2000/svg"\';\nqrSvg += !opts.scalable ? \' width="\' + size + \'px" height="\' + size + \'px"\' : \'\';\nqrSvg += \' viewBox="0 0 \' + size + \' \' + size + \'" \';\nqrSvg += \' preserveAspectRatio="xMinYMin meet"\';\nqrSvg += (title.text || alt.text) ? \' role="img" aria-labelledby="\' +\nescapeXml([title.id, alt.id].join(\' \').trim() ) + \'"\' : \'\';\nqrSvg += \'>\';\nqrSvg += (title.text) ? \'<title id="\' + escapeXml(title.id) + \'">\' +\nescapeXml(title.text) + \'</title>\' : \'\';\nqrSvg += (alt.text) ? \'<description id="\' + escapeXml(alt.id) + \'">\' +\nescapeXml(alt.text) + \'</description>\' : \'\';\nqrSvg += \'<rect width="100%" height="100%" fill="white" cx="0" cy="0"/>\';\nqrSvg += \'<path d="\';\nfor (r = 0; r < _this.getModuleCount(); r += 1) {\nmr = r * cellSize + margin;\nfor (c = 0; c < _this.getModuleCount(); c += 1) {\nif (_this.isDark(r, c) ) {\nmc = c*cellSize+margin;\nqrSvg += \'M\' + mc + \',\' + mr + rect;\n}\n}\n}\nqrSvg += \'" stroke="transparent" fill="black"/>\';\nqrSvg += \'</svg>\';\nreturn qrSvg;\n};\n_this.createDataURL = function(cellSize, margin) {\ncellSize = cellSize || 2;\nmargin = (typeof margin == \'undefined\')? cellSize * 4 : margin;\nvar size = _this.getModuleCount() * cellSize + margin * 2;\nvar min = margin;\nvar max = size - margin;\nreturn createDataURL(size, size, function(x, y) {\nif (min <= x && x < max && min <= y && y < max) {\nvar c = Math.floor( (x - min) / cellSize);\nvar r = Math.floor( (y - min) / cellSize);\nreturn _this.isDark(r, c)? 0 : 1;\n} else {\nreturn 1;\n}\n} );\n};\n_this.createImgTag = function(cellSize, margin, alt) {\ncellSize = cellSize || 2;\nmargin = (typeof margin == \'undefined\')? cellSize * 4 : margin;\nvar size = _this.getModuleCount() * cellSize + margin * 2;\nvar img = \'\';\nimg += \'<img\';\nimg += \'\\u0020src="\';\nimg += _this.createDataURL(cellSize, margin);\nimg += \'"\';\nimg += \'\\u0020width="\';\nimg += size;\nimg += \'"\';\nimg += \'\\u0020height="\';\nimg += size;\nimg += \'"\';\nif (alt) {\nimg += \'\\u0020alt="\';\nimg += escapeXml(alt);\nimg += \'"\';\n}\nimg += \'/>\';\nreturn img;\n};\nvar escapeXml = function(s) {\nvar escaped = \'\';\nfor (var i = 0; i < s.length; i += 1) {\nvar c = s.charAt(i);\nswitch(c) {\ncase \'<\': escaped += \'&lt;\'; break;\ncase \'>\': escaped += \'&gt;\'; break;\ncase \'&\': escaped += \'&amp;\'; break;\ncase \'"\': escaped += \'&quot;\'; break;\ndefault : escaped += c; break;\n}\n}\nreturn escaped;\n};\nvar _createHalfASCII = function(margin) {\nvar cellSize = 1;\nmargin = (typeof margin == \'undefined\')? cellSize * 2 : margin;\nvar size = _this.getModuleCount() * cellSize + margin * 2;\nvar min = margin;\nvar max = size - margin;\nvar y, x, r1, r2, p;\nvar blocks = {\n\'██\': \'█\',\n\'█ \': \'▀\',\n\' █\': \'▄\',\n\'  \': \' \'\n};\nvar blocksLastLineNoMargin = {\n\'██\': \'▀\',\n\'█ \': \'▀\',\n\' █\': \' \',\n\'  \': \' \'\n};\nvar ascii = \'\';\nfor (y = 0; y < size; y += 2) {\nr1 = Math.floor((y - min) / cellSize);\nr2 = Math.floor((y + 1 - min) / cellSize);\nfor (x = 0; x < size; x += 1) {\np = \'█\';\nif (min <= x && x < max && min <= y && y < max && _this.isDark(r1, Math.floor((x - min) / cellSize))) {\np = \' \';\n}\nif (min <= x && x < max && min <= y+1 && y+1 < max && _this.isDark(r2, Math.floor((x - min) / cellSize))) {\np += \' \';\n}\nelse {\np += \'█\';\n}\nascii += (margin < 1 && y+1 >= max) ? blocksLastLineNoMargin[p] : blocks[p];\n}\nascii += \'\\n\';\n}\nif (size % 2 && margin > 0) {\nreturn ascii.substring(0, ascii.length - size - 1) + Array(size+1).join(\'▀\');\n}\nreturn ascii.substring(0, ascii.length-1);\n};\n_this.createASCII = function(cellSize, margin) {\ncellSize = cellSize || 1;\nif (cellSize < 2) {\nreturn _createHalfASCII(margin);\n}\ncellSize -= 1;\nmargin = (typeof margin == \'undefined\')? cellSize * 2 : margin;\nvar size = _this.getModuleCount() * cellSize + margin * 2;\nvar min = margin;\nvar max = size - margin;\nvar y, x, r, p;\nvar white = Array(cellSize+1).join(\'██\');\nvar black = Array(cellSize+1).join(\'  \');\nvar ascii = \'\';\nvar line = \'\';\nfor (y = 0; y < size; y += 1) {\nr = Math.floor( (y - min) / cellSize);\nline = \'\';\nfor (x = 0; x < size; x += 1) {\np = 1;\nif (min <= x && x < max && min <= y && y < max && _this.isDark(r, Math.floor((x - min) / cellSize))) {\np = 0;\n}\nline += p ? white : black;\n}\nfor (r = 0; r < cellSize; r += 1) {\nascii += line + \'\\n\';\n}\n}\nreturn ascii.substring(0, ascii.length-1);\n};\n_this.renderTo2dContext = function(context, cellSize) {\ncellSize = cellSize || 2;\nvar length = _this.getModuleCount();\nfor (var row = 0; row < length; row++) {\nfor (var col = 0; col < length; col++) {\ncontext.fillStyle = _this.isDark(row, col) ? \'black\' : \'white\';\ncontext.fillRect(col * cellSize, row * cellSize, cellSize, cellSize);\n}\n}\n}\nreturn _this;\n};\nqrcode.stringToBytesFuncs = {\n\'default\' : function(s) {\nvar bytes = [];\nfor (var i = 0; i < s.length; i += 1) {\nvar c = s.charCodeAt(i);\nbytes.push(c & 0xff);\n}\nreturn bytes;\n}\n};\nqrcode.stringToBytes = qrcode.stringToBytesFuncs[\'default\'];\n/**\n* @param unicodeData base64 string of byte array.\n* [16bit Unicode],[16bit Bytes], ...\n* @param numChars\n*/\nqrcode.createStringToBytes = function(unicodeData, numChars) {\nvar unicodeMap = function() {\nvar bin = base64DecodeInputStream(unicodeData);\nvar read = function() {\nvar b = bin.read();\nif (b == -1) throw \'eof\';\nreturn b;\n};\nvar count = 0;\nvar unicodeMap = {};\nwhile (true) {\nvar b0 = bin.read();\nif (b0 == -1) break;\nvar b1 = read();\nvar b2 = read();\nvar b3 = read();\nvar k = String.fromCharCode( (b0 << 8) | b1);\nvar v = (b2 << 8) | b3;\nunicodeMap[k] = v;\ncount += 1;\n}\nif (count != numChars) {\nthrow count + \' != \' + numChars;\n}\nreturn unicodeMap;\n}();\nvar unknownChar = \'?\'.charCodeAt(0);\nreturn function(s) {\nvar bytes = [];\nfor (var i = 0; i < s.length; i += 1) {\nvar c = s.charCodeAt(i);\nif (c < 128) {\nbytes.push(c);\n} else {\nvar b = unicodeMap[s.charAt(i)];\nif (typeof b == \'number\') {\nif ( (b & 0xff) == b) {\nbytes.push(b);\n} else {\nbytes.push(b >>> 8);\nbytes.push(b & 0xff);\n}\n} else {\nbytes.push(unknownChar);\n}\n}\n}\nreturn bytes;\n};\n};\nvar QRMode = {\nMODE_NUMBER :    1 << 0,\nMODE_ALPHA_NUM : 1 << 1,\nMODE_8BIT_BYTE : 1 << 2,\nMODE_KANJI :     1 << 3\n};\nvar QRErrorCorrectionLevel = {\nL : 1,\nM : 0,\nQ : 3,\nH : 2\n};\nvar QRMaskPattern = {\nPATTERN000 : 0,\nPATTERN001 : 1,\nPATTERN010 : 2,\nPATTERN011 : 3,\nPATTERN100 : 4,\nPATTERN101 : 5,\nPATTERN110 : 6,\nPATTERN111 : 7\n};\nvar QRUtil = function() {\nvar PATTERN_POSITION_TABLE = [\n[],\n[6, 18],\n[6, 22],\n[6, 26],\n[6, 30],\n[6, 34],\n[6, 22, 38],\n[6, 24, 42],\n[6, 26, 46],\n[6, 28, 50],\n[6, 30, 54],\n[6, 32, 58],\n[6, 34, 62],\n[6, 26, 46, 66],\n[6, 26, 48, 70],\n[6, 26, 50, 74],\n[6, 30, 54, 78],\n[6, 30, 56, 82],\n[6, 30, 58, 86],\n[6, 34, 62, 90],\n[6, 28, 50, 72, 94],\n[6, 26, 50, 74, 98],\n[6, 30, 54, 78, 102],\n[6, 28, 54, 80, 106],\n[6, 32, 58, 84, 110],\n[6, 30, 58, 86, 114],\n[6, 34, 62, 90, 118],\n[6, 26, 50, 74, 98, 122],\n[6, 30, 54, 78, 102, 126],\n[6, 26, 52, 78, 104, 130],\n[6, 30, 56, 82, 108, 134],\n[6, 34, 60, 86, 112, 138],\n[6, 30, 58, 86, 114, 142],\n[6, 34, 62, 90, 118, 146],\n[6, 30, 54, 78, 102, 126, 150],\n[6, 24, 50, 76, 102, 128, 154],\n[6, 28, 54, 80, 106, 132, 158],\n[6, 32, 58, 84, 110, 136, 162],\n[6, 26, 54, 82, 110, 138, 166],\n[6, 30, 58, 86, 114, 142, 170]\n];\nvar G15 = (1 << 10) | (1 << 8) | (1 << 5) | (1 << 4) | (1 << 2) | (1 << 1) | (1 << 0);\nvar G18 = (1 << 12) | (1 << 11) | (1 << 10) | (1 << 9) | (1 << 8) | (1 << 5) | (1 << 2) | (1 << 0);\nvar G15_MASK = (1 << 14) | (1 << 12) | (1 << 10) | (1 << 4) | (1 << 1);\nvar _this = {};\nvar getBCHDigit = function(data) {\nvar digit = 0;\nwhile (data != 0) {\ndigit += 1;\ndata >>>= 1;\n}\nreturn digit;\n};\n_this.getBCHTypeInfo = function(data) {\nvar d = data << 10;\nwhile (getBCHDigit(d) - getBCHDigit(G15) >= 0) {\nd ^= (G15 << (getBCHDigit(d) - getBCHDigit(G15) ) );\n}\nreturn ( (data << 10) | d) ^ G15_MASK;\n};\n_this.getBCHTypeNumber = function(data) {\nvar d = data << 12;\nwhile (getBCHDigit(d) - getBCHDigit(G18) >= 0) {\nd ^= (G18 << (getBCHDigit(d) - getBCHDigit(G18) ) );\n}\nreturn (data << 12) | d;\n};\n_this.getPatternPosition = function(typeNumber) {\nreturn PATTERN_POSITION_TABLE[typeNumber - 1];\n};\n_this.getMaskFunction = function(maskPattern) {\nswitch (maskPattern) {\ncase QRMaskPattern.PATTERN000 :\nreturn function(i, j) { return (i + j) % 2 == 0; };\ncase QRMaskPattern.PATTERN001 :\nreturn function(i, j) { return i % 2 == 0; };\ncase QRMaskPattern.PATTERN010 :\nreturn function(i, j) { return j % 3 == 0; };\ncase QRMaskPattern.PATTERN011 :\nreturn function(i, j) { return (i + j) % 3 == 0; };\ncase QRMaskPattern.PATTERN100 :\nreturn function(i, j) { return (Math.floor(i / 2) + Math.floor(j / 3) ) % 2 == 0; };\ncase QRMaskPattern.PATTERN101 :\nreturn function(i, j) { return (i * j) % 2 + (i * j) % 3 == 0; };\ncase QRMaskPattern.PATTERN110 :\nreturn function(i, j) { return ( (i * j) % 2 + (i * j) % 3) % 2 == 0; };\ncase QRMaskPattern.PATTERN111 :\nreturn function(i, j) { return ( (i * j) % 3 + (i + j) % 2) % 2 == 0; };\ndefault :\nthrow \'bad maskPattern:\' + maskPattern;\n}\n};\n_this.getErrorCorrectPolynomial = function(errorCorrectLength) {\nvar a = qrPolynomial([1], 0);\nfor (var i = 0; i < errorCorrectLength; i += 1) {\na = a.multiply(qrPolynomial([1, QRMath.gexp(i)], 0) );\n}\nreturn a;\n};\n_this.getLengthInBits = function(mode, type) {\nif (1 <= type && type < 10) {\nswitch(mode) {\ncase QRMode.MODE_NUMBER    : return 10;\ncase QRMode.MODE_ALPHA_NUM : return 9;\ncase QRMode.MODE_8BIT_BYTE : return 8;\ncase QRMode.MODE_KANJI     : return 8;\ndefault :\nthrow \'mode:\' + mode;\n}\n} else if (type < 27) {\nswitch(mode) {\ncase QRMode.MODE_NUMBER    : return 12;\ncase QRMode.MODE_ALPHA_NUM : return 11;\ncase QRMode.MODE_8BIT_BYTE : return 16;\ncase QRMode.MODE_KANJI     : return 10;\ndefault :\nthrow \'mode:\' + mode;\n}\n} else if (type < 41) {\nswitch(mode) {\ncase QRMode.MODE_NUMBER    : return 14;\ncase QRMode.MODE_ALPHA_NUM : return 13;\ncase QRMode.MODE_8BIT_BYTE : return 16;\ncase QRMode.MODE_KANJI     : return 12;\ndefault :\nthrow \'mode:\' + mode;\n}\n} else {\nthrow \'type:\' + type;\n}\n};\n_this.getLostPoint = function(qrcode) {\nvar moduleCount = qrcode.getModuleCount();\nvar lostPoint = 0;\nfor (var row = 0; row < moduleCount; row += 1) {\nfor (var col = 0; col < moduleCount; col += 1) {\nvar sameCount = 0;\nvar dark = qrcode.isDark(row, col);\nfor (var r = -1; r <= 1; r += 1) {\nif (row + r < 0 || moduleCount <= row + r) {\ncontinue;\n}\nfor (var c = -1; c <= 1; c += 1) {\nif (col + c < 0 || moduleCount <= col + c) {\ncontinue;\n}\nif (r == 0 && c == 0) {\ncontinue;\n}\nif (dark == qrcode.isDark(row + r, col + c) ) {\nsameCount += 1;\n}\n}\n}\nif (sameCount > 5) {\nlostPoint += (3 + sameCount - 5);\n}\n}\n};\nfor (var row = 0; row < moduleCount - 1; row += 1) {\nfor (var col = 0; col < moduleCount - 1; col += 1) {\nvar count = 0;\nif (qrcode.isDark(row, col) ) count += 1;\nif (qrcode.isDark(row + 1, col) ) count += 1;\nif (qrcode.isDark(row, col + 1) ) count += 1;\nif (qrcode.isDark(row + 1, col + 1) ) count += 1;\nif (count == 0 || count == 4) {\nlostPoint += 3;\n}\n}\n}\nfor (var row = 0; row < moduleCount; row += 1) {\nfor (var col = 0; col < moduleCount - 6; col += 1) {\nif (qrcode.isDark(row, col)\n&& !qrcode.isDark(row, col + 1)\n&&  qrcode.isDark(row, col + 2)\n&&  qrcode.isDark(row, col + 3)\n&&  qrcode.isDark(row, col + 4)\n&& !qrcode.isDark(row, col + 5)\n&&  qrcode.isDark(row, col + 6) ) {\nlostPoint += 40;\n}\n}\n}\nfor (var col = 0; col < moduleCount; col += 1) {\nfor (var row = 0; row < moduleCount - 6; row += 1) {\nif (qrcode.isDark(row, col)\n&& !qrcode.isDark(row + 1, col)\n&&  qrcode.isDark(row + 2, col)\n&&  qrcode.isDark(row + 3, col)\n&&  qrcode.isDark(row + 4, col)\n&& !qrcode.isDark(row + 5, col)\n&&  qrcode.isDark(row + 6, col) ) {\nlostPoint += 40;\n}\n}\n}\nvar darkCount = 0;\nfor (var col = 0; col < moduleCount; col += 1) {\nfor (var row = 0; row < moduleCount; row += 1) {\nif (qrcode.isDark(row, col) ) {\ndarkCount += 1;\n}\n}\n}\nvar ratio = Math.abs(100 * darkCount / moduleCount / moduleCount - 50) / 5;\nlostPoint += ratio * 10;\nreturn lostPoint;\n};\nreturn _this;\n}();\nvar QRMath = function() {\nvar EXP_TABLE = new Array(256);\nvar LOG_TABLE = new Array(256);\nfor (var i = 0; i < 8; i += 1) {\nEXP_TABLE[i] = 1 << i;\n}\nfor (var i = 8; i < 256; i += 1) {\nEXP_TABLE[i] = EXP_TABLE[i - 4]\n^ EXP_TABLE[i - 5]\n^ EXP_TABLE[i - 6]\n^ EXP_TABLE[i - 8];\n}\nfor (var i = 0; i < 255; i += 1) {\nLOG_TABLE[EXP_TABLE[i] ] = i;\n}\nvar _this = {};\n_this.glog = function(n) {\nif (n < 1) {\nthrow \'glog(\' + n + \')\';\n}\nreturn LOG_TABLE[n];\n};\n_this.gexp = function(n) {\nwhile (n < 0) {\nn += 255;\n}\nwhile (n >= 256) {\nn -= 255;\n}\nreturn EXP_TABLE[n];\n};\nreturn _this;\n}();\nfunction qrPolynomial(num, shift) {\nif (typeof num.length == \'undefined\') {\nthrow num.length + \'/\' + shift;\n}\nvar _num = function() {\nvar offset = 0;\nwhile (offset < num.length && num[offset] == 0) {\noffset += 1;\n}\nvar _num = new Array(num.length - offset + shift);\nfor (var i = 0; i < num.length - offset; i += 1) {\n_num[i] = num[i + offset];\n}\nreturn _num;\n}();\nvar _this = {};\n_this.getAt = function(index) {\nreturn _num[index];\n};\n_this.getLength = function() {\nreturn _num.length;\n};\n_this.multiply = function(e) {\nvar num = new Array(_this.getLength() + e.getLength() - 1);\nfor (var i = 0; i < _this.getLength(); i += 1) {\nfor (var j = 0; j < e.getLength(); j += 1) {\nnum[i + j] ^= QRMath.gexp(QRMath.glog(_this.getAt(i) ) + QRMath.glog(e.getAt(j) ) );\n}\n}\nreturn qrPolynomial(num, 0);\n};\n_this.mod = function(e) {\nif (_this.getLength() - e.getLength() < 0) {\nreturn _this;\n}\nvar ratio = QRMath.glog(_this.getAt(0) ) - QRMath.glog(e.getAt(0) );\nvar num = new Array(_this.getLength() );\nfor (var i = 0; i < _this.getLength(); i += 1) {\nnum[i] = _this.getAt(i);\n}\nfor (var i = 0; i < e.getLength(); i += 1) {\nnum[i] ^= QRMath.gexp(QRMath.glog(e.getAt(i) ) + ratio);\n}\nreturn qrPolynomial(num, 0).mod(e);\n};\nreturn _this;\n};\nvar QRRSBlock = function() {\nvar RS_BLOCK_TABLE = [\n[1, 26, 19],\n[1, 26, 16],\n[1, 26, 13],\n[1, 26, 9],\n[1, 44, 34],\n[1, 44, 28],\n[1, 44, 22],\n[1, 44, 16],\n[1, 70, 55],\n[1, 70, 44],\n[2, 35, 17],\n[2, 35, 13],\n[1, 100, 80],\n[2, 50, 32],\n[2, 50, 24],\n[4, 25, 9],\n[1, 134, 108],\n[2, 67, 43],\n[2, 33, 15, 2, 34, 16],\n[2, 33, 11, 2, 34, 12],\n[2, 86, 68],\n[4, 43, 27],\n[4, 43, 19],\n[4, 43, 15],\n[2, 98, 78],\n[4, 49, 31],\n[2, 32, 14, 4, 33, 15],\n[4, 39, 13, 1, 40, 14],\n[2, 121, 97],\n[2, 60, 38, 2, 61, 39],\n[4, 40, 18, 2, 41, 19],\n[4, 40, 14, 2, 41, 15],\n[2, 146, 116],\n[3, 58, 36, 2, 59, 37],\n[4, 36, 16, 4, 37, 17],\n[4, 36, 12, 4, 37, 13],\n[2, 86, 68, 2, 87, 69],\n[4, 69, 43, 1, 70, 44],\n[6, 43, 19, 2, 44, 20],\n[6, 43, 15, 2, 44, 16],\n[4, 101, 81],\n[1, 80, 50, 4, 81, 51],\n[4, 50, 22, 4, 51, 23],\n[3, 36, 12, 8, 37, 13],\n[2, 116, 92, 2, 117, 93],\n[6, 58, 36, 2, 59, 37],\n[4, 46, 20, 6, 47, 21],\n[7, 42, 14, 4, 43, 15],\n[4, 133, 107],\n[8, 59, 37, 1, 60, 38],\n[8, 44, 20, 4, 45, 21],\n[12, 33, 11, 4, 34, 12],\n[3, 145, 115, 1, 146, 116],\n[4, 64, 40, 5, 65, 41],\n[11, 36, 16, 5, 37, 17],\n[11, 36, 12, 5, 37, 13],\n[5, 109, 87, 1, 110, 88],\n[5, 65, 41, 5, 66, 42],\n[5, 54, 24, 7, 55, 25],\n[11, 36, 12, 7, 37, 13],\n[5, 122, 98, 1, 123, 99],\n[7, 73, 45, 3, 74, 46],\n[15, 43, 19, 2, 44, 20],\n[3, 45, 15, 13, 46, 16],\n[1, 135, 107, 5, 136, 108],\n[10, 74, 46, 1, 75, 47],\n[1, 50, 22, 15, 51, 23],\n[2, 42, 14, 17, 43, 15],\n[5, 150, 120, 1, 151, 121],\n[9, 69, 43, 4, 70, 44],\n[17, 50, 22, 1, 51, 23],\n[2, 42, 14, 19, 43, 15],\n[3, 141, 113, 4, 142, 114],\n[3, 70, 44, 11, 71, 45],\n[17, 47, 21, 4, 48, 22],\n[9, 39, 13, 16, 40, 14],\n[3, 135, 107, 5, 136, 108],\n[3, 67, 41, 13, 68, 42],\n[15, 54, 24, 5, 55, 25],\n[15, 43, 15, 10, 44, 16],\n[4, 144, 116, 4, 145, 117],\n[17, 68, 42],\n[17, 50, 22, 6, 51, 23],\n[19, 46, 16, 6, 47, 17],\n[2, 139, 111, 7, 140, 112],\n[17, 74, 46],\n[7, 54, 24, 16, 55, 25],\n[34, 37, 13],\n[4, 151, 121, 5, 152, 122],\n[4, 75, 47, 14, 76, 48],\n[11, 54, 24, 14, 55, 25],\n[16, 45, 15, 14, 46, 16],\n[6, 147, 117, 4, 148, 118],\n[6, 73, 45, 14, 74, 46],\n[11, 54, 24, 16, 55, 25],\n[30, 46, 16, 2, 47, 17],\n[8, 132, 106, 4, 133, 107],\n[8, 75, 47, 13, 76, 48],\n[7, 54, 24, 22, 55, 25],\n[22, 45, 15, 13, 46, 16],\n[10, 142, 114, 2, 143, 115],\n[19, 74, 46, 4, 75, 47],\n[28, 50, 22, 6, 51, 23],\n[33, 46, 16, 4, 47, 17],\n[8, 152, 122, 4, 153, 123],\n[22, 73, 45, 3, 74, 46],\n[8, 53, 23, 26, 54, 24],\n[12, 45, 15, 28, 46, 16],\n[3, 147, 117, 10, 148, 118],\n[3, 73, 45, 23, 74, 46],\n[4, 54, 24, 31, 55, 25],\n[11, 45, 15, 31, 46, 16],\n[7, 146, 116, 7, 147, 117],\n[21, 73, 45, 7, 74, 46],\n[1, 53, 23, 37, 54, 24],\n[19, 45, 15, 26, 46, 16],\n[5, 145, 115, 10, 146, 116],\n[19, 75, 47, 10, 76, 48],\n[15, 54, 24, 25, 55, 25],\n[23, 45, 15, 25, 46, 16],\n[13, 145, 115, 3, 146, 116],\n[2, 74, 46, 29, 75, 47],\n[42, 54, 24, 1, 55, 25],\n[23, 45, 15, 28, 46, 16],\n[17, 145, 115],\n[10, 74, 46, 23, 75, 47],\n[10, 54, 24, 35, 55, 25],\n[19, 45, 15, 35, 46, 16],\n[17, 145, 115, 1, 146, 116],\n[14, 74, 46, 21, 75, 47],\n[29, 54, 24, 19, 55, 25],\n[11, 45, 15, 46, 46, 16],\n[13, 145, 115, 6, 146, 116],\n[14, 74, 46, 23, 75, 47],\n[44, 54, 24, 7, 55, 25],\n[59, 46, 16, 1, 47, 17],\n[12, 151, 121, 7, 152, 122],\n[12, 75, 47, 26, 76, 48],\n[39, 54, 24, 14, 55, 25],\n[22, 45, 15, 41, 46, 16],\n[6, 151, 121, 14, 152, 122],\n[6, 75, 47, 34, 76, 48],\n[46, 54, 24, 10, 55, 25],\n[2, 45, 15, 64, 46, 16],\n[17, 152, 122, 4, 153, 123],\n[29, 74, 46, 14, 75, 47],\n[49, 54, 24, 10, 55, 25],\n[24, 45, 15, 46, 46, 16],\n[4, 152, 122, 18, 153, 123],\n[13, 74, 46, 32, 75, 47],\n[48, 54, 24, 14, 55, 25],\n[42, 45, 15, 32, 46, 16],\n[20, 147, 117, 4, 148, 118],\n[40, 75, 47, 7, 76, 48],\n[43, 54, 24, 22, 55, 25],\n[10, 45, 15, 67, 46, 16],\n[19, 148, 118, 6, 149, 119],\n[18, 75, 47, 31, 76, 48],\n[34, 54, 24, 34, 55, 25],\n[20, 45, 15, 61, 46, 16]\n];\nvar qrRSBlock = function(totalCount, dataCount) {\nvar _this = {};\n_this.totalCount = totalCount;\n_this.dataCount = dataCount;\nreturn _this;\n};\nvar _this = {};\nvar getRsBlockTable = function(typeNumber, errorCorrectionLevel) {\nswitch(errorCorrectionLevel) {\ncase QRErrorCorrectionLevel.L :\nreturn RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 0];\ncase QRErrorCorrectionLevel.M :\nreturn RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 1];\ncase QRErrorCorrectionLevel.Q :\nreturn RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 2];\ncase QRErrorCorrectionLevel.H :\nreturn RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 3];\ndefault :\nreturn undefined;\n}\n};\n_this.getRSBlocks = function(typeNumber, errorCorrectionLevel) {\nvar rsBlock = getRsBlockTable(typeNumber, errorCorrectionLevel);\nif (typeof rsBlock == \'undefined\') {\nthrow \'bad rs block @ typeNumber:\' + typeNumber +\n\'/errorCorrectionLevel:\' + errorCorrectionLevel;\n}\nvar length = rsBlock.length / 3;\nvar list = [];\nfor (var i = 0; i < length; i += 1) {\nvar count = rsBlock[i * 3 + 0];\nvar totalCount = rsBlock[i * 3 + 1];\nvar dataCount = rsBlock[i * 3 + 2];\nfor (var j = 0; j < count; j += 1) {\nlist.push(qrRSBlock(totalCount, dataCount) );\n}\n}\nreturn list;\n};\nreturn _this;\n}();\nvar qrBitBuffer = function() {\nvar _buffer = [];\nvar _length = 0;\nvar _this = {};\n_this.getBuffer = function() {\nreturn _buffer;\n};\n_this.getAt = function(index) {\nvar bufIndex = Math.floor(index / 8);\nreturn ( (_buffer[bufIndex] >>> (7 - index % 8) ) & 1) == 1;\n};\n_this.put = function(num, length) {\nfor (var i = 0; i < length; i += 1) {\n_this.putBit( ( (num >>> (length - i - 1) ) & 1) == 1);\n}\n};\n_this.getLengthInBits = function() {\nreturn _length;\n};\n_this.putBit = function(bit) {\nvar bufIndex = Math.floor(_length / 8);\nif (_buffer.length <= bufIndex) {\n_buffer.push(0);\n}\nif (bit) {\n_buffer[bufIndex] |= (0x80 >>> (_length % 8) );\n}\n_length += 1;\n};\nreturn _this;\n};\nvar qrNumber = function(data) {\nvar _mode = QRMode.MODE_NUMBER;\nvar _data = data;\nvar _this = {};\n_this.getMode = function() {\nreturn _mode;\n};\n_this.getLength = function(buffer) {\nreturn _data.length;\n};\n_this.write = function(buffer) {\nvar data = _data;\nvar i = 0;\nwhile (i + 2 < data.length) {\nbuffer.put(strToNum(data.substring(i, i + 3) ), 10);\ni += 3;\n}\nif (i < data.length) {\nif (data.length - i == 1) {\nbuffer.put(strToNum(data.substring(i, i + 1) ), 4);\n} else if (data.length - i == 2) {\nbuffer.put(strToNum(data.substring(i, i + 2) ), 7);\n}\n}\n};\nvar strToNum = function(s) {\nvar num = 0;\nfor (var i = 0; i < s.length; i += 1) {\nnum = num * 10 + chatToNum(s.charAt(i) );\n}\nreturn num;\n};\nvar chatToNum = function(c) {\nif (\'0\' <= c && c <= \'9\') {\nreturn c.charCodeAt(0) - \'0\'.charCodeAt(0);\n}\nthrow \'illegal char :\' + c;\n};\nreturn _this;\n};\nvar qrAlphaNum = function(data) {\nvar _mode = QRMode.MODE_ALPHA_NUM;\nvar _data = data;\nvar _this = {};\n_this.getMode = function() {\nreturn _mode;\n};\n_this.getLength = function(buffer) {\nreturn _data.length;\n};\n_this.write = function(buffer) {\nvar s = _data;\nvar i = 0;\nwhile (i + 1 < s.length) {\nbuffer.put(\ngetCode(s.charAt(i) ) * 45 +\ngetCode(s.charAt(i + 1) ), 11);\ni += 2;\n}\nif (i < s.length) {\nbuffer.put(getCode(s.charAt(i) ), 6);\n}\n};\nvar getCode = function(c) {\nif (\'0\' <= c && c <= \'9\') {\nreturn c.charCodeAt(0) - \'0\'.charCodeAt(0);\n} else if (\'A\' <= c && c <= \'Z\') {\nreturn c.charCodeAt(0) - \'A\'.charCodeAt(0) + 10;\n} else {\nswitch (c) {\ncase \' \' : return 36;\ncase \'$\' : return 37;\ncase \'%\' : return 38;\ncase \'*\' : return 39;\ncase \'+\' : return 40;\ncase \'-\' : return 41;\ncase \'.\' : return 42;\ncase \'/\' : return 43;\ncase \':\' : return 44;\ndefault :\nthrow \'illegal char :\' + c;\n}\n}\n};\nreturn _this;\n};\nvar qr8BitByte = function(data) {\nvar _mode = QRMode.MODE_8BIT_BYTE;\nvar _data = data;\nvar _bytes = qrcode.stringToBytes(data);\nvar _this = {};\n_this.getMode = function() {\nreturn _mode;\n};\n_this.getLength = function(buffer) {\nreturn _bytes.length;\n};\n_this.write = function(buffer) {\nfor (var i = 0; i < _bytes.length; i += 1) {\nbuffer.put(_bytes[i], 8);\n}\n};\nreturn _this;\n};\nvar qrKanji = function(data) {\nvar _mode = QRMode.MODE_KANJI;\nvar _data = data;\nvar stringToBytes = qrcode.stringToBytesFuncs[\'SJIS\'];\nif (!stringToBytes) {\nthrow \'sjis not supported.\';\n}\n!function(c, code) {\nvar test = stringToBytes(c);\nif (test.length != 2 || ( (test[0] << 8) | test[1]) != code) {\nthrow \'sjis not supported.\';\n}\n}(\'\\u53cb\', 0x9746);\nvar _bytes = stringToBytes(data);\nvar _this = {};\n_this.getMode = function() {\nreturn _mode;\n};\n_this.getLength = function(buffer) {\nreturn ~~(_bytes.length / 2);\n};\n_this.write = function(buffer) {\nvar data = _bytes;\nvar i = 0;\nwhile (i + 1 < data.length) {\nvar c = ( (0xff & data[i]) << 8) | (0xff & data[i + 1]);\nif (0x8140 <= c && c <= 0x9FFC) {\nc -= 0x8140;\n} else if (0xE040 <= c && c <= 0xEBBF) {\nc -= 0xC140;\n} else {\nthrow \'illegal char at \' + (i + 1) + \'/\' + c;\n}\nc = ( (c >>> 8) & 0xff) * 0xC0 + (c & 0xff);\nbuffer.put(c, 13);\ni += 2;\n}\nif (i < data.length) {\nthrow \'illegal char at \' + (i + 1);\n}\n};\nreturn _this;\n};\nvar byteArrayOutputStream = function() {\nvar _bytes = [];\nvar _this = {};\n_this.writeByte = function(b) {\n_bytes.push(b & 0xff);\n};\n_this.writeShort = function(i) {\n_this.writeByte(i);\n_this.writeByte(i >>> 8);\n};\n_this.writeBytes = function(b, off, len) {\noff = off || 0;\nlen = len || b.length;\nfor (var i = 0; i < len; i += 1) {\n_this.writeByte(b[i + off]);\n}\n};\n_this.writeString = function(s) {\nfor (var i = 0; i < s.length; i += 1) {\n_this.writeByte(s.charCodeAt(i) );\n}\n};\n_this.toByteArray = function() {\nreturn _bytes;\n};\n_this.toString = function() {\nvar s = \'\';\ns += \'[\';\nfor (var i = 0; i < _bytes.length; i += 1) {\nif (i > 0) {\ns += \',\';\n}\ns += _bytes[i];\n}\ns += \']\';\nreturn s;\n};\nreturn _this;\n};\nvar base64EncodeOutputStream = function() {\nvar _buffer = 0;\nvar _buflen = 0;\nvar _length = 0;\nvar _base64 = \'\';\nvar _this = {};\nvar writeEncoded = function(b) {\n_base64 += String.fromCharCode(encode(b & 0x3f) );\n};\nvar encode = function(n) {\nif (n < 0) {\n} else if (n < 26) {\nreturn 0x41 + n;\n} else if (n < 52) {\nreturn 0x61 + (n - 26);\n} else if (n < 62) {\nreturn 0x30 + (n - 52);\n} else if (n == 62) {\nreturn 0x2b;\n} else if (n == 63) {\nreturn 0x2f;\n}\nthrow \'n:\' + n;\n};\n_this.writeByte = function(n) {\n_buffer = (_buffer << 8) | (n & 0xff);\n_buflen += 8;\n_length += 1;\nwhile (_buflen >= 6) {\nwriteEncoded(_buffer >>> (_buflen - 6) );\n_buflen -= 6;\n}\n};\n_this.flush = function() {\nif (_buflen > 0) {\nwriteEncoded(_buffer << (6 - _buflen) );\n_buffer = 0;\n_buflen = 0;\n}\nif (_length % 3 != 0) {\nvar padlen = 3 - _length % 3;\nfor (var i = 0; i < padlen; i += 1) {\n_base64 += \'=\';\n}\n}\n};\n_this.toString = function() {\nreturn _base64;\n};\nreturn _this;\n};\nvar base64DecodeInputStream = function(str) {\nvar _str = str;\nvar _pos = 0;\nvar _buffer = 0;\nvar _buflen = 0;\nvar _this = {};\n_this.read = function() {\nwhile (_buflen < 8) {\nif (_pos >= _str.length) {\nif (_buflen == 0) {\nreturn -1;\n}\nthrow \'unexpected end of file./\' + _buflen;\n}\nvar c = _str.charAt(_pos);\n_pos += 1;\nif (c == \'=\') {\n_buflen = 0;\nreturn -1;\n} else if (c.match(/^\\s$/) ) {\ncontinue;\n}\n_buffer = (_buffer << 6) | decode(c.charCodeAt(0) );\n_buflen += 6;\n}\nvar n = (_buffer >>> (_buflen - 8) ) & 0xff;\n_buflen -= 8;\nreturn n;\n};\nvar decode = function(c) {\nif (0x41 <= c && c <= 0x5a) {\nreturn c - 0x41;\n} else if (0x61 <= c && c <= 0x7a) {\nreturn c - 0x61 + 26;\n} else if (0x30 <= c && c <= 0x39) {\nreturn c - 0x30 + 52;\n} else if (c == 0x2b) {\nreturn 62;\n} else if (c == 0x2f) {\nreturn 63;\n} else {\nthrow \'c:\' + c;\n}\n};\nreturn _this;\n};\nvar gifImage = function(width, height) {\nvar _width = width;\nvar _height = height;\nvar _data = new Array(width * height);\nvar _this = {};\n_this.setPixel = function(x, y, pixel) {\n_data[y * _width + x] = pixel;\n};\n_this.write = function(out) {\nout.writeString(\'GIF87a\');\nout.writeShort(_width);\nout.writeShort(_height);\nout.writeByte(0x80); // 2bit\nout.writeByte(0);\nout.writeByte(0);\nout.writeByte(0x00);\nout.writeByte(0x00);\nout.writeByte(0x00);\nout.writeByte(0xff);\nout.writeByte(0xff);\nout.writeByte(0xff);\nout.writeString(\',\');\nout.writeShort(0);\nout.writeShort(0);\nout.writeShort(_width);\nout.writeShort(_height);\nout.writeByte(0);\nvar lzwMinCodeSize = 2;\nvar raster = getLZWRaster(lzwMinCodeSize);\nout.writeByte(lzwMinCodeSize);\nvar offset = 0;\nwhile (raster.length - offset > 255) {\nout.writeByte(255);\nout.writeBytes(raster, offset, 255);\noffset += 255;\n}\nout.writeByte(raster.length - offset);\nout.writeBytes(raster, offset, raster.length - offset);\nout.writeByte(0x00);\nout.writeString(\';\');\n};\nvar bitOutputStream = function(out) {\nvar _out = out;\nvar _bitLength = 0;\nvar _bitBuffer = 0;\nvar _this = {};\n_this.write = function(data, length) {\nif ( (data >>> length) != 0) {\nthrow \'length over\';\n}\nwhile (_bitLength + length >= 8) {\n_out.writeByte(0xff & ( (data << _bitLength) | _bitBuffer) );\nlength -= (8 - _bitLength);\ndata >>>= (8 - _bitLength);\n_bitBuffer = 0;\n_bitLength = 0;\n}\n_bitBuffer = (data << _bitLength) | _bitBuffer;\n_bitLength = _bitLength + length;\n};\n_this.flush = function() {\nif (_bitLength > 0) {\n_out.writeByte(_bitBuffer);\n}\n};\nreturn _this;\n};\nvar getLZWRaster = function(lzwMinCodeSize) {\nvar clearCode = 1 << lzwMinCodeSize;\nvar endCode = (1 << lzwMinCodeSize) + 1;\nvar bitLength = lzwMinCodeSize + 1;\nvar table = lzwTable();\nfor (var i = 0; i < clearCode; i += 1) {\ntable.add(String.fromCharCode(i) );\n}\ntable.add(String.fromCharCode(clearCode) );\ntable.add(String.fromCharCode(endCode) );\nvar byteOut = byteArrayOutputStream();\nvar bitOut = bitOutputStream(byteOut);\nbitOut.write(clearCode, bitLength);\nvar dataIndex = 0;\nvar s = String.fromCharCode(_data[dataIndex]);\ndataIndex += 1;\nwhile (dataIndex < _data.length) {\nvar c = String.fromCharCode(_data[dataIndex]);\ndataIndex += 1;\nif (table.contains(s + c) ) {\ns = s + c;\n} else {\nbitOut.write(table.indexOf(s), bitLength);\nif (table.size() < 0xfff) {\nif (table.size() == (1 << bitLength) ) {\nbitLength += 1;\n}\ntable.add(s + c);\n}\ns = c;\n}\n}\nbitOut.write(table.indexOf(s), bitLength);\nbitOut.write(endCode, bitLength);\nbitOut.flush();\nreturn byteOut.toByteArray();\n};\nvar lzwTable = function() {\nvar _map = {};\nvar _size = 0;\nvar _this = {};\n_this.add = function(key) {\nif (_this.contains(key) ) {\nthrow \'dup key:\' + key;\n}\n_map[key] = _size;\n_size += 1;\n};\n_this.size = function() {\nreturn _size;\n};\n_this.indexOf = function(key) {\nreturn _map[key];\n};\n_this.contains = function(key) {\nreturn typeof _map[key] != \'undefined\';\n};\nreturn _this;\n};\nreturn _this;\n};\nvar createDataURL = function(width, height, getPixel) {\nvar gif = gifImage(width, height);\nfor (var y = 0; y < height; y += 1) {\nfor (var x = 0; x < width; x += 1) {\ngif.setPixel(x, y, getPixel(x, y) );\n}\n}\nvar b = byteArrayOutputStream();\ngif.write(b);\nvar base64 = base64EncodeOutputStream();\nvar bytes = b.toByteArray();\nfor (var i = 0; i < bytes.length; i += 1) {\nbase64.writeByte(bytes[i]);\n}\nbase64.flush();\nreturn \'data:image/gif;base64,\' + base64;\n};\nreturn qrcode;\n}();\n!function() {\nqrcode.stringToBytesFuncs[\'UTF-8\'] = function(s) {\nfunction toUTF8Array(str) {\nvar utf8 = [];\nfor (var i=0; i < str.length; i++) {\nvar charcode = str.charCodeAt(i);\nif (charcode < 0x80) utf8.push(charcode);\nelse if (charcode < 0x800) {\nutf8.push(0xc0 | (charcode >> 6),\n0x80 | (charcode & 0x3f));\n}\nelse if (charcode < 0xd800 || charcode >= 0xe000) {\nutf8.push(0xe0 | (charcode >> 12),\n0x80 | ((charcode>>6) & 0x3f),\n0x80 | (charcode & 0x3f));\n}\nelse {\ni++;\ncharcode = 0x10000 + (((charcode & 0x3ff)<<10)\n| (str.charCodeAt(i) & 0x3ff));\nutf8.push(0xf0 | (charcode >>18),\n0x80 | ((charcode>>12) & 0x3f),\n0x80 | ((charcode>>6) & 0x3f),\n0x80 | (charcode & 0x3f));\n}\n}\nreturn utf8;\n}\nreturn toUTF8Array(s);\n};\n}();\nqrcode.stringToBytes = qrcode.stringToBytesFuncs[\'UTF-8\'];\nfunction qrMake(link){try{var qr=qrcode(0,\"M\");qr.addData(link,\"Byte\");qr.make();return {size:qr.getModuleCount(),get:function(r,c){return qr.isDark(r,c)?1:0;}};}catch(e){return null;}}\nfunction showQR(name,link,dtxt,copied){var qlink=link+(link.indexOf("?")>=0?"&":"?")+"dl=1";var old=document.getElementById("qrmask");if(old)old.parentNode.removeChild(old);var cv=null;if(window.__qrCache&&window.__qrCache[qlink]){cv=window.__qrCache[qlink];}else{var q=qrMake(qlink);if(!q){gmsg("链接过长，无法生成二维码",false);return;}var S=q.size;var px=Math.max(4,Math.min(9,Math.floor(300/(S+8))));cv=document.createElement("canvas");cv.width=(S+8)*px;cv.height=(S+8)*px;cv.style.width=((S+8)*px)+"px";cv.style.height=((S+8)*px)+"px";var g=cv.getContext("2d");g.fillStyle="#ffffff";g.fillRect(0,0,cv.width,cv.height);g.fillStyle="#000000";for(var r=0;r<S;r++)for(var c=0;c<S;c++)if(q.get(r,c))g.fillRect((c+4)*px,(r+4)*px,px,px);try{window.__qrCache=window.__qrCache||{};window.__qrCache[qlink]=cv;}catch(_){}}cv.style.cursor="pointer";cv.title="点击打开此二维码对应的链接";cv.onclick=function(){try{window.open(qlink,"_blank");}catch(e){location.href=qlink;}};var box=document.createElement("div");box.id="qrmask";box.className="qrmask";var card=document.createElement("div");card.className="qrbox";var h=document.createElement("div");h.style.cssText="font-size:15px;font-weight:600;margin-bottom:6px;text-align:center;white-space:normal;word-break:break-all;overflow-wrap:anywhere";h.textContent=name;var tip=document.createElement("div");tip.style.cssText="color:#6b7280;font-size:12px;margin-bottom:12px";tip.textContent="手机扫码直接下载"+(dtxt?("（"+dtxt+"）"):"");var lk=document.createElement("div");lk.style.cssText="margin-top:14px;font-size:12px;color:#374151;word-break:break-all";lk.className="mono";lk.textContent=link;var cp=document.createElement("div");cp.style.cssText="margin-top:6px;font-size:12px;font-weight:600;"+(copied?"color:#16a34a":"color:#dc2626");cp.textContent=copied?"链接已复制到剪贴板 ✓":"请手动复制下方链接";var cb=document.createElement("button");cb.className="btn ghost";cb.style.marginTop="14px";cb.textContent="关闭";cb.onclick=function(){box.parentNode.removeChild(box);};card.appendChild(h);card.appendChild(tip);card.appendChild(cv);card.appendChild(lk);card.appendChild(cp);card.appendChild(cb);box.appendChild(card);box.onclick=function(ev){if(ev.target===box)box.parentNode.removeChild(box);};document.body.appendChild(box);}\nvar queue=[],busy=0;\nfunction addFiles(files){for(var i=0;i<files.length;i++){var item={f:files[i],state:"wait",xhrs:[],cancelled:false};item.el=makeCard(item);document.getElementById("ups").prepend(item.el);queue.push(item);}refreshQueue();pump();}\nfunction makeCard(item){var div=document.createElement("div");div.className="up";var row=document.createElement("div");row.className="row";row.style.justifyContent="space-between";var b=document.createElement("b");b.textContent=item.f.name;b.title=item.f.name;b.className="fname";var right=document.createElement("span");right.className="row";var st=document.createElement("span");var btn2=document.createElement("button");btn2.className="btn small ghost";btn2.textContent="插队";btn2.onclick=function(){promoteItem(item);};btn2.style.display="none";var btn=document.createElement("button");btn.className="btn small danger";btn.textContent="取消";btn.onclick=function(){cancelItem(item);};right.appendChild(btn2);right.appendChild(st);right.appendChild(btn);row.appendChild(b);row.appendChild(right);var bar=document.createElement("div");bar.className="bar";bar.style.display="none";bar.innerHTML="<div></div>";var info=document.createElement("div");info.style.color="#6b7280";info.style.fontSize="12px";div.appendChild(row);div.appendChild(bar);div.appendChild(info);item.qTxt=st;item.bar=bar;item.barIn=bar.firstChild;item.info=info;item.btn2=btn2;return div;}\nfunction refreshQueue(){for(var i=0;i<queue.length;i++){var it=queue[i];if(it.state==="wait"){var ahead=0;for(var j=0;j<i;j++){if(queue[j].state==="wait")ahead++;}it.qTxt.textContent=ahead>0?("等待中（前面还有 "+ahead+" 个）"):"下一个待传";it.btn2.style.display="inline";it.bar.style.display="none";it.info.textContent="大小 "+fmtSize(it.f.size);}else if(it.state==="up"){it.qTxt.textContent="上传中…";it.btn2.style.display="none";}else{it.btn2.style.display="none";}}}\nfunction pump(){if(busy>0)return;var next=null;for(var i=0;i<queue.length;i++){if(queue[i].state==="wait"){next=queue[i];break;}}if(!next)return;busy=1;next.state="up";refreshQueue();startUpload(next);}\nfunction cancelItem(item){item.cancelled=true;var wasUp=item.state==="up";for(var i=0;i<item.xhrs.length;i++){try{item.xhrs[i].abort();}catch(_){}}if(wasUp&&item.uploadId&&item.key){try{fetch("/api/abort",{method:"POST",headers:{"content-type":"application/json","x-auth-token":TOKEN},body:JSON.stringify({key:item.key,uploadId:item.uploadId})});}catch(e){}}try{localStorage.removeItem(resumeKey(item.f));}catch(e){}item.qTxt.textContent="已取消";item.bar.style.display="none";item.info.textContent="该任务已中止，可重新选择文件重传";item.btn2.style.display="none";setTimeout(function(){var idx=queue.indexOf(item);if(idx>=0)queue.splice(idx,1);item.el.remove();if(wasUp){busy=0;refreshQueue();pump();}else{refreshQueue();}},1200);}\nfunction promoteItem(item){if(item.state!=="wait")return;var firstWait=-1;for(var i=0;i<queue.length;i++){if(queue[i].state==="wait"){firstWait=i;break;}}var idx=queue.indexOf(item);if(firstWait<0||idx===firstWait)return;queue.splice(idx,1);queue.splice(firstWait,0,item);refreshQueue();}\nfunction resumeKey(f){return "fh_up|"+f.name+"|"+f.size;}\nfunction xhrPut(url,blob,onProg){var x=new XMLHttpRequest();var p=new Promise(function(res,rej){x.open("PUT",url);x.setRequestHeader("x-auth-token",TOKEN);x.upload.onprogress=function(e){if(e.lengthComputable&&onProg)onProg(e.loaded,e.total);};x.onload=function(){var j=null;try{j=JSON.parse(x.responseText);}catch(_){j=null;}if(x.status>=200&&x.status<300&&j)res(j);else rej(new Error((j&&j.error)||("HTTP"+x.status)));};x.onerror=function(){rej(new Error("网络错误"));};x.send(blob);});p._x=x;return p;}\nfunction startUpload(item){var f=item.f,total=f.size,t0=Date.now();var doneMap={},curMap={},chunkSize=0,pc=0,key="",uploadId="",mode="",fileHash="";var prevT=Date.now(),sentB=0,v=null,timer=null,finished=false;\nfunction calcHash(){\nif(f.size>512*1048576){return Promise.resolve("");}\nreturn f.arrayBuffer().then(function(ab){return crypto.subtle.digest("SHA-256",ab);})\n.then(function(dg){return Array.from(new Uint8Array(dg)).map(function(b){return b.toString(16).padStart(2,"0");}).join("");});}\nfunction show(){if(finished||item.cancelled)return;var bytes=0,kk;for(kk in doneMap)bytes+=Math.min(chunkSize||total,total-(Number(kk)-1)*(chunkSize||total));for(kk in curMap)bytes+=curMap[kk];var now=Date.now(),dt=(now-prevT)/1000;prevT=now;var inst=dt>0.2?(bytes-sentB)/dt:0;sentB=bytes;if(isFinite(inst)&&inst>0){v=(v==null)?inst:v*0.7+inst*0.3;}else if(v==null){v=0;}var pct=total?Math.min(100,(bytes/total)*95+((pc>0?Object.keys(doneMap).length/pc:1))*5):100;var eta=v>120?Math.round((total-bytes)/v):0;var pTxt=pc>0?("分片 "+Object.keys(doneMap).length+"/"+pc+" · "):"";item.qTxt.textContent=pTxt+fmtSize(bytes)+" / "+fmtSize(total);item.bar.style.display="";item.barIn.style.width=pct+"%";item.info.textContent="大小 "+fmtSize(total)+" · 速度 "+(v>120?fmtSize(Math.round(v))+"/s":"—")+" · 进度 "+pct.toFixed(0)+"% · 预计剩余 "+fmtEta(eta);}\ntimer=setInterval(show,500);\nfunction settle(){if(timer){clearInterval(timer);timer=null;}}\nvar rawSt=JSON.parse(localStorage.getItem(resumeKey(f))||"null");\nvar st=(rawSt&&rawSt.name===f.name&&rawSt.size===f.size&&rawSt.uploadId&&rawSt.done)?rawSt:null;\nif(st){chunkSize=st.chunkSize;doneMap=st.done||{};}\nshow();\ncalcHash().then(function(fh){fileHash=fh;return api("POST","/api/init",{name:f.name,size:f.size,mime:f.type||"",hash:fileHash,dir:CUR_DIR,resume:st?{key:st.key,uploadId:st.uploadId}:null});}).then(function(res){if(item.cancelled)return;if(res.dup){settle();finished=true;key=res.key;item.state="done";item.qTxt.textContent="秒传成功 ✓";item.bar.style.display="none";item.info.textContent="大小 "+fmtSize(total)+"（服务器已有相同文件，免上传）";gmsg("【"+esc(f.name)+"】秒传成功（已存在相同内容文件）",true);refresh();return;}chunkSize=res.chunkSize;pc=res.partCount;key=res.key;uploadId=res.uploadId;mode=res.mode;item.uploadId=uploadId;item.key=key;if(!(st&&st.key===key&&st.uploadId===uploadId&&st.chunkSize===chunkSize)){doneMap={};}if(mode==="direct"){var attD=0;function tryDirect(){var xp=xhrPut("/api/direct?key="+encodeURIComponent(key)+"&hash="+encodeURIComponent(fileHash||""),f,function(loaded){curMap[0]=loaded;show();});item.xhrs.push(xp._x);return xp.then(function(j){if(j.error)throw new Error(j.error);settle();finished=true;localStorage.removeItem(resumeKey(f));item.state="done";item.qTxt.textContent="上传完成 ✓";item.bar.style.display="none";item.info.textContent="大小 "+fmtSize(total);gmsg("【"+esc(f.name)+"】上传成功",true);refresh();},function(e){if(item.cancelled)throw e;attD++;if(attD<3){item.info.textContent="网络波动，第"+attD+"次自动重试中…";return new Promise(function(res2){setTimeout(function(){res2(tryDirect());},800*attD);});}throw e;});}return tryDirect();}var todo=[];for(var n=1;n<=pc;n++){if(!doneMap[n])todo.push(n);}function save(){localStorage.setItem(resumeKey(f),JSON.stringify({name:f.name,size:f.size,key:key,uploadId:uploadId,chunkSize:chunkSize,done:doneMap}));}var active=0,stop=false,finishCb=null;function one(n){var off=(n-1)*chunkSize,blob=f.slice(off,Math.min(off+chunkSize,total));var att=0;function attempt(){var xp2=xhrPut("/api/part?key="+encodeURIComponent(key)+"&uploadId="+encodeURIComponent(uploadId)+"&partNumber="+n,blob,function(loaded){curMap[n]=loaded;show();});item.xhrs.push(xp2._x);return xp2.catch(function(e){if(item.cancelled)throw e;att++;if(att>RETRY)throw e;return attempt();});}return attempt().then(function(j){doneMap[n]=j.etag;delete curMap[n];sentB=0;prevT=Date.now();save();show();});}function runner(){while(active<CONC){var n2=todo.shift();if(n2===undefined)break;if(doneMap[n2])continue;active++;one(n2).then(next,fail);}}function fail(e){active--;stop=true;settle();if(finishCb)finishCb(e);}function next(){active--;runner();if(active===0&&todo.length===0&&!stop){var plist=[];for(var n3=1;n3<=pc;n3++){if(doneMap[n3])plist.push([n3,doneMap[n3]]);}if(plist.length<pc){stop=true;if(finishCb)finishCb(new Error("分片缺失"));return;}settle();finished=true;item.qTxt.textContent="正在合并分片…";item.bar.style.display="none";api("POST","/api/complete",{key:key,uploadId:uploadId,parts:plist,mode:mode,hash:fileHash,size:total}).then(function(){localStorage.removeItem(resumeKey(f));item.state="done";item.qTxt.textContent="上传完成 ✓";item.info.textContent="大小 "+fmtSize(total);gmsg("【"+esc(f.name)+"】上传成功",true);refresh();if(finishCb)finishCb(null);},function(e){gmsg("【"+esc(f.name)+"】合并失败："+esc(e.message||""),false);if(finishCb)finishCb(e);});}}return new Promise(function(res2,rej2){finishCb=function(e){finishCb=null;if(e)rej2(e);else res2();};runner();});}).then(function(){busy=0;refreshQueue();pump();},function(e){settle();if(!item.cancelled){item.state="fail";item.qTxt.textContent="上传失败";item.bar.style.display="none";item.info.textContent=(e&&e.message)||"未知错误";}busy=0;refreshQueue();pump();});}\nvar logOffset=0,logTotal=-1,logSortCol="id",logSortDir="desc";\nfunction sortBy(col){\n  if(logSortCol===col){logSortDir=logSortDir==="asc"?"desc":"asc";}\n  else{logSortCol=col;logSortDir="asc";}\n  updateSortArrows();loadLog(true);\n}\nfunction updateSortArrows(){\n  var cols=["file_name","action","log_time","ip"];\n  cols.forEach(function(c){\n    var el=document.getElementById("sa-"+c);\n    if(el){el.textContent=(logSortCol===c)?(logSortDir==="asc"?" ↑":" ↓"):"";}\n  });\n}\nfunction loadMoreLog(){loadLog(false);}\nfunction loadLog(reset){\n  if(reset){logOffset=0;logTotal=-1;}\n  api("GET","/api/log?offset="+logOffset+"&limit=10&sort="+logSortCol+"&dir="+logSortDir).then(function(j){\n    logTotal=j.total;\n    var tb=document.getElementById("logTb");\n    if(logOffset===0){tb.innerHTML="";}\n    j.items.forEach(function(r,idx){\n      var tr=document.createElement("tr");\n      var actMap={"upload":"上传","download":"下载","move":"移动","rename":"重命名","mkdir":"新建文件夹","share":"分享","unshare":"取消分享","delete":"删除"};var act=r.action&&actMap[r.action]?actMap[r.action]:(r.action||"其他");var actColor={"upload":"#2563eb","download":"#059669","move":"#7c3aed","rename":"#0891b2","mkdir":"#d97706","share":"#db2777","unshare":"#b45309","delete":"#dc2626"}[r.action]||"#374151";\n      tr.innerHTML="<td>"+(logOffset+idx+1)+"</td><td class=\'fname\' title=\'"+esc(r.file_name)+"\'>"+esc(r.file_name)+"</td><td style=\'color:"+actColor+";font-weight:600\'>"+act+"</td><td style=\'white-space:nowrap\'>"+fmtTime(r.log_time)+"</td><td>"+esc(r.ip)+"</td><td>"+esc(r.os)+" / "+esc(r.browser)+"</td>";\n      tb.appendChild(tr);\n    });\n    logOffset+=j.items.length;\n    var more=document.getElementById("logMoreBtn");\n    if(more){\n      if(logTotal>=0&&logOffset>=logTotal){more.textContent="已全部加载（共"+logTotal+"条）";more.disabled=true;}\n      else{more.textContent="加载更多";more.disabled=false;}\n    }\n  },function(e){gmsg("记录加载失败："+esc(e.message),false);});\n}\n(function(){\n  var cols=["file_name","action","log_time","ip"];\n  cols.forEach(function(c){\n    var th=document.getElementById("th-"+c);\n    if(th){th.style.cursor="pointer";th.onclick=function(){sortBy(c);};}\n  });\n})();\nvar CUR_DIR="";function renderCrumb(){var c=document.getElementById("crumb");if(!c)return;c.innerHTML="";var rel=CUR_DIR;if(rel.length&&rel.charAt(rel.length-1)===String.fromCharCode(47))rel=rel.slice(0,-1);var segs=rel.length?rel.split(String.fromCharCode(47)):[];var acc="";var h0=document.createElement("a");h0.href="javascript:void(0)";h0.textContent="全部文件";h0.style.color="#2563eb";h0.style.textDecoration="none";h0.onclick=function(){CUR_DIR="";refresh();};c.appendChild(h0);segs.forEach(function(s){acc+=s+String.fromCharCode(47);var sp=document.createElement("span");sp.textContent=String.fromCharCode(47);sp.style.color="#9ca3af";sp.style.margin="0 4px";c.appendChild(sp);var a=document.createElement("a");a.href="javascript:void(0)";a.textContent=s;a.style.color="#2563eb";a.style.textDecoration="none";var d=acc;a.onclick=function(){CUR_DIR=d;refresh();};c.appendChild(a);});}function doMkdir(){var n=prompt("新文件夹叫什么");if(n===null)return;n=String(n).trim();if(!n)return;api("POST","/api/mkdir",{parent:CUR_DIR,name:n}).then(function(){gmsg("文件夹【"+esc(n)+"】建好了",true);refresh();},function(e){gmsg("没建成："+esc(e.message),false);});}function doBatchShare(){var items=[];document.querySelectorAll(".rowchk:checked").forEach(function(c){var key=decodeURIComponent(c.getAttribute("data-key"));if(!key||!key.startsWith("files/"))return;var row=c.closest("tr");var sel=row?row.querySelector("select"):null;var days=sel?Number(sel.value||"30"):30;items.push({key:key,days:days});});if(!items.length){gmsg("先勾选要分享的文件（文件夹不能分享）",false);return;}var perm=0,mx=0;items.forEach(function(it){var d=Number(it.days);if(d===0)perm=1;else if(d>mx)mx=d;});var dtxt=perm?"永久":(mx+"天");var bnm="批量分享（"+items.length+"个文件）";api("POST","/api/batch-share",{items:items}).then(function(r){if(!r||!r.link){gmsg("生成分享页失败",false);return;}tryClip(r.link,function(){showQR(bnm,r.link,dtxt,true);},function(){showQR(bnm,r.link,dtxt,false);});},function(e){gmsg("生成分享页失败："+esc(e.message),false);});} function doMove(){var keys=getSelKeys();if(!keys.length){gmsg("先勾选要搬的文件",false);return;}var sel=document.getElementById("moveDest");sel.innerHTML="";var o0=document.createElement("option");o0.value="";o0.textContent="全部文件（根目录）";sel.appendChild(o0);(window.__curFolders||[]).forEach(function(fd){var o=document.createElement("option");o.value=fd.path;o.textContent=fd.name;sel.appendChild(o);});document.getElementById("moveBox").style.display="block";}function goMove(){var keys=getSelKeys();if(!keys.length){gmsg("先勾选要搬的文件",false);return;}var dest=document.getElementById("moveDest").value;var btn=document.getElementById("moveGo");btn.disabled=true;btn.textContent="搬ing…";api("POST","/api/move",{keys:keys,dest:dest}).then(function(r){btn.disabled=false;btn.textContent="确定";document.getElementById("moveBox").style.display="none";if(r.fail===0){gmsg("搬好了 "+r.ok+" 个，分享链接不受影响",true);}else{gmsg("搬完："+r.ok+" 成功 / "+r.fail+" 失败"+((r.errors&&r.errors.length)?("（"+esc(r.errors[0])+"）"):""),false);}refresh();},function(e){btn.disabled=false;btn.textContent="确定";gmsg("没搬成："+esc(e.message),false);});}function refresh(){api("GET","/api/list?path="+encodeURIComponent(CUR_DIR)).then(function(j){window.__curFolders=j.folders||[];renderCrumb();document.getElementById("stat").textContent="共 "+j.count+" 个文件 · 额度统计中…";fetch("/api/usage",{headers:{"x-auth-token":TOKEN}}).then(function(r2){return r2.json()}).then(function(u){if(u&&u.used>=0)document.getElementById("stat").textContent="共 "+j.count+" 个文件 · 已用 "+fmtSize(u.used)+" / 20GB";});var tb=document.getElementById("tb");tb.innerHTML="";(j.folders||[]).forEach(function(fd){var ftr=document.createElement("tr");var ftd0=document.createElement("td");ftr.appendChild(ftd0);var ftd1=document.createElement("td");var fa=document.createElement("a");fa.href="javascript:void(0)";fa.textContent="\ud83d\udcc1 "+fd.name;fa.style.color="#2563eb";fa.style.textDecoration="none";fa.style.fontWeight="600";fa.onclick=function(){CUR_DIR=fd.path;refresh();};ftd1.appendChild(fa);ftr.appendChild(ftd1);var ftd2=document.createElement("td");ftd2.textContent="—";ftd2.style.color="#d1d5db";ftr.appendChild(ftd2);var ftd3=document.createElement("td");if(fd.created)ftd3.textContent=fmtTime(fd.created);ftd3.style.whiteSpace="nowrap";ftd3.style.color="#6b7280";ftr.appendChild(ftd3);var fop=document.createElement("td");fop.className="row";fop.style.flexWrap="nowrap";fop.style.whiteSpace="nowrap";fop.style.justifyContent="flex-end";fop.style.textAlign="right";var fb4=document.createElement("button");fb4.className="btn small ghost";fb4.textContent="重命名";fb4.onclick=function(){var nv=prompt("文件夹改成什么名字",fd.name);if(nv===null)return;nv=String(nv).trim();if(!nv||nv===fd.name)return;api("POST","/api/rename",{path:fd.path,name:nv}).then(function(){gmsg("文件夹改名成功",true);refresh();},function(e){gmsg("改名失败："+esc(e.message),false);});};var fb5=document.createElement("button");fb5.className="btn small danger";fb5.textContent="删除";fb5.onclick=function(){if(!confirm("删掉文件夹【"+fd.name+"】？（空的才能删）"))return;api("POST","/api/rmdir",{path:fd.path}).then(function(){gmsg("文件夹【"+esc(fd.name)+"】已删",true);refresh();},function(e){gmsg("删不掉："+esc(e.message),false);});};fop.appendChild(makeDots([{label:"重命名",onclick:function(){fb4.onclick();}},{label:"删除",danger:true,onclick:function(){fb5.onclick();}}]));ftr.appendChild(fop);tb.appendChild(ftr);});j.items.forEach(function(it){var tr=document.createElement("tr");var chk=document.createElement("input");chk.type="checkbox";chk.className="rowchk";chk.setAttribute("data-key",encodeURIComponent(it.key));var td0=document.createElement("td");td0.appendChild(chk);tr.appendChild(td0);tr.innerHTML+="<td class=\'fname\' title=\'"+esc(it.name)+"\'>"+esc(it.name)+"</td><td>"+fmtSize(it.size)+"</td><td style=\'white-space:nowrap\'>"+fmtTime(it.mtime)+"</td><td></td>";var op=tr.lastChild;op.className="row";op.style.flexWrap="nowrap";op.style.whiteSpace="nowrap";op.style.justifyContent="flex-end";op.style.textAlign="right";var sel=document.createElement("select");sel.innerHTML=\'<option value="30">30天</option><option value="7">7天</option><option value="1">1天</option><option value="365">365天</option><option value="0">永久</option>\';var b1=document.createElement("button");b1.className="btn small ghost";b1.textContent="复制链接";b1.onclick=function(){var ck=it.key+"|"+sel.value;var dtxt=sel.options[sel.selectedIndex].text;function cOK(link){copyFeedback(b1,"已复制 ✓",false);showQR(it.name,link,dtxt,true);}function cNO(link){copyFeedback(b1,"请手动复制",true);showQR(it.name,link,dtxt,false);}if(window.__shareCache&&window.__shareCache[ck]){var c=window.__shareCache[ck];tryClip(c,function(){cOK(c);},function(){cNO(c);});return;}copyFeedback(b1,"生成中…",false);b1.disabled=true;api("GET","/api/share?key="+encodeURIComponent(it.key)+"&days="+sel.value).then(function(r){try{window.__shareCache=window.__shareCache||{};window.__shareCache[ck]=r.link;}catch(_){}tryClip(r.link,function(){cOK(r.link);},function(){cNO(r.link);});},function(e){copyFeedback(b1,"生成失败",true);gmsg("生成链接失败："+esc(e.message),false);});};var b2=document.createElement("button");b2.className="btn small ghost";b2.textContent="下载";b2.onclick=function(){copyFeedback(b2,"取链接…",false);api("GET","/api/share?key="+encodeURIComponent(it.key)+"&days=0&dl=1").then(function(r){copyFeedback(b2,"已开始 ✓",false);setTimeout(function(){location.href=r.link;},320);},function(e){copyFeedback(b2,"下载失败",true);gmsg("下载失败："+esc(e.message),false);});};var bq=document.createElement("button");bq.className="btn small ghost";bq.textContent="二维码";bq.onclick=function(){var ck=it.key+"|1";var dtxt="1天";function open(link){tryClip(link,function(){showQR(it.name,link,dtxt,true);},function(){showQR(it.name,link,dtxt,false);});}if(window.__shareCache&&window.__shareCache[ck]){open(window.__shareCache[ck]);return;}copyFeedback(bq,"生成中…",false);bq.disabled=true;api("GET","/api/share?key="+encodeURIComponent(it.key)+"&days=1").then(function(r){try{window.__shareCache=window.__shareCache||{};window.__shareCache[ck]=r.link;}catch(_){}copyFeedback(bq,"已打开 ✓",false);open(r.link);},function(e){copyFeedback(bq,"失败",true);gmsg("生成二维码失败："+esc(e.message),false);});};var b3=document.createElement("button");b3.className="btn small danger";b3.textContent="删除";b3.onclick=function(){if(!confirm("确定删除【"+it.name+"】？"))return;api("DELETE","/api/file?key="+encodeURIComponent(it.key)).then(function(){try{if(window.__shareCache){for(var k in window.__shareCache){if(k.indexOf(it.key+"|")===0)delete window.__shareCache[k];}}}catch(_){}gmsg("已删除："+esc(it.name),true);refresh();},function(e){gmsg("删除失败："+esc(e.message),false);});};var br=document.createElement("button");br.className="btn small ghost";br.textContent="重命名";br.onclick=function(){var nv=prompt("改成什么名字",it.name);if(nv===null)return;nv=String(nv).trim();if(!nv||nv===it.name)return;br.disabled=true;br.textContent="改ing…";api("POST","/api/rename",{key:it.key,name:nv}).then(function(){try{if(window.__shareCache){for(var kk in window.__shareCache){if(kk.indexOf(it.key+"|")===0)delete window.__shareCache[kk];}}}catch(_){}gmsg("改名成功，分享链接照常用",true);refresh();},function(e){gmsg("改名失败："+esc(e.message),false);br.disabled=false;br.textContent="重命名";});};op.appendChild(sel);op.appendChild(b1);op.appendChild(b2);op.appendChild(bq);op.appendChild(makeDots([{label:"重命名",onclick:function(){br.onclick();}},{label:"删除",danger:true,onclick:function(){b3.onclick();}}]));tb.appendChild(tr);});syncBatchBar();},function(e){gmsg("列取失败："+esc(e.message),false);});}\nvar dz=document.getElementById("drop");\ndz.addEventListener("dragover",function(e){e.preventDefault();dz.classList.add("on");});\ndz.addEventListener("dragleave",function(){dz.classList.remove("on");});\ndz.addEventListener("drop",function(e){e.preventDefault();dz.classList.remove("on");addFiles(e.dataTransfer.files);});\ndocument.getElementById("fi").addEventListener("change",function(e){addFiles(e.target.files);e.target.value="";});\nif(TOKEN){fetch("/api/login",{method:"POST",headers:{"content-type":"application/json","x-auth-token":TOKEN},body:"{}"}).then(function(r){return r.json()}).then(function(j){if(j.ok)enter();}).catch(function(){});}function syncBatchBar(){var chks=document.querySelectorAll(".rowchk");var sel=document.querySelectorAll(".rowchk:checked");var bar=document.getElementById("batchBar");var cnt=document.getElementById("selCount");if(bar){if(chks.length>0){bar.style.display="block";}else{bar.style.display="none";}}if(cnt){if(sel.length>0){cnt.textContent="已选 "+sel.length+" 个";}else{cnt.textContent="";}}}\nfunction getSelKeys(){var arr=[];document.querySelectorAll(".rowchk:checked").forEach(function(c){arr.push(decodeURIComponent(c.getAttribute("data-key")));});return arr;}\n(function(){var sa=document.getElementById("selAll");var sa2=document.getElementById("selAll2");var del=document.getElementById("delSel");var bsh=document.getElementById("batchShare");if(bsh){bsh.onclick=doBatchShare;}var tb=document.getElementById("tb");\nif(sa){sa.onchange=function(){document.querySelectorAll(".rowchk").forEach(function(c){c.checked=sa.checked;});syncBatchBar();};}\nif(sa2){sa2.onchange=function(){document.querySelectorAll(".rowchk").forEach(function(c){c.checked=sa2.checked;});if(sa){sa.checked=sa2.checked;}syncBatchBar();};}\nif(tb){tb.addEventListener("change",function(ev){if(ev.target&&ev.target.className==="rowchk"){var chks=document.querySelectorAll(".rowchk");var sel=document.querySelectorAll(".rowchk:checked");if(sa){sa.checked=chks.length>0&&sel.length===chks.length;}if(sa2){sa2.checked=chks.length>0&&sel.length===chks.length;}syncBatchBar();}});}\nvar mvs=document.getElementById("moveSel");if(mvs){mvs.onclick=doMove;}var mvg=document.getElementById("moveGo");if(mvg){mvg.onclick=goMove;}if(del){del.onclick=function(){var keys=getSelKeys();if(keys.length===0){gmsg("请先勾选要删除的文件",false);return;}if(!confirm("确定批量删除选中的 "+keys.length+" 个文件？此操作不可恢复")){return;}gmsg("正在删除 "+keys.length+" 个文件…",true);api("POST","/api/batch-delete",{keys:keys}).then(function(j){if(j.fail===0){gmsg("已删除 "+j.ok+" 个文件",true);}else{gmsg("删除完成："+j.ok+" 成功 / "+j.fail+" 失败",false);}refresh();},function(e){gmsg("批量删除失败："+esc(e.message),false);refresh();});};}\n})();function openShareMgr(){var m=document.getElementById("shareMgrMask");if(m)m.style.display="flex";loadShares();}function closeShareMgr(){var m=document.getElementById("shareMgrMask");if(m)m.style.display="none";}function loadShares(){var b=document.getElementById("shareMgrBody");if(b)b.textContent="加载中…";api("GET","/api/shares").then(function(r){renderShares(r.items||[]);},function(e){if(b)b.textContent="加载失败："+esc(e.message);});}function renderShares(items){var b=document.getElementById("shareMgrBody");if(!b)return;b.innerHTML="";if(!items.length){var e=document.createElement("div");e.style.cssText="color:#6b7280;padding:20px;text-align:center";e.textContent="当前没有进行中的分享";b.appendChild(e);updateBatchBtn();return;}for(var i=0;i<items.length;i++){var it=items[i];var row=document.createElement("div");row.className="shr-row";var chk=document.createElement("input");chk.type="checkbox";chk.className="shr-chk";chk.value=it.code;chk.onchange=updateBatchBtn;var info=document.createElement("div");info.className="shr-info";var nm=document.createElement("div");nm.className="shr-name";nm.textContent=it.name||it.key||"";var mt=document.createElement("div");mt.className="shr-meta";mt.textContent=(it.type==="batch"?"批量分享":"单文件")+" · 创建 "+(it.created?fmtTime(it.created):"—")+" · "+(it.expire>0?("剩余 "+fmtRemain(it.expire)):"永久");info.appendChild(nm);info.appendChild(mt);var btn=document.createElement("button");btn.className="btn small danger";btn.textContent="取消分享";(function(c){btn.onclick=function(){revokeShare(c,btn);};})(it.code);row.appendChild(chk);row.appendChild(info);row.appendChild(btn);b.appendChild(row);}updateBatchBtn();}function revokeShare(code,btn){if(!confirm("确定取消该分享？取消后链接立即失效。"))return;btn.disabled=true;api("POST","/api/share/revoke",{code:code}).then(function(r){gmsg("已取消分享",true);loadShares();},function(e){btn.disabled=false;gmsg("取消失败："+esc(e.message),false);});}function fmtRemain(exp){var s=exp-Math.floor(Date.now()/1000);if(s<=0)return"已过期";if(s<86400)return Math.ceil(s/3600)+"小时";return Math.ceil(s/86400)+"天";}function updateBatchBtn(){var n=document.querySelectorAll("#shareMgrBody .shr-chk:checked").length;var bb=document.getElementById("revokeSelBtn");if(bb)bb.disabled=n===0;}function revokeSelected(){var cs=[].map.call(document.querySelectorAll("#shareMgrBody .shr-chk:checked"),function(x){return x.value;});if(!cs.length){gmsg("先勾选要取消的分享",false);return;}if(!confirm("确定取消选中的 "+cs.length+" 个分享？取消后链接立即失效。"))return;api("POST","/api/share/revoke",{codes:cs}).then(function(r){gmsg("已取消 "+cs.length+" 个分享",true);loadShares();},function(e){gmsg("取消失败："+esc(e.message),false);});}</script>\n</body>\n</html>';

// ---------------- 路由 ----------------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname;
    try {
      if (p === '/' || p === '/index.html') return new Response(HTML_PAGE.replace('__VER__', VERSION), { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store, no-cache, must-revalidate, max-age=0', 'pragma': 'no-cache', 'expires': '0' } });
      if (p === '/favicon.ico') return new Response(null, { status: 204 });
      if (p === '/api/login') {
        if (!env.ADMIN_TOKEN) return json(500, { error: '未配置ADMIN_TOKEN' });
        return json(200, { ok: request.headers.get('x-auth-token') === env.ADMIN_TOKEN });
      }
      if (p.startsWith('/f/')) return await handleDownload(request, env, url);
      if (SHORT_RE.test(p)) {
        const code = p.slice(1);
        if (/^[FS][A-Za-z0-9]{7}$/.test(code)) {
          if (code[0] === 'S') {
            await ensureDB(env);
            if (!env.DB) return json(404, { error: 'Not Found' });
            return await serveBatchShare(env, code);
          }
        }
        await ensureDB(env);
        if (!env.DB) return json(404, { error: 'Not Found' });
        const s = await lookupShare(env, code);
        if (!s) return new Response('链接不存在或已过期', { status: 410, headers: { 'content-type': 'text/plain; charset=utf-8' } });
        if (s.kind === 'dir') return new Response('文件夹分享已停用', { status: 410, headers: { 'content-type': 'text/plain; charset=utf-8' } });
        return await serveFile(request, env, s.key, url.searchParams.get('dl') === '1');
      }
      if (request.headers.get('x-auth-token') !== env.ADMIN_TOKEN) return json(401, { error: '未授权' });
      if (p === '/api/init' && request.method === 'POST') return await handleInit(request, env);
      if (p === '/api/direct' && request.method === 'PUT') return await handleDirect(request, env, url);
      if (p === '/api/part' && request.method === 'PUT') return await handlePart(request, env, url);
      if (p === '/api/complete' && request.method === 'POST') return await handleComplete(request, env);
      if (p === '/api/abort' && request.method === 'POST') return await handleAbort(request, env);
      if (p === '/api/list' && request.method === 'GET') return await handleList(env, url);
      if (p === '/api/usage' && request.method === 'GET') {
        const used = await usageCached(env);
        return json(200, { used });
      }
      if (p === '/api/share' && request.method === 'GET') return await handleShare(request, env, url);
      if (p === '/api/batch-share' && request.method === 'POST') return await handleBatchShare(request, env, url);
      if (p === '/api/shares' && request.method === 'GET') return await handleListShares(env);
      if (p === '/api/share/revoke' && request.method === 'POST') return await handleRevokeShare(request, env);
      if (p === '/api/stats' && request.method === 'GET') return await handleStats(env, url);
      if (p === '/api/log' && request.method === 'GET') return await handleLog(env, url);
      if (p === '/api/file' && request.method === 'DELETE') return await handleDelete(request, env, url);
      if (p === '/api/batch-delete' && request.method === 'POST') return await handleBatchDelete(request, env);
      if (p === '/api/mkdir' && request.method === 'POST') return await handleMkdir(request, env);
      if (p === '/api/rmdir' && request.method === 'POST') return await handleRmdir(request, env);
      if (p === '/api/rename' && request.method === 'POST') return await handleRename(request, env);
      if (p === '/api/move' && request.method === 'POST') return await handleMove(request, env);
      return json(404, { error: 'Not Found' });
    } catch (e) {
      return json(500, { error: '服务异常', detail: String((e && e.message) || e).slice(0, 200) });
    }
  },
};
