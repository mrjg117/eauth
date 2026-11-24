/**
 * 统一鉴权入口 · 阿里云 ESA 边缘函数（旧版免费套餐 / 0 KV）
 * 路由：
 *   GET /login                  服务端渲染登录页（图标栏 + 微信内嵌二维码 + 其他平台跳转）
 *   GET /authorize              校验 service/redirect/provider -> 302 上游授权页
 *   GET /callback/:provider     验 state -> 换 uid -> 查白名单 -> 签 JWT -> 302 回业务 #token
 *   GET /token                  预留：自有 code 换 JWT（0 存储版默认不用）
 *   GET /whoami                 首次登记：显示 provider:uidHash
 *   GET /deny                   拒绝页
 *
 * 环境变量见 env.example。密钥类请用「加密存储」。
 */

const TE = new TextEncoder()

/* ---------------- 基础工具 ---------------- */
const b64u = (data) => {
  const bytes = typeof data === 'string' ? TE.encode(data) : new Uint8Array(data)
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
const unb64u = (str) => {
  let s = str.replace(/-/g, '+').replace(/_/g, '/')
  while (s.length % 4) s += '='
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}
const hex = (u8) => Array.from(u8, (x) => x.toString(16).padStart(2, '0')).join('')

async function importHmac(secret) {
  return crypto.subtle.importKey('raw', TE.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'])
}
async function hmac(secret, data) {
  const key = await importHmac(secret)
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, TE.encode(data)))
}
async function eq(a, b) {
  if (a.length !== b.length) return false
  let d = 0
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return d === 0
}
const json = (obj, status = 200) => new Response(JSON.stringify(obj), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }
})
const html = (body, status = 200) => new Response(body, {
  status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }
})
const goto = (url) => new Response(null, { status: 302, headers: { location: url, 'cache-control': 'no-store' } })
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))

/* ---------------- 身份派生 ---------------- */
// 平台返回的原始 uid -> 固定哈希短 ID。白名单里只存哈希，不存原始 openid。
async function uidHash(env, provider, rawUid) {
  const sig = await hmac(env.JWT_SECRET, `${provider}:${rawUid}`)
  return hex(sig).slice(0, 16)
}

/* ---------------- state（自包含签名，不落 KV） ---------------- */
async function makeState(env, payload) {
  const body = b64u(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + 300 }))
  const sig = b64u(await hmac(env.COOKIE_SECRET, body))
  return `${body}.${sig}`
}
async function readState(env, state) {
  try {
    const [body, sig] = state.split('.')
    const expect = b64u(await hmac(env.COOKIE_SECRET, body))
    if (!(await eq(sig, expect))) return null
    const data = JSON.parse(new TextDecoder().decode(unb64u(body)))
    if (data.exp < Math.floor(Date.now() / 1000)) return null
    return data
  } catch { return null }
}

/* ---------------- JWT ---------------- */
async function makeJwt(env, service, provider, hash) {
  const now = Math.floor(Date.now() / 1000)
  const ttl = Number(env.JWT_TTL || 604800)
  const head = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const payload = b64u(JSON.stringify({
    iss: 'auth-edge', aud: service, sub: hash, p: provider, iat: now, exp: now + ttl
  }))
  const sig = b64u(await hmac(env.JWT_SECRET, `${head}.${payload}`))
  return `${head}.${payload}.${sig}`
}

/* ---------------- 服务白名单（业务方） ---------------- */
function services(env) {
  try { return JSON.parse(env.SERVICES || '{}') } catch { return {} }
}
function validTarget(env, service, rd) {
  const svc = services(env)[service]
  if (!svc) return null
  if (!svc.redirect?.some((p) => rd.startsWith(p))) return null
  return svc
}

/* ---------------- 用户白名单（在线表格 / env 兜底） ---------------- */
/**
 * ALLOWLIST_URL 指向一个公开可读的纯文本/CSV，每行： provider:hash,状态,备注
 * 也可直接用 ALLOWED_USERS 逗号列表兜底。二者取并集。
 * 表格服务的 token 放 ALLOWLIST_TOKEN（可选，Bearer）。
 */
async function loadAllowlist(env) {
  const set = new Set()
  for (const item of (env.ALLOWED_USERS || '').split(',')) {
    const k = item.trim()
    if (k.includes(':')) set.add(k)
  }
  if (env.ALLOWLIST_URL) {
    try {
      const headers = env.ALLOWLIST_TOKEN ? { authorization: `Bearer ${env.ALLOWLIST_TOKEN}` } : {}
      const res = await fetch(env.ALLOWLIST_URL, { headers, cf: { cacheTtl: 60 } })
      if (res.ok) {
        const text = await res.text()
        for (const line of text.split(/\r?\n/)) {
          const cols = line.split(',').map((x) => x.trim())
          if (!cols[0]?.includes(':')) continue
          const status = (cols[1] || 'active').toLowerCase()
          if (['active', '1', 'yes', 'true', '允许', ''].includes(status)) set.add(cols[0])
        }
      }
    } catch (e) {
      // 在线表格拉取失败时降级为 env 名单，避免把自己锁在门外
      console.warn('allowlist fetch failed:', e.message)
    }
  }
  return set
}
async function isAllowed(env, provider, hash) {
  const allow = await loadAllowlist(env)
  return allow.has(`${provider}:${hash}`)
}

/* ---------------- Provider 定义 ---------------- */
const P = {
  wx: {
    name: '微信', mode: 'web', color: '#1D9E75',
    auth: (e, st, rd) => `https://open.weixin.qq.com/connect/qrconnect?appid=${e.WX_ID}&redirect_uri=${encodeURIComponent(`${e.AUTH_BASE}/callback/wx`)}&response_type=code&scope=snsapi_login&state=${st}#wechat_redirect`,
    uid: async (e, code) => {
      const r = await fetch(`https://api.weixin.qq.com/sns/oauth2/access_token?appid=${e.WX_ID}&secret=${e.WX_SECRET}&code=${code}&grant_type=authorization_code`)
      const j = await r.json()
      if (!j.openid) throw new Error(j.errmsg || 'wx token failed')
      return { raw: j.unionid || j.openid, id: j.unionid ? 'wxu' : 'wx' }
    }
  },
  wxmp: {
    name: '微信小程序码', mode: 'mini', color: '#1D9E75',
    // 个人主体小程序：scene 携带一次性 ticket，扫码进小程序后 wx.login -> /mini/code
    auth: () => null,
    uid: async (e, code) => {
      const r = await fetch(`https://api.weixin.qq.com/sns/jscode2session?appid=${e.WXMP_ID}&secret=${e.WXMP_SECRET}&js_code=${code}&grant_type=authorization_code`)
      const j = await r.json()
      if (!j.openid) throw new Error(j.errmsg || 'jscode2session failed')
      return { raw: j.openid, id: 'wxm' }
    }
  },
  ali: {
    name: '支付宝', mode: 'web', color: '#1677FF',
    auth: (e, st) => `https://openauth.alipay.com/oauth2/publicAppAuthorize.htm?app_id=${e.ALI_ID}&scope=auth_user&redirect_uri=${encodeURIComponent(`${e.AUTH_BASE}/callback/ali`)}&state=${st}`,
    uid: async (e, code) => {
      const body = new URLSearchParams({ app_id: e.ALI_ID, method: 'alipay.system.oauth.token', format: 'JSON', charset: 'utf-8', sign_type: 'RSA2', timestamp: new Date().toISOString().slice(0, 19) + 'Z', version: '1.0', grant_type: 'authorization_code', code })
      // 支付宝网关需签名。若不想实现 RSA2，可改用自建中转或先只接免签名的平台。
      if (e.ALI_PRIVATE_KEY) {
        const sign = await rsaSign(e.ALI_PRIVATE_KEY, body.toString())
        body.set('sign', sign)
      }
      const r = await fetch('https://openapi.alipay.com/gateway.do', { method: 'POST', body })
      const j = await r.json()
      const d = j.alipay_system_oauth_token_response
      if (!d?.user_id) throw new Error('ali token failed')
      return { raw: d.user_id, id: 'ali' }
    }
  },
  qq: {
    name: 'QQ', mode: 'web', color: '#378ADD',
    auth: (e, st) => `https://graph.qq.com/oauth2.0/authorize?client_id=${e.QQ_ID}&response_type=code&scope=get_user_info&redirect_uri=${encodeURIComponent(`${e.AUTH_BASE}/callback/qq`)}&state=${st}`,
    uid: async (e, code) => {
      const t = await (await fetch(`https://graph.qq.com/oauth2.0/token?grant_type=authorization_code&client_id=${e.QQ_ID}&client_secret=${e.QQ_SECRET}&code=${code}&redirect_uri=${encodeURIComponent(`${e.AUTH_BASE}/callback/qq`)}`)).text()
      const token = new URLSearchParams(t).get('access_token')
      if (!token) throw new Error('qq token failed')
      const me = await (await fetch(`https://graph.qq.com/oauth2.0/me?access_token=${token}`)).text()
      const m = me.slice(me.indexOf('{'), me.lastIndexOf('}') + 1)
      const j = JSON.parse(m)
      if (!j.openid) throw new Error('qq openid failed')
      return { raw: j.openid, id: 'qq' }
    }
  },
  gitee: {
    name: 'Gitee', mode: 'web', color: '#D85A30',
    auth: (e, st) => `https://gitee.com/oauth/authorize?client_id=${e.GITEE_ID}&redirect_uri=${encodeURIComponent(`${e.AUTH_BASE}/callback/gitee`)}&response_type=code&scope=user_info&state=${st}`,
    uid: async (e, code) => {
      const r = await fetch('https://gitee.com/oauth/token', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ grant_type: 'authorization_code', code, client_id: e.GITEE_ID, client_secret: e.GITEE_SECRET, redirect_uri: `${e.AUTH_BASE}/callback/gitee` })
      })
      const j = await r.json()
      if (!j.access_token) throw new Error('gitee token failed')
      const u = await (await fetch('https://gitee.com/api/v5/user', { headers: { authorization: `token ${j.access_token}` } })).json()
      return { raw: String(u.id), id: 'gitee' }
    }
  },
  github: {
    name: 'GitHub', mode: 'web', color: '#5F5E5A',
    auth: (e, st) => `https://github.com/login/oauth/authorize?client_id=${e.GH_ID}&redirect_uri=${encodeURIComponent(`${e.AUTH_BASE}/callback/github`)}&scope=read:user&state=${st}`,
    uid: async (e, code) => {
      const r = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST', headers: { accept: 'application/json', 'content-type': 'application/json' },
        body: JSON.stringify({ client_id: e.GH_ID, client_secret: e.GH_SECRET, code })
      })
      const j = await r.json()
      if (!j.access_token) throw new Error('github token failed')
      const u = await (await fetch('https://api.github.com/user', { headers: { authorization: `Bearer ${j.access_token}`, 'user-agent': 'auth-edge' } })).json()
      return { raw: String(u.id), id: 'gh' }
    }
  },
  douyin: {
    name: '抖音', mode: 'web', color: '#E24B4A',
    auth: (e, st) => `https://open.douyin.com/platform/oauth/connect?client_key=${e.DY_ID}&response_type=code&scope=user_info&redirect_uri=${encodeURIComponent(`${e.AUTH_BASE}/callback/douyin`)}&state=${st}`,
    uid: async (e, code) => {
      const r = await fetch('https://open.douyin.com/oauth/access_token/', {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_key: e.DY_ID, client_secret: e.DY_SECRET, code, grant_type: 'authorization_code' })
      })
      const j = await r.json()
      if (!j.data?.open_id) throw new Error('douyin token failed')
      return { raw: j.data.union_id || j.data.open_id, id: j.data.union_id ? 'dyu' : 'dy' }
    }
  }
}
const enabled = (env) => (env.PROVIDERS || 'wxmp,ali,qq,gitee,github').split(',').filter((k) => P[k]).map((k) => ({ k, ...P[k] }))

async function rsaSign(pem, data) {
  const der = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '')
  const key = await crypto.subtle.importKey('pkcs8', unb64u(der), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign'])
  return b64u(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, TE.encode(data)))
}

/* ---------------- 页面 ---------------- */
function pageShell(title, body, env) {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>
:root{color-scheme:dark;--bg:#111318;--card:#1b1e25;--line:#2b2f39;--fg:#eceef3;--mut:#9aa0ad;--acc:#5DCAA5}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(1200px 600px at 50% -10%,#1d2a29,transparent),var(--bg);color:var(--fg);font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;display:flex;align-items:center;justify-content:center;padding:24px}
.card{width:min(100%,520px);background:var(--card);border:1px solid var(--line);border-radius:16px;padding:32px}
h1{font-size:18px;font-weight:500;margin:0 0 6px}p.sub{color:var(--mut);margin:0 0 24px;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(88px,1fr));gap:10px}
.p{display:flex;flex-direction:column;align-items:center;gap:8px;padding:14px 6px;border:1px solid var(--line);border-radius:12px;text-decoration:none;color:var(--fg);background:#20242c;transition:.15s}
.p:hover{border-color:var(--acc);transform:translateY(-1px)}.dot{width:22px;height:22px;border-radius:7px;display:grid;place-items:center;font-size:11px;color:#fff}
.note{margin-top:20px;padding:12px 14px;border-radius:10px;background:#15181e;color:var(--mut);font-size:12px}
code{color:var(--acc);word-break:break-all}.err{color:#F09595}.ok{color:#9FE1CB}
a.qr{display:inline-block;padding:10px 16px;border:1px solid var(--acc);border-radius:10px;color:var(--acc);text-decoration:none}
</style></head><body><div class="card">${body}</div></body></html>`
}

function loginPage(env, url) {
  const service = url.searchParams.get('service') || 'default'
  const rd = url.searchParams.get('rd') || ''
  const svc = validTarget(env, service, rd)
  const list = enabled(env)
  const stateReady = !!svc
  const cards = list.map((p) => {
    const st = stateReady ? '' : ''
    const href = `/authorize?service=${encodeURIComponent(service)}&provider=${p.k}&rd=${encodeURIComponent(rd)}`
    const label = p.mode === 'mini' ? '小程序码' : p.name
    return `<a class="p" href="${href}"><span class="dot" style="background:${p.color}">${esc(p.name.slice(0, 1))}</span><span>${esc(label)}</span></a>`
  }).join('')
  const body = `
    <h1>扫码登录</h1>
    <p class="sub">统一鉴权入口 · ${esc(service)}</p>
    <div class="grid">${cards}</div>
    <div class="note">${stateReady
      ? '选择一个平台。微信走小程序码；支付宝、QQ、Gitee、GitHub、抖音由平台页面展示二维码，回调后统一回到这里签发票据。'
      : '<span class="err">service 或回跳地址不在白名单内，已阻止跳转。</span>'}</div>`
  return html(pageShell('扫码登录', body, env))
}

function denyPage(env, reason) {
  return html(pageShell('无权限', `<h1>未通过鉴权</h1><p class="sub">${esc(reason || '账号不在白名单')}</p>
    <div class="note">该账号已通过平台验证，但不在允许列表内。请把 <code>provider:哈希</code> 加入在线表格后重试。</div>`, env), 403)
}
function whoamiPage(env, provider, hash) {
  return html(pageShell('登记身份', `<h1>登记你的 ID</h1><p class="sub">把下面这一行填进白名单表格</p>
    <div class="note"><code>${esc(provider)}:${esc(hash)}</code></div>
    <div class="note">登记后把 AUTH_MODE 改回 strict 并重新发布。当前为登记模式，未签发令牌。</div>`, env))
}

/* ---------------- 路由 ---------------- */
async function handleAuthorize(request, env) {
  const u = new URL(request.url)
  const service = u.searchParams.get('service') || ''
  const provider = u.searchParams.get('provider') || ''
  const rd = u.searchParams.get('rd') || ''
  const svc = validTarget(env, service, rd)
  if (!svc) return html(pageShell('参数错误', '<h1>参数错误</h1><p class="sub">service 或 rd 不在白名单</p>', env), 400)
  if (!svc.providers?.includes(provider) || !P[provider]) return html(pageShell('参数错误', '<h1>不支持的平台</h1>', env), 400)
  const state = await makeState(env, { service, provider, rd })
  if (P[provider].mode === 'mini') {
    // 小程序码：scene 携带 state 的短 ticket；小程序拿到后 wx.login 再换身份
    return html(pageShell('微信扫码', `<h1>微信扫码</h1><p class="sub">小程序码模式</p>
      <div class="note">用微信扫描小程序码，进入小程序完成登录。<br>scene 携带 <code>${esc(state.slice(0, 24))}…</code></div>`, env))
  }
  return goto(P[provider].auth(env, state, rd))
}

async function handleCallback(request, env, provider) {
  const u = new URL(request.url)
  const stateRaw = u.searchParams.get('state') || ''
  const code = u.searchParams.get('code') || ''
  const st = await readState(env, stateRaw)
  if (!st || st.provider !== provider) return html(pageShell('失败', '<h1>state 校验失败</h1><p class="sub">请从登录页重新开始</p>', env), 400)
  if (!code) return html(pageShell('失败', '<h1>未拿到 code</h1>', env), 400)
  try {
    const { raw, id } = await P[provider].uid(env, code)
    const hash = await uidHash(env, id, raw)
    if (env.AUTH_MODE === 'open') return whoamiPage(env, id, hash)
    if (!(await isAllowed(env, id, hash))) return denyPage(env, `${id}:${hash}`)
    const jwt = await makeJwt(env, st.service, provider, hash)
    const sep = st.rd.includes('#') ? '&' : '#'
    return goto(`${st.rd}${sep}token=${encodeURIComponent(jwt)}`)
  } catch (e) {
    return html(pageShell('失败', `<h1>上游换取失败</h1><div class="note err">${esc(e.message)}</div>`, env), 502)
  }
}

async function handleMiniCode(request, env) {
  // 小程序端 wx.login 拿到 code 后 POST 到这里；body: { code, state }
  let body
  try { body = await request.json() } catch { return json({ error: 'bad json' }, 400) }
  const st = await readState(env, body.state || '')
  if (!st) return json({ error: 'bad state' }, 400)
  try {
    const { raw, id } = await P.wxmp.uid(env, body.code)
    const hash = await uidHash(env, id, raw)
    if (env.AUTH_MODE === 'open') return whoamiPage(env, id, hash)
    if (!(await isAllowed(env, id, hash))) return denyPage(env, `${id}:${hash}`)
    const jwt = await makeJwt(env, st.service, 'wxmp', hash)
    const sep = st.rd.includes('#') ? '&' : '#'
    return json({ token: jwt, redirect: `${st.rd}${sep}token=${encodeURIComponent(jwt)}` })
  } catch (e) {
    return json({ error: e.message }, 502)
  }
}

export default {
  async fetch(request, context, env) {
    const u = new URL(request.url)
    const path = u.pathname
    try {
      if (path === '/login' || path === '/') return loginPage(env, u)
      if (path === '/authorize') return handleAuthorize(request, env)
      if (path.startsWith('/callback/')) return handleCallback(request, env, path.slice('/callback/'.length))
      if (path === '/mini/code' && request.method === 'POST') return handleMiniCode(request, env)
      if (path === '/whoami') {
        const p = u.searchParams.get('p') || 'wxm'
        return whoamiPage(env, p, u.searchParams.get('id') || '')
      }
      if (path === '/deny') return denyPage(env, u.searchParams.get('reason'))
      return html(pageShell('404', '<h1>404</h1>', env), 404)
    } catch (e) {
      console.error(e)
      return json({ error: 'internal', message: e.message }, 500)
    }
  }
}
