// QuotaHub glmsign port. This is a private fork preserving the stable
// zcode 3.4.0 identity, decimal PoW, extra request headers, and fail-open
// behavior that QuotaHub used for the 67%/33.5% signed channel.
import { randomBytes } from "node:crypto"
import { mkdirSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"
import { createSigner, _internal } from "./sign.mjs"

const PROVIDER = "ac-sign-glm-coding"
const BASE = "https://open.bigmodel.cn/api/anthropic"
const MODELS = {
  "GLM-5.3": { context: 1_000_000, output: 128_000, efforts: ["low", "high", "max"] },
  "GLM-5.3-Flash": { context: 1_000_000, output: 128_000, efforts: ["low", "high", "max"] },
  "GLM-5.2": { context: 1_000_000, output: 128_000, efforts: ["none", "high", "max"] },
  "GLM-5-Turbo": { context: 200_000, output: 64_000, efforts: ["none", "high"] },
}
const BIZ_API = "https://bigmodel.cn"

async function call(method, url, key, signal) {
  const res = await fetch(url, {
    method,
    headers: { Accept: "application/json", Authorization: key },
    signal,
  })
  const text = await res.text()
  let env
  try { env = JSON.parse(text) } catch {}
  if (!res.ok) throw new Error(env?.msg || `${res.status} ${res.statusText}`)
  const code = env?.code
  if (code != null && code !== 0 && code !== 200) throw new Error(env?.msg || `code ${code}`)
  return env?.data ?? null
}

const isNum = (v) => typeof v === "number" && Number.isFinite(v)
const compact = (n) => (Number.isInteger(n) ? String(n) : n.toFixed(2).replace(/0+$/, "").replace(/\.$/, ""))
function spanOf(unit, n) {
  n = Math.trunc(Number(n) || 0)
  if (unit === 3 && n <= 0) n = 5
  n = Math.max(n, 1)
  return { 1: 60, 3: 3600, 4: 86400, 5: 30 * 86400, 6: 7 * 86400 }[unit] * n || 0
}
function windowName(span) {
  if (span === 0) return "Credits"
  if (span < 86400) return `${Math.trunc(span / 3600)} hours`
  if (span === 7 * 86400) return "Weekly"
  if (span >= 28 * 86400) return "Monthly"
  return `${Math.trunc(span / 86400)} days`
}
function limitWindows(d) {
  const out = []
  for (const x of d?.limits ?? []) {
    const span = spanOf(Math.trunc(Number(x?.unit) || 0), x?.number)
    const w = { name: windowName(span), used: 0 }
    if (String(x?.type ?? "").toUpperCase() === "TIME_LIMIT") (w.name = "MCP · Month"), (w.aside = true)
    if (isNum(x?.percentage)) w.used = x.percentage
    if (x?.usage === 0) (w.used = 0), (w.aside = true)
    if (isNum(x?.usage) && x.usage > 0) {
      const total = x.usage
      if (isNum(x.remaining)) {
        const used = total - x.remaining
        w.used = (100 * used) / total
        w.amount = used
        w.limit = total
        w.display = `${compact(used)} / ${compact(total)}`
      } else if (isNum(x.currentValue)) {
        if (!isNum(x.percentage)) w.used = (100 * x.currentValue) / total
        w.amount = x.currentValue
        w.limit = total
        w.display = `${compact(x.currentValue)} / ${compact(total)}`
      }
    }
    const reset = Math.trunc(Number(x?.nextResetTime) || 0)
    if (reset > 0) w.resetsAt = new Date(reset).toISOString()
    if (span) w.span = span
    out.push(w)
  }
  return out
}
function beijing(s) {
  s = String(s ?? "").trim().replace(" ", "T")
  if (!/^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2})?$/.test(s)) return 0
  const t = Date.parse(s + (s.length === 10 ? "T00:00:00" : "") + "+08:00")
  return Number.isFinite(t) ? t : 0
}
function termOf(subs) {
  for (const x of Array.isArray(subs) ? subs : []) {
    if (String(x?.status ?? "").toUpperCase() !== "VALID") continue
    const auto = x.autoRenew === true || x.autoRenew === 1
    const t = beijing(typeof x.nextRenewTime === "string" ? x.nextRenewTime : "")
    if (t) return { until: new Date(t).toISOString(), renew: auto ? "auto" : "off" }
    const ds = String(typeof x.valid === "string" ? x.valid : "").match(/\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}:\d{2})?/g) ?? []
    if (ds.length && !auto) {
      const end = beijing(ds[ds.length - 1])
      if (end) return { until: new Date(end).toISOString(), renew: "off" }
    }
    return {}
  }
  return {}
}
async function codingUsage(key) {
  const d = (await call("GET", BIZ_API + "/api/monitor/usage/quota/limit", key)) ?? {}
  const out = {}
  if (typeof d.level === "string" && d.level) out.plan = "GLM Coding " + d.level[0].toUpperCase() + d.level.slice(1)
  out.windows = limitWindows(d)
  try { Object.assign(out, termOf(await call("GET", BIZ_API + "/api/biz/subscription/list", key))) } catch {}
  return out
}

const signers = new Map()

function cachePath() {
  const root = process.env.XDG_CONFIG_HOME || join(homedir(), ".config")
  return join(root, "magpie", "ac-sign-glm-coding-key.json")
}

function signerFor(key) {
  let entry = signers.get(key)
  if (!entry) {
    mkdirSync(join(cachePath(), ".."), { recursive: true })
    entry = createSigner({ apiKey: key, cachePath: cachePath() })
    signers.set(key, entry)
  }
  return entry
}

export async function AutoClawCodingAuthPlugin() {
  return {
    config: async (cfg) => {
      cfg.provider ??= {}
      cfg.provider[PROVIDER] ??= {
        name: "AC Signed GLM Coding",
        npm: "@ai-sdk/anthropic",
        api: BASE,
        models: MODELS,
      }
    },
    auth: {
      provider: PROVIDER,
      methods: [{
        type: "api",
        label: "AutoClaw-compatible BigModel Coding Plan API key",
      }],
      async loader(getAuth) {
        const auth = await getAuth()
        if (auth?.type !== "api" || !auth.key) return {}
        const key = String(auth.key).trim()
        const signer = signerFor(key)
        return {
          baseURL: BASE,
          async fetch(input, init) {
            const headers = new Headers(init?.headers)
            // magpie's gateway converter calls the OpenAI-compatible endpoint;
            // this plugin owns the Anthropic Messages endpoint explicitly.
            let url = input instanceof Request ? input.url : String(input)
            if (url.includes("/v1/chat/completions")) {
              url = BASE + "/v1/messages"
              init = { ...init, body: init?.body }
            }
            headers.set("x-api-key", key)
            headers.set("Authorization", `Bearer ${key}`)
            let model = ""
            try { model = String(JSON.parse(String(init?.body ?? "{}")).model ?? "") } catch {}
            const sessionID = randomBytes(16).toString("hex")
            const signed = await signer.headers(sessionID, model)
            for (const [name, value] of Object.entries(signed ?? {})) headers.set(name, value)
            let response = await fetch(url, { ...init, headers })
            if (response.status === 401) {
              const text = await response.text()
              const reason = (/VERIFY_[A-Z_]+/.exec(text) ?? [])[0] ?? ""
              if (reason === "VERIFY_SIGNATURE_INVALID" || reason === "VERIFY_APIKEY_EXPIRED") {
                const failure = signer.noteVerifyFailure(reason)
                if (!failure.disabled) {
                  signer.reset()
                  const resigned = await signer.headers(sessionID, model)
                  for (const [name, value] of Object.entries(resigned ?? {})) headers.set(name, value)
                  response = await fetch(url, { ...init, headers })
                } else response = new Response(text, { status: 401, statusText: response.statusText, headers: response.headers })
              } else if (reason) {
                signer.noteVerifyFailure(reason)
                response = new Response(text, { status: 401, statusText: response.statusText, headers: response.headers })
              } else response = new Response(text, { status: 401, statusText: response.statusText, headers: response.headers })
            }
            return response
          },
        }
      },
      async usage(getAuth) {
        const auth = await getAuth()
        if (auth?.type !== "api" || !auth.key) return { error: "not signed in", windows: [] }
        try {
          return await codingUsage(String(auth.key).trim())
        } catch (e) {
          return { error: `BigModel usage failed: ${e?.message ?? e}`, windows: [] }
        }
      },
      async checkin() {
        return { outcome: "inactive", message: "BigModel API keys do not have AutoClaw's daily check-in" }
      },
    },
    provider: {
      id: PROVIDER,
      async models(provider) {
        return provider.models
      },
    },
  }
}

export const _internalPlugin = { PROVIDER, BASE, MODELS, cachePath, signerFor, signers, codingUsage, limitWindows, termOf }
export { _internal as _internalSign }
