// AutoClaw 2.1.0 zhipu-client-sign port. Keep this implementation aligned
// with the official client rather than the older QuotaHub zcode identity.
import { createHash, randomBytes } from "node:crypto"
import { mkdirSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"
import { createSigner, splitCredential, _internal } from "./sign.mjs"

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
    headers: { Accept: "application/json", Authorization: `Bearer ${key}` },
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
  let earliest = null
  for (const x of Array.isArray(subs) ? subs : []) {
    if (String(x?.status ?? "").toUpperCase() !== "VALID") continue
    const auto = x.autoRenew === true || x.autoRenew === 1
    const next = beijing(typeof x.nextRenewTime === "string" ? x.nextRenewTime : "")
    const ds = String(typeof x.valid === "string" ? x.valid : "").match(/\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}:\d{2})?/g) ?? []
    const validEnd = beijing(ds[ds.length - 1])
    const t = next || (ds.length && !auto ? validEnd : 0)
    if (t && (!earliest || t < earliest.at)) earliest = { at: t, auto }
  }
  return earliest ? { until: new Date(earliest.at).toISOString(), renew: earliest.auto ? "auto" : "off" } : {}
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

function cachePath(key = "") {
  const root = process.env.XDG_CONFIG_HOME || join(homedir(), ".config")
  const suffix = key ? createHash("sha256").update(key).digest("hex").slice(0, 16) : "default"
  return join(root, "magpie", `ac-sign-glm-coding-${suffix}.json`)
}

function signerFor(key) {
  let entry = signers.get(key)
  if (!entry) {
    mkdirSync(join(cachePath(key), ".."), { recursive: true })
    entry = createSigner({ apiKey: key, cachePath: cachePath(key) })
    signers.set(key, entry)
  }
  return entry
}

const selections = new Map()
const SELECTION_TTL_MS = 5 * 60 * 1000

function keysOf(auth, options) {
  const explicit = Array.isArray(options?.keys) ? options.keys.map((key) => String(key).trim()).filter(Boolean) : []
  if (explicit.length) return [...new Set(explicit)]
  return String(auth?.key ?? "").split(/\r?\n/).map((key) => key.trim()).filter(Boolean)
}

async function selectKey(keys) {
  const cacheKey = keys.join("\n")
  const cached = selections.get(cacheKey)
  if (cached && Date.now() - cached.at < SELECTION_TTL_MS) return cached
  const cards = await Promise.all(keys.map(async (key) => {
    try { return { key, card: await codingUsage(key) } } catch { return null }
  }))
  const usable = cards.filter(Boolean)
  if (!usable.length) throw new Error("none of the BigModel keys could report usage")
  // The signed coding-plan key whose entitlement ends soonest is the one to
  // spend first; a key with no known term is kept behind every dated key.
  const chosen = usable.sort((a, b) => {
    const at = Date.parse(a.card.until ?? "") || Number.POSITIVE_INFINITY
    const bt = Date.parse(b.card.until ?? "") || Number.POSITIVE_INFINITY
    return at - bt || a.key.localeCompare(b.key)
  })[0]
  const selection = { at: Date.now(), ...chosen }
  selections.set(cacheKey, selection)
  return selection
}

export async function AutoClawCodingAuthPlugin(_client, options) {
  return {
    config: async (cfg) => {
      cfg.provider ??= {}
      cfg.provider[PROVIDER] ??= {
        name: "AC Signed GLM Coding",
        npm: "@ai-sdk/anthropic",
        api: BASE + "/v1",
        models: Object.fromEntries(Object.entries(MODELS).map(([id, m]) => [id, {
          id,
          name: id,
          reasoning: m.efforts.some((e) => e !== "none"),
          tool_call: true,
          attachment: false,
          modalities: { input: ["text"], output: ["text"] },
          limit: { context: m.context, output: m.output },
          cost: { input: 0, output: 0, cache_read: 0, cache_write: 0 },
          variants: Object.fromEntries(m.efforts.map((e) => [e, e === "none" ? { thinking: { type: "disabled" } } : { thinking: { type: "enabled", budgetTokens: e === "max" ? 31999 : e === "high" ? 16000 : 4096 } }])),
        }])),
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
        const keys = keysOf(auth, options)
        if (!keys.length) return {}
        const key = keys.length === 1 ? keys[0] : (await selectKey(keys)).key
        const signer = signerFor(key)
        return {
          baseURL: BASE + "/v1",
          async fetch(input, init) {
            const headers = new Headers(init?.headers)
            // magpie's gateway converter calls the OpenAI-compatible endpoint;
            // this plugin owns the Anthropic Messages endpoint explicitly.
            let url = input instanceof Request ? input.url : String(input)
            if (url.includes("/v1/chat/completions")) {
              const body = JSON.parse(String(init?.body ?? "{}"))
              const messages = Array.isArray(body.messages) ? body.messages : []
              const converted = {
                model: String(body.model ?? ""),
                max_tokens: Number(body.max_tokens ?? 4096) || 4096,
                stream: body.stream === true,
                messages: messages.map((m) => ({
                  role: m.role === "assistant" ? "assistant" : m.role === "tool" ? "user" : "user",
                  content: Array.isArray(m.content)
                    ? m.content.map((part) => part?.text ?? "").join("\n")
                    : String(m.content ?? ""),
                })),
              }
              url = BASE + "/v1/messages"
              init = { ...init, method: "POST", body: JSON.stringify(converted), signal: undefined }
            }
            headers.set("x-api-key", key)
            headers.set("Authorization", `Bearer ${key}`)
            headers.set("anthropic-version", "2023-06-01")
            let model = ""
            try { model = String(JSON.parse(String(init?.body ?? "{}")).model ?? "") } catch {}
            const sessionID = randomBytes(16).toString("hex")
            const hasAuthorization = headers.has("authorization")
            const signed = await signer.headers(sessionID, { hasAuthorization, model })
            for (const [name, value] of Object.entries(signed ?? {})) headers.set(name, value)
            let response = await fetch(url, { ...init, headers })
            if (response.status === 401) {
              const text = await response.text()
              const reason = (/VERIFY_[A-Z_]+/.exec(text) ?? [])[0] ?? ""
              if (reason) {
                const hardStop = /VERIFY_POW_REQUIRED|VERIFY_POW_INVALID|VERIFY_TS_OUT_OF_WINDOW|VERIFY_MISSING_FIELD|VERIFY_INVALID_FORMAT|VERIFY_PROTOCOL_ERROR|VERIFY_APIKEY_DISABLED/.test(reason)
                const disabled = signer.noteVerifyFailure(reason, hardStop).disabled
                const rekey = reason === "VERIFY_SIGNATURE_INVALID" || reason === "VERIFY_APIKEY_EXPIRED"
                if (rekey && !disabled) {
                  const resigned = await signer.headers(sessionID, { hasAuthorization, model })
                  for (const [name, value] of Object.entries(resigned ?? {})) headers.set(name, value)
                  response = await fetch(url, { ...init, headers })
                } else response = new Response(text, { status: 401, statusText: response.statusText, headers: response.headers })
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
          const keys = keysOf(auth, options)
          if (!keys.length) return { error: "not signed in", windows: [] }
          const selection = keys.length === 1 ? { key: keys[0], card: await codingUsage(keys[0]) } : await selectKey(keys)
          if (keys.length > 1) selection.card.balance = `${keys.length} keys · serving ${selection.key.split(".")[0]}…`
          return selection.card
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
        return Object.fromEntries(Object.entries(provider.models ?? {}).map(([id, m]) => [id, {
          id,
          providerID: PROVIDER,
          name: id,
          api: { id, url: BASE + "/v1", npm: "@ai-sdk/anthropic" },
          status: "active",
          cost: { input: 0, output: 0, cache: { read: 0, write: 0 } },
          limit: { context: m.limit?.context ?? 0, output: m.limit?.output ?? 0 },
          options: {},
          headers: {},
          capabilities: {
            temperature: true,
            reasoning: !!m.reasoning,
            attachment: false,
            toolcall: true,
            input: { text: true, image: false, audio: false, video: false, pdf: false },
            output: { text: true, image: false, audio: false, video: false, pdf: false },
            interleaved: false,
          },
          release_date: "",
          variants: m.variants ?? {},
        }]))
      },
    },
  }
}

export const _internalPlugin = { PROVIDER, BASE, MODELS, cachePath, signerFor, signers, selections, keysOf, selectKey, codingUsage, limitWindows, termOf }
export { _internal as _internalSign }
