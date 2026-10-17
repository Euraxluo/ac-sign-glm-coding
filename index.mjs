// AutoClaw-compatible BigModel Coding Plan signing. This is a private fork:
// unlike packages/zcode, it intentionally follows AutoClaw 2.1.0's client
// identity and decimal PoW, matching the implementation long-used by QuotaHub.
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
            headers.set("x-api-key", key)
            headers.set("Authorization", `Bearer ${key}`)
            const sessionID = randomBytes(16).toString("hex")
            const signed = await signer.headers(sessionID)
            for (const [name, value] of Object.entries(signed)) headers.set(name, value)
            let response = await fetch(input, { ...init, headers })
            if (response.status === 401) {
              const text = await response.text()
              if (text.includes("VERIFY_SIGNATURE_INVALID") || text.includes("VERIFY_APIKEY_EXPIRED")) {
                signer.reset()
                const resigned = await signer.headers(sessionID)
                for (const [name, value] of Object.entries(resigned)) headers.set(name, value)
                response = await fetch(input, { ...init, headers })
              } else response = new Response(text, { status: 401, statusText: response.statusText, headers: response.headers })
            }
            return response
          },
        }
      },
      async usage() {
        return { windows: [{ name: "Signed channel", used: 0, display: "AutoClaw-compatible signed requests", aside: true }] }
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

export const _internalPlugin = { PROVIDER, BASE, MODELS, cachePath, signerFor, signers }
export { _internal as _internalSign }
