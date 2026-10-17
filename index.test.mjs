import { afterEach, beforeEach, expect, test } from "bun:test"
import { homedir, tmpdir } from "node:os"
import { realpathSync } from "node:fs"
import { createCipheriv, createHash, createPrivateKey, createPublicKey, verify as cryptoVerify } from "node:crypto"
import { mkdirSync } from "node:fs"
import { join } from "node:path"
import { AutoClawCodingAuthPlugin, _internalPlugin } from "./index.mjs"
import { minePow, _internal as _internalSign } from "./sign.mjs"

if (![tmpdir(), realpathSync(tmpdir())].some((t) => homedir().startsWith(t))) throw new Error("run in an isolated home")

const KEY = "one.secret"
const auth = { type: "api", key: KEY }
const sent = []
const real = globalThis.fetch
const DER = Buffer.from("MC4CAQAwBQYDK2VwBCIEINaofm94EHDBFTX6XkGlMUU8F41qb2mXKe/DMwUJbxCh", "base64")

function sealedKey() {
  const key = _internalSign.hkdf(Buffer.from("secret"), "ed25519_priv")
  const cipher = createCipheriv("aes-256-gcm", key, Buffer.alloc(12))
  cipher.setAAD(Buffer.from("one"))
  const der = Buffer.from("MC4CAQAwBQYDK2VwBCIEINaofm94EHDBFTX6XkGlMUU8F41qb2mXKe/DMwUJbxCh", "base64")
  return Buffer.concat([Buffer.alloc(12), cipher.update(Buffer.from(der.toString("base64"))), cipher.final(), cipher.getAuthTag()]).toString("base64")
}

beforeEach(() => {
  sent.length = 0
  _internalPlugin.signers.clear()
  mkdirSync(join(tmpdir(), `ac-sign-${process.pid}`), { recursive: true })
  process.env.XDG_CONFIG_HOME = join(tmpdir(), `ac-sign-${process.pid}`)
  globalThis.fetch = async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input))
    if (url.pathname === "/api/paas/c1f3a7e2/v2/client") return Response.json({ code: 200, data: { privateCipher: sealedKey() } })
    sent.push({ input: String(input), init, headers: new Headers(init?.headers) })
    return Response.json({ ok: true })
  }
})

afterEach(() => {
  globalThis.fetch = real
  _internalPlugin.signers.clear()
})

async function send() {
  const hooks = await AutoClawCodingAuthPlugin()
  const opts = await hooks.auth.loader(async () => auth, { id: _internalPlugin.PROVIDER })
  return opts.fetch("https://open.bigmodel.cn/api/anthropic/v1/messages", { method: "POST", body: JSON.stringify({ model: "GLM-5.3", messages: [] }) })
}

test("AutoClaw PoW stays decimal and leading-zero valid", () => {
  const pow = minePow("key", "session", "123")
  expect(pow).toMatch(/^\d+$/)
  const challenge = createHash("sha256").update("key\nautoclaw\nsession\n123").digest("hex").slice(0, 32)
  expect(createHash("sha256").update(`${challenge}\n${pow}`).digest()[0]).toBe(0)
})

test("a model request carries AutoClaw's signed headers", async () => {
  const res = await send()
  expect(res.status).toBe(200)
  expect(sent).toHaveLength(1)
  expect(sent[0].headers.get("x-api-key")).toBe(KEY)
  expect(sent[0].headers.get("x-app-id")).toBe("autoclaw")
  expect(sent[0].headers.get("x-client-version")).toBe("2.1.0")
  expect(sent[0].headers.get("x-client-pow")).toMatch(/^\d+$/)
  expect(sent[0].headers.get("x-session-id")).toMatch(/^[0-9a-f]{32}$/)
  const signature = Buffer.from(sent[0].headers.get("x-client-sig"), "base64")
  const publicKey = createPublicKey(createPrivateKey({ key: DER, format: "der", type: "pkcs8" }))
  const message = `one\n${sent[0].headers.get("x-client-ts")}\n2.1.0\n${sent[0].headers.get("x-session-id")}\n${sent[0].headers.get("x-client-nonce")}`
  expect(cryptoVerify(null, Buffer.from(message), publicKey, signature)).toBe(true)
})

test("handshake uses apiKey and AutoClaw identity", async () => {
  const captures = []
  globalThis.fetch = async (input, init) => {
    const url = new URL(String(input))
    if (url.pathname === "/api/paas/c1f3a7e2/v2/client") {
      captures.push({ headers: new Headers(init?.headers), body: JSON.parse(init?.body) })
      return Response.json({ code: 200, data: { privateCipher: sealedKey() } })
    }
    return Response.json({ ok: true })
  }
  await send()
  expect(captures).toHaveLength(1)
  expect(captures[0].body.apiKey).toBe(KEY)
  expect(captures[0].headers.get("authorization")).toBe(`Bearer ${KEY}`)
})
