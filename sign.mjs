// AutoClaw 2.1.0's zhipu-client-sign port. It deliberately uses AutoClaw's
// decimal PoW form; the zcode package instead follows ZCode 3.15.3.
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  randomBytes,
  randomUUID,
  sign as cryptoSign,
} from "node:crypto"

const UPSTREAM = "https://open.bigmodel.cn"
const HANDSHAKE_PATH = "/api/paas/c1f3a7e2/v2/client"
const KDF_SALT = "WD_CLIENT_SIGN_KDF_SALT"
const APP_ID = "autoclaw"
const VERSION = "2.1.0"
const HANDSHAKE_COOLDOWN_MS = 10 * 60 * 1000
const HANDSHAKE_TIMEOUT_MS = 30_000
const FIRST_WAIT_MS = 3_000
const KEY_TTL_MS = 6 * 60 * 60 * 1000
const VERIFY_DISABLE_MS = 30 * 60 * 1000
const POW_MAX = 5_000_000
const VERIFY_FAILURE_LIMIT = 2
const VERIFY_FAILURE_WINDOW_MS = 10 * 60 * 1000

function hkdf(secret, info, length = 32) {
  const prk = createHmac("sha256", KDF_SALT).update(secret).digest()
  const out = []
  let t = Buffer.alloc(0)
  for (let i = 1; Buffer.concat(out).length < length; i++) {
    t = createHmac("sha256", prk).update(Buffer.concat([t, Buffer.from(info), Buffer.from([i])])).digest()
    out.push(t)
  }
  return Buffer.concat(out).subarray(0, length)
}

function gcmOpen(key, blob, aad) {
  if (!(blob.length > 12 + 16)) throw new Error("handshake cipher too short")
  const d = createDecipheriv("aes-256-gcm", key, blob.subarray(0, 12))
  d.setAAD(Buffer.from(aad))
  d.setAuthTag(blob.subarray(blob.length - 16))
  return Buffer.concat([d.update(blob.subarray(12, blob.length - 16)), d.final()])
}

function gcmSeal(key, plain, aad) {
  const nonce = randomBytes(12)
  const c = createCipheriv("aes-256-gcm", key, nonce)
  c.setAAD(Buffer.from(aad))
  return Buffer.concat([nonce, c.update(plain), c.final(), c.getAuthTag()])
}

export function splitCredential(apiKey) {
  const value = String(apiKey ?? "")
  const parts = value.split(".")
  if (parts.length !== 2) throw new Error("AutoClaw Coding Plan needs an API key shaped <id>.<secret>")
  const [id, secret] = parts
  if (!id.trim() || !secret.trim() || id.trim() !== id || secret.trim() !== secret) throw new Error("AutoClaw Coding Plan needs an API key shaped <id>.<secret>")
  return { id, secret }
}

export function minePow(keyID, sessionID, ts) {
  const challenge = createHash("sha256")
    .update(`${keyID}\n${APP_ID}\n${sessionID}\n${ts}`)
    .digest("hex")
    .slice(0, 32)
  for (let candidate = 0; candidate < POW_MAX; candidate++) {
    if (createHash("sha256").update(`${challenge}\n${candidate}`).digest()[0] === 0) return String(candidate)
  }
  return ""
}

function privateKeyFromDER(der) {
  const key = createPrivateKey({ key: der, format: "der", type: "pkcs8" })
  if (key.asymmetricKeyType !== "ed25519") throw new Error("AutoClaw signing key is not Ed25519")
  return key
}

function cacheKey(secret) {
  return hkdf(secret, "local-key-cache")
}

function readKeyCache(path, keyID, secret, setKey) {
  if (!path) return
  let entry = {}
  try { entry = JSON.parse(readFileSync(path, "utf8")) ?? {} } catch { return }
  if (entry.keyId !== keyID || typeof entry.cipher !== "string" || !entry.cipher) return
  const der = gcmOpen(cacheKey(secret), Buffer.from(entry.cipher, "base64"), keyID)
  setKey(privateKeyFromDER(der), gcmSeal(cacheKey(secret), der, keyID))
}

import { readFileSync, renameSync, writeFileSync } from "node:fs"

function writeKeyCache(path, keyID, secret, key) {
  if (!path || !key) return
  const der = key.export({ format: "der", type: "pkcs8" })
  const blob = gcmSeal(cacheKey(secret), der, keyID)
  const raw = JSON.stringify({ keyId: keyID, savedAt: Date.now(), cipher: blob.toString("base64") })
  const tmp = `${path}.tmp`
  writeFileSync(tmp, raw, { mode: 0o600 })
  renameSync(tmp, path)
}

export function createSigner({ apiKey, cachePath = "", fetchImpl = globalThis.fetch } = {}) {
  let credential = splitCredential(apiKey)
  let key, sealedDER, fetchedAt, inflight
  let verifyFailures = []
  let handshakeFailedUntil = 0
  let disabledUntil = 0

  async function handshake() {
    const ts = String(Date.now())
    const nonce = randomBytes(16).toString("hex")
    const mac = createHmac("sha256", hkdf(credential.secret, "getSignKey_hmac"))
      .update(`get_sign_key\n${credential.id}\n${ts}\n${nonce}`)
      .digest("base64")
    const apiKey = `${credential.id}.${credential.secret}`
    const res = await fetchImpl(UPSTREAM + HANDSHAKE_PATH, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ apiKey, ts, nonce, sig: mac }),
      signal: AbortSignal.timeout(30_000),
    })
    const env = await res.json().catch(() => ({}))
    const cipher = env?.data?.privateCipher
    if (!res.ok || env?.code !== 200 || !cipher) throw new Error(`AutoClaw sign handshake: HTTP ${res.status} code ${env?.code ?? "none"}`)
    const der = Buffer.from(gcmOpen(hkdf(credential.secret, "ed25519_priv"), Buffer.from(cipher, "base64"), credential.id).toString("utf8").trim(), "base64")
    const nextKey = privateKeyFromDER(der)
    sealedDER = gcmSeal(cacheKey(credential.secret), der, credential.id)
    writeKeyCache(cachePath, credential.id, credential.secret, nextKey)
    return nextKey
  }

  async function ensure() {
    if (key && Date.now() - fetchedAt < KEY_TTL_MS) return
    if (sealedDER && !key) {
      key = privateKeyFromDER(gcmOpen(cacheKey(credential.secret), sealedDER, credential.id))
      fetchedAt = Date.now()
      return
    }
    if (Date.now() < handshakeFailedUntil) return
    if (inflight) {
      await new Promise((resolve) => {
        const timer = setTimeout(resolve, FIRST_WAIT_MS)
        const settle = () => { clearTimeout(timer); resolve() }
        inflight.then(settle, settle)
      })
      return
    }
    key = sealedDER = fetchedAt = undefined
    handshakeFailedUntil = 0
    const pending = handshake()
      .then((nextKey) => {
        key = nextKey
        fetchedAt = Date.now()
        return nextKey
      })
      .catch((error) => {
        handshakeFailedUntil = Date.now() + HANDSHAKE_COOLDOWN_MS
        throw error
      })
      .finally(() => { inflight = undefined })
    inflight = pending
    await pending
  }

  function reset() {
    key = sealedDER = fetchedAt = undefined
  }

  function noteVerifyFailure(reason, immediate = false) {
    if (/VERIFY_POW_REQUIRED|VERIFY_POW_INVALID|VERIFY_TS_OUT_OF_WINDOW|VERIFY_MISSING_FIELD|VERIFY_INVALID_FORMAT|VERIFY_PROTOCOL_ERROR|VERIFY_APIKEY_DISABLED/.test(reason)) immediate = true
    const now = Date.now()
    const previous = verifyFailures[0]
    const withinWindow = previous && now - previous.at < VERIFY_FAILURE_WINDOW_MS
    verifyFailures = withinWindow ? [...verifyFailures, { at: previous.at, reason }] : [{ at: now, reason }]
    if (!immediate && verifyFailures.length < VERIFY_FAILURE_LIMIT) return { action: immediate ? "hard_stop" : "count_only", disabled: false }
    disabledUntil = now + VERIFY_DISABLE_MS
    verifyFailures = []
    reset()
    return { action: immediate ? "hard_stop" : "count_only", disabled: true }
  }

  async function headers(sessionID, { hasAuthorization = false, requestId = "", model = "" } = {}) {
    if (Date.now() < disabledUntil) return null
    await ensure()
    if (!key) return null
    const ts = String(Date.now())
    const nonce = randomBytes(16).toString("hex")
    const pow = minePow(credential.id, sessionID, ts)
    const out = {
      "X-Session-Id": sessionID,
      "X-Client-Ts": ts,
      "X-Client-Version": VERSION,
      "X-Client-Nonce": nonce,
      "X-Client-Sig": cryptoSign(null, Buffer.from(`${credential.id}\n${ts}\n${VERSION}\n${sessionID}\n${nonce}`), key).toString("base64"),
      // AutoClaw's model-request attribution layer (#810), captured on the
      // same outgoing BigModel request as the signing headers.
      "X-Product": APP_ID,
      "X-Request-Id": requestId || randomUUID(),
      "X-Request-Model": model,
      "X-Client-Type": "pc",
    }
    if (pow) {
      out["X-App-Id"] = APP_ID
      out["X-Client-Pow"] = pow
    }
    if (!hasAuthorization) out["Authorization"] = `Bearer ${credential.id}.${credential.secret}`
    return out
  }

  return {
    headers,
    reset,
    ensure,
    noteVerifyFailure,
    isDisabled() { return Date.now() < disabledUntil },
    bind(nextKey) {
      credential = splitCredential(nextKey)
      reset()
    },
  }
}

export const _internal = { APP_ID, VERSION, cacheKey, gcmOpen, gcmSeal, hkdf, privateKeyFromDER, readKeyCache, writeKeyCache, APP_ID, VERSION, HANDSHAKE_COOLDOWN_MS, HANDSHAKE_TIMEOUT_MS, FIRST_WAIT_MS, KEY_TTL_MS, VERIFY_FAILURE_LIMIT, VERIFY_FAILURE_WINDOW_MS, VERIFY_DISABLE_MS, POW_MAX }
