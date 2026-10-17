# @euraxluo/ac-sign-glm-coding

A private magpie provider that sends a BigModel GLM Coding Plan key through
AutoClaw 2.1.0's `zhipu-client-sign` protocol.

- Provider id: `ac-sign-glm-coding`
- API: Anthropic Messages at `open.bigmodel.cn/api/anthropic`
- Identity: AutoClaw `2.1.0`, app id `autoclaw`
- Ordinary API key only (`<id>.<secret>`); each key is a magpie account
- Decimal-counter PoW, 8 leading-zero bits, 5,000,000 candidate cap
- AutoClaw model-request attribution headers: `X-Product`, `X-Request-Id`, `X-Request-Model`, and `X-Client-Type`
- One rekey after `VERIFY_SIGNATURE_INVALID` / `VERIFY_APIKEY_EXPIRED`; hard-stop VERIFY reasons or two failures disable signing for 30 minutes
- Private signing key cache: `~/.config/magpie/ac-sign-glm-coding-key.json`, mode 0600
- Usage reads BigModel Coding Plan windows and the earliest plan expiry (`until` means the subscription term, not a credit expiry)
- magpie performs account selection and routing; this plugin does not run its own account scheduler
- BigModel business usage requests use `Authorization: Bearer`
- BigModel API keys have no AutoClaw daily check-in; `checkin` reports inactive

This package intentionally follows installed AutoClaw 2.1.0 rather than the older QuotaHub `zcode` identity or ZCode 3.15.3. It combines AutoClaw's signing headers with its model-request attribution layer, both seen in the runtime capture and present in the official bundle. It uses a 6-hour in-memory key lifetime, a 10-minute handshake-failure cooldown, and AutoClaw's verify classification.

## Install

```sh
magpie plugin add github:Euraxluo/ac-sign-glm-coding
magpie plugin login ac-sign-glm-coding
magpie provider test ac-sign-glm-coding GLM-5.3
```
