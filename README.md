# @euraxluo/ac-sign-glm-coding

A private magpie provider that sends a BigModel GLM Coding Plan key through
AutoClaw 2.1.0's `zhipu-client-sign` protocol.

- Provider id: `ac-sign-glm-coding`
- API: Anthropic Messages at `open.bigmodel.cn/api/anthropic`
- Identity: AutoClaw `2.1.0`, app id `autoclaw`
- Ordinary API key only (`<id>.<secret>`)
- Decimal-counter PoW, 8 leading-zero bits, 5,000,000 candidate cap
- One rekey after `VERIFY_SIGNATURE_INVALID` / `VERIFY_APIKEY_EXPIRED`
- Private signing key cache: `~/.config/magpie/ac-sign-glm-coding-key.json`, mode 0600
- BigModel API keys have no AutoClaw daily check-in; `checkin` reports inactive

This package intentionally does **not** use ZCode 3.15.3's project-token
credential or 32-hex PoW form. It is the AutoClaw-compatible implementation
that QuotaHub has used stably.

## Install

```sh
magpie plugin add github:Euraxluo/ac-sign-glm-coding
magpie plugin login ac-sign-glm-coding
magpie provider test ac-sign-glm-coding GLM-5.3
```
