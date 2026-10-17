# @euraxluo/ac-sign-glm-coding

A private magpie provider that sends a BigModel GLM Coding Plan key through
QuotaHub `glmsign`'s stable zcode 3.4.0 signed-channel protocol.

- Provider id: `ac-sign-glm-coding`
- API: Anthropic Messages at `open.bigmodel.cn/api/anthropic`
- Identity: QuotaHub glmsign, `ZCode/3.4.0`, app id `zcode`
- Ordinary API key only (`<id>.<secret>`)
- Decimal-counter PoW, 8 leading-zero bits, 5,000,000 candidate cap
- Extra stable-channel headers: `X-Product`, `X-Client-Type`, `X-Request-Id`, `X-Request-Model`, and `User-Agent`
- One rekey after `VERIFY_SIGNATURE_INVALID` / `VERIFY_APIKEY_EXPIRED`; two VERIFY failures enter fail-open unsigned mode, as QuotaHub did
- Private signing key cache: `~/.config/magpie/ac-sign-glm-coding-key.json`, mode 0600
- Usage reads BigModel Coding Plan windows and the plan term
- BigModel API keys have no AutoClaw daily check-in; `checkin` reports inactive

This package intentionally does **not** use ZCode 3.15.3's project-token
credential or 32-hex PoW form. It is the QuotaHub `glmsign` behavior that
has run stably and observed the same 67% high-window / 33.5% off-peak
accounting as official clients.

## Install

```sh
magpie plugin add github:Euraxluo/ac-sign-glm-coding
magpie plugin login ac-sign-glm-coding
magpie provider test ac-sign-glm-coding GLM-5.3
```
