# BIP85KMS

## Observability / Workers Logs policy — 2026-09 cost incident

**What happened (2026-09-05):** the Cloudflare account (b8b395a6029fc23bcc4f4ac31fcd1f1c) crossed its $25 usage alert mid-month. Root cause: Workers Logs ingestion — observability left at/near max (head_sampling_rate 1.0, logs + traces + invocation_logs all on) across dozens of deployed workers produced ~54M log events/month against the 20M free tier (≈$0.60 per additional million). Biggest burners: the cashu-mint-* cluster under continuous loop traffic (cashu-mint-signet alone ~7.4M events/week) and boltz-bridge-* at sampling 1.0.

**State since 2026-09-05:** observability is hard-zeroed on ALL workers in this account — via the Cloudflare API (live settings) and in every wrangler config in this repo (`observability.enabled = false`, head_sampling_rate 0, logs/traces/invocation_logs off). This is deliberate for the rest of billing month September 2026. Historical sampling values are recoverable from git history.

**Rules for agents working here:**
1. Do not deploy with observability enabled or with raised sampling "for visibility". Default is OFF/0 everywhere.
2. Debugging: enable selectively — only the specific worker being debugged, lowest rate that gives signal (start 0.05–0.1), `invocation_logs: true` only if truly needed — and zero it again in the same PR or an immediate follow-up.
3. Never leave head_sampling_rate at/near 1.0 on a deployed worker; on a busy worker that alone costs real money (see incident above).
4. When planning features/deployments, budget log volume explicitly: estimated events/month ≈ requests/month × log lines/request × sampling rate, checked against the 20M account-wide free tier.
5. After any deploy that touches logging, check Workers & Pages → Observability and the billing usage page; budget alerts are configured on the account.

Workers deployed from this repo: bip85kms
