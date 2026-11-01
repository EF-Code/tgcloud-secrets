# Telegram Serverless compatibility probe

This fixture verifies `tgcloud-secrets` against the real Telegram Serverless
V8 runtime without exposing a vendor credential.

1. Copy `runtime/secret-fetch.js` to `tgcloud/lib/secret-fetch.js` in a private
   Serverless test project.
2. Copy `handlers/message.js` to that project's `tgcloud/handlers/message.js`.
   Use a separate test project if the bot already has a message handler.
3. Replace the endpoint and capability placeholders. Use a disposable
   capability restricted to `POST /probe` on a synthetic test upstream.
4. Execute the local sources on Telegram without deploying them:

   ```sh
   npx tgcloud run handlers/message \
     '{text:"/tgcloud_secrets_probe"}' \
     --ctx '{update:{update_id:1}}'
   ```

The run must show a string-based HTTPS request at the broker, a successful
status, and the available runtime globals. The probe returns its result to the
CLI without sending a Telegram message. Never use a production capability,
Bot API token, vendor credential, or customer data in this probe.

## Live validation

On 2026-11-01 the unreleased adapter was executed with Telegram's SDK fetch
against a synthetic broker through a temporary HTTPS tunnel. Secret injection,
JSON forwarding, and removal of the capability header before reaching the
upstream passed with HTTP 200. Disallowed paths, disallowed methods, and
attempted injected-header overrides returned HTTP 400. After revocation, the
same disposable capability returned HTTP 401 from Telegram.

The runtime exposed `TextEncoder` and `Uint8Array`, but no global `URL`,
`Headers`, `AbortController`, or `fetch`. This revealed the beta.3 adapter's
`URL is not defined` failure. The current adapter handles this environment
with a strict ASCII-origin fallback, and its regression test removes the same
globals before importing the vendorable module.

Redirect handling and invocation cancellation require separate endpoints and
must not be claimed compatible until their observed results are recorded.
