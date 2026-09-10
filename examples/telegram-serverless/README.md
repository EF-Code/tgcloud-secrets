# Telegram Serverless compatibility probe

This fixture verifies `tgcloud-secrets` against the real Telegram Serverless
V8 runtime without exposing a vendor credential.

1. Copy `runtime/secret-fetch.js` to `lib/secret-fetch.js` in a private
   Serverless test project.
2. Copy `handlers/message.js` to that project's `handlers/message.js`.
3. Replace the endpoint and capability placeholders. Use a disposable
   capability restricted to `POST /probe` on a synthetic test upstream.
4. Execute the local sources on Telegram without deploying them:

   ```sh
   npx tgcloud run handlers/message \
     '{chat:{id:1},from:{id:1},text:"/tgcloud_secrets_probe"}' \
     --ctx '{update:{update_id:1}}'
   ```

The run must show a string-based HTTPS request at the broker, a successful
status, and the available runtime globals. Never use a production capability,
Bot API token, vendor credential, or customer data in this probe.

Redirect handling and invocation cancellation require separate endpoints and
must not be claimed compatible until their observed results are recorded.
