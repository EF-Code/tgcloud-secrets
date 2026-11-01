import { fetch } from 'sdk';
import { createTelegramSecretFetch } from '../lib/secret-fetch.js';

// Replace these two non-secret placeholders only in a private test project.
// The capability must be disposable and limited to the broker's probe route.
const brokerFetch = createTelegramSecretFetch({
  endpoint: 'https://broker.example.com',
  // Deliberately invalid until replaced, so this fixture cannot call a remote
  // endpoint accidentally.
  capability: 'REPLACE_WITH_DISPOSABLE_CAPABILITY',
  fetch,
});

export default async function (message) {
  if (message?.text !== '/tgcloud_secrets_probe') return { ignored: true };

  const globals = {
    URL: typeof URL,
    TextEncoder: typeof TextEncoder,
    Uint8Array: typeof Uint8Array,
    Headers: typeof Headers,
    AbortController: typeof AbortController,
  };
  const response = await brokerFetch('/probe', {
    method: 'POST',
    body: { probe: 'telegram-serverless', version: 1 },
  });
  const result = {
    globals,
    brokerStatus: response.status,
    brokerOk: response.ok,
  };
  // Return through the CLI instead of sending a message to a synthetic chat ID.
  return result;
}
