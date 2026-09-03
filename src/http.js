/**
 * Parse request framing once at the HTTP boundary. Node normally rejects many
 * malformed combinations, but an explicit check keeps the application
 * behavior deterministic across adapters and prevents a downstream proxy from
 * interpreting a request differently from this process.
 */
export function parseRequestFraming(request) {
  const headers = request?.headers;
  const contentLength = headers?.['content-length'];
  const transferEncoding = headers?.['transfer-encoding'];
  const invalid = (message) => Object.assign(new Error(message), { statusCode: 400, closeConnection: true });

  // Node normally normalizes singleton headers, but its parser behavior can
  // vary with adapter options. Inspect the wire-level header list as well so
  // duplicate framing headers cannot be hidden by normalization.
  const rawHeaders = request?.rawHeaders;
  if (Array.isArray(rawHeaders)) {
    let contentLengthCount = 0;
    let transferEncodingCount = 0;
    for (let index = 0; index + 1 < rawHeaders.length; index += 2) {
      const name = typeof rawHeaders[index] === 'string' ? rawHeaders[index].toLowerCase() : '';
      if (name === 'content-length') contentLengthCount += 1;
      if (name === 'transfer-encoding') transferEncodingCount += 1;
    }
    if (contentLengthCount > 1 || transferEncodingCount > 1) {
      throw invalid('Request framing headers must not be repeated');
    }
  }

  if (Array.isArray(contentLength) || Array.isArray(transferEncoding)) {
    throw invalid('Request framing headers must not be repeated');
  }

  let length = null;
  if (contentLength !== undefined) {
    if (typeof contentLength !== 'string' || !/^(?:0|[1-9]\d*)$/.test(contentLength)) {
      throw invalid('Content-Length is invalid');
    }
    length = Number(contentLength);
    if (!Number.isSafeInteger(length)) throw invalid('Content-Length is too large');
  }

  if (transferEncoding !== undefined) {
    if (typeof transferEncoding !== 'string' || transferEncoding.toLowerCase() !== 'chunked' || length !== null) {
      throw invalid('Request transfer framing is invalid');
    }
  }

  return Object.freeze({
    contentLength: length,
    chunked: transferEncoding !== undefined,
    hasBody: (length !== null && length > 0) || transferEncoding !== undefined,
  });
}
