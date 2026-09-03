import { TextDecoder } from 'node:util';

const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const JSON_WHITESPACE = new Set([' ', '\t', '\n', '\r']);
const NUMBER_TOKEN = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/;
const HEX = /^[0-9a-fA-F]{4}$/;

function invalidJson(message = 'Request body must be valid JSON') {
  return Object.assign(new Error(message), { statusCode: 400 });
}

function inputBuffer(input) {
  if (Buffer.isBuffer(input)) return input;
  if (input instanceof Uint8Array) return Buffer.from(input);
  if (typeof input === 'string') return Buffer.from(input, 'utf8');
  throw invalidJson();
}

function hasLoneSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

class JsonSyntaxParser {
  constructor(source, { maxDepth, maxFields, maxArrayItems, maxStringBytes }) {
    this.source = source;
    this.index = 0;
    this.maxDepth = maxDepth;
    this.maxFields = maxFields;
    this.maxArrayItems = maxArrayItems;
    this.maxStringBytes = maxStringBytes;
    this.fields = 0;
  }

  whitespace() {
    while (JSON_WHITESPACE.has(this.source[this.index])) this.index += 1;
  }

  string() {
    const start = this.index;
    this.index += 1;
    while (this.index < this.source.length) {
      const code = this.source.charCodeAt(this.index);
      const character = this.source[this.index];
      if (character === '"') {
        this.index += 1;
        let value;
        try {
          value = JSON.parse(this.source.slice(start, this.index));
        } catch {
          throw invalidJson();
        }
        if (hasLoneSurrogate(value)) throw invalidJson('JSON contains malformed Unicode');
        if (Buffer.byteLength(value, 'utf8') > this.maxStringBytes) throw invalidJson('JSON string is too large');
        return value;
      }
      if (code < 0x20) throw invalidJson();
      if (character === '\\') {
        this.index += 1;
        const escape = this.source[this.index];
        if (!'"\\/bfnrtu'.includes(escape)) throw invalidJson();
        if (escape === 'u') {
          const digits = this.source.slice(this.index + 1, this.index + 5);
          if (!HEX.test(digits)) throw invalidJson();
          this.index += 4;
        }
      }
      this.index += 1;
    }
    throw invalidJson();
  }

  value(depth = 0) {
    if (depth > this.maxDepth) throw invalidJson('JSON nesting is too deep');
    this.whitespace();
    const character = this.source[this.index];
    if (character === '"') return this.string();
    if (character === '{') return this.object(depth);
    if (character === '[') return this.array(depth);
    if (this.source.startsWith('true', this.index)) {
      this.index += 4;
      return;
    }
    if (this.source.startsWith('false', this.index)) {
      this.index += 5;
      return;
    }
    if (this.source.startsWith('null', this.index)) {
      this.index += 4;
      return;
    }
    const number = NUMBER_TOKEN.exec(this.source.slice(this.index));
    if (number) {
      this.index += number[0].length;
      return;
    }
    throw invalidJson();
  }

  object(depth) {
    this.index += 1;
    this.whitespace();
    const keys = new Set();
    if (this.source[this.index] === '}') {
      this.index += 1;
      return;
    }
    while (this.index < this.source.length) {
      this.whitespace();
      if (this.source[this.index] !== '"') throw invalidJson();
      const key = this.string();
      if (UNSAFE_KEYS.has(key) || keys.has(key)) throw invalidJson('JSON object contains a duplicate or unsafe field');
      keys.add(key);
      this.fields += 1;
      if (this.fields > this.maxFields) throw invalidJson('JSON object contains too many fields');
      this.whitespace();
      if (this.source[this.index] !== ':') throw invalidJson();
      this.index += 1;
      this.value(depth + 1);
      this.whitespace();
      if (this.source[this.index] === '}') {
        this.index += 1;
        return;
      }
      if (this.source[this.index] !== ',') throw invalidJson();
      this.index += 1;
    }
    throw invalidJson();
  }

  array(depth) {
    this.index += 1;
    this.whitespace();
    if (this.source[this.index] === ']') {
      this.index += 1;
      return;
    }
    let items = 0;
    while (this.index < this.source.length) {
      items += 1;
      if (items > this.maxArrayItems) throw invalidJson('JSON array contains too many items');
      this.value(depth + 1);
      this.whitespace();
      if (this.source[this.index] === ']') {
        this.index += 1;
        return;
      }
      if (this.source[this.index] !== ',') throw invalidJson();
      this.index += 1;
    }
    throw invalidJson();
  }

  finish() {
    this.value(0);
    this.whitespace();
    if (this.index !== this.source.length) throw invalidJson();
  }
}

/**
 * Parse a bounded JSON document with strict UTF-8, duplicate-key, nesting,
 * field, array, unsafe-key, surrogate, and unsafe-number checks. The caller
 * remains responsible for validating the endpoint-specific schema.
 */
export function parseStrictJson(input, {
  maxBytes = 1 * 1024 * 1024,
  maxDepth = 10,
  maxFields = 256,
  maxArrayItems = 256,
  maxStringBytes = 256 * 1024,
} = {}) {
  const raw = inputBuffer(input);
  if (raw.length > maxBytes) throw Object.assign(new Error('Request body is too large'), { statusCode: 413 });
  let source;
  try {
    source = new TextDecoder('utf-8', { fatal: true }).decode(raw);
  } catch {
    throw invalidJson('Request body must contain valid UTF-8');
  }
  if (source.length === 0) throw invalidJson();
  const parser = new JsonSyntaxParser(source, { maxDepth, maxFields, maxArrayItems, maxStringBytes });
  parser.finish();
  let parsed;
  try {
    parsed = JSON.parse(source, (_key, value) => {
      if (typeof value === 'number' && (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value)))) {
        throw invalidJson('JSON contains an unsafe number');
      }
      if (typeof value === 'string' && hasLoneSurrogate(value)) throw invalidJson('JSON contains malformed Unicode');
      return value;
    });
  } catch (error) {
    if (error?.statusCode) throw error;
    throw invalidJson();
  }
  const inspectStrings = (value) => {
    if (typeof value === 'string') {
      if (hasLoneSurrogate(value) || Buffer.byteLength(value, 'utf8') > maxStringBytes) throw invalidJson('JSON contains malformed Unicode or an oversized string');
      return;
    }
    if (Array.isArray(value)) {
      for (const entry of value) inspectStrings(entry);
      return;
    }
    if (value && typeof value === 'object') {
      for (const [key, child] of Object.entries(value)) {
        if (hasLoneSurrogate(key)) throw invalidJson('JSON contains malformed Unicode');
        inspectStrings(child);
      }
    }
  };
  inspectStrings(parsed);
  return parsed;
}

export { invalidJson };
