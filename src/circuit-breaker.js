export class CircuitOpenError extends Error {
  constructor() {
    super('Upstream circuit is open');
    this.name = 'CircuitOpenError';
    this.statusCode = 503;
    this.publicCode = 'dependency_unavailable';
  }
}

export class CircuitBreaker {
  constructor({ failureThreshold = 5, cooldownMs = 30_000, successThreshold = 2 } = {}) {
    if (!Number.isSafeInteger(failureThreshold) || failureThreshold < 1 || failureThreshold > 100) throw new Error('failureThreshold is invalid');
    if (!Number.isSafeInteger(cooldownMs) || cooldownMs < 100 || cooldownMs > 10 * 60 * 1_000) throw new Error('cooldownMs is invalid');
    if (!Number.isSafeInteger(successThreshold) || successThreshold < 1 || successThreshold > 10) throw new Error('successThreshold is invalid');
    this.failureThreshold = failureThreshold;
    this.cooldownMs = cooldownMs;
    this.successThreshold = successThreshold;
    this.state = 'closed';
    this.failures = 0;
    this.successes = 0;
    this.openedAt = 0;
    this.inFlightProbe = false;
  }

  snapshot() {
    return Object.freeze({ state: this.state, failures: this.failures, successes: this.successes, openedAt: this.openedAt });
  }

  _beforeCall() {
    if (this.state === 'open') {
      if (Date.now() - this.openedAt < this.cooldownMs) throw new CircuitOpenError();
      if (this.inFlightProbe) throw new CircuitOpenError();
      this.state = 'half-open';
      this.inFlightProbe = true;
    } else if (this.state === 'half-open') {
      if (this.inFlightProbe) throw new CircuitOpenError();
      this.inFlightProbe = true;
    }
  }

  _success() {
    this.inFlightProbe = false;
    if (this.state === 'half-open') {
      this.successes += 1;
      if (this.successes >= this.successThreshold) {
        this.state = 'closed';
        this.failures = 0;
        this.successes = 0;
      }
      return;
    }
    this.failures = 0;
  }

  _failure() {
    this.inFlightProbe = false;
    this.successes = 0;
    this.failures += 1;
    if (this.state === 'half-open' || this.failures >= this.failureThreshold) {
      this.state = 'open';
      this.openedAt = Date.now();
    }
  }

  async execute(task, { isFailure = () => false } = {}) {
    if (typeof task !== 'function') throw new Error('Circuit task is required');
    if (typeof isFailure !== 'function') throw new Error('Circuit failure predicate is invalid');
    this._beforeCall();
    try {
      const result = await task();
      if (isFailure(result)) this._failure();
      else this._success();
      return result;
    } catch (error) {
      // Deterministic policy/client failures must not open a vendor circuit
      // for otherwise healthy traffic. Callers mark those errors explicitly.
      if (error?.circuitFailure !== false) this._failure();
      throw error;
    }
  }
}

export class CircuitBreakerPool {
  constructor({ maxEntries = 1_000, ...breakerOptions } = {}) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > 10_000) throw new Error('CircuitBreakerPool maxEntries is invalid');
    this.maxEntries = maxEntries;
    this.breakerOptions = breakerOptions;
    this.breakers = new Map();
  }

  for(key) {
    if (typeof key !== 'string' || key.length === 0 || key.length > 512) throw new Error('Circuit key is invalid');
    let breaker = this.breakers.get(key);
    if (!breaker) {
      if (this.breakers.size >= this.maxEntries) this.breakers.delete(this.breakers.keys().next().value);
      breaker = new CircuitBreaker(this.breakerOptions);
      this.breakers.set(key, breaker);
    }
    return breaker;
  }

  clear() {
    this.breakers.clear();
  }
}
