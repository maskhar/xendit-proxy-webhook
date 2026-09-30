import { request } from 'undici';
import type { Config } from '../config/env.js';
import { AppError, errorMessage } from '../security/errors.js';
import { asJsonObject, type JsonObject } from '../security/json.js';

export type ProviderResponse = {
  statusCode: number;
  body: JsonObject;
};

export class ProviderTransportError extends Error {
  readonly uncertain: boolean;

  constructor(message: string, uncertain: boolean, options?: ErrorOptions) {
    super(message, options);
    this.name = 'ProviderTransportError';
    this.uncertain = uncertain;
  }
}

export class XenditClient {
  readonly #baseUrl: URL;
  readonly #authorization: string;
  readonly #apiVersion: string;
  readonly #timeoutMs: number;

  constructor(config: Config) {
    this.#baseUrl = new URL(config.XENDIT_API_BASE_URL);
    this.#authorization = `Basic ${Buffer.from(`${config.xenditApiKey}:`).toString('base64')}`;
    this.#apiVersion = config.XENDIT_API_VERSION;
    this.#timeoutMs = config.PROVIDER_TIMEOUT_MS;
  }

  async createPaymentRequest(body: JsonObject): Promise<ProviderResponse> {
    return this.#send('POST', '/v3/payment_requests', body, true);
  }

  async getPaymentRequest(id: string): Promise<ProviderResponse> {
    return this.#send('GET', `/v3/payment_requests/${encodeURIComponent(id)}`, undefined, true);
  }

  async cancelPaymentRequest(id: string): Promise<ProviderResponse> {
    return this.#send('POST', `/v3/payment_requests/${encodeURIComponent(id)}/cancel`, {}, true);
  }

  async createPaymentSession(body: JsonObject): Promise<ProviderResponse> {
    return this.#send('POST', '/sessions', body);
  }

  async getPaymentSession(id: string): Promise<ProviderResponse> {
    return this.#send('GET', `/sessions/${encodeURIComponent(id)}`);
  }

  async createLegacyInvoice(body: JsonObject): Promise<ProviderResponse> {
    return this.#send('POST', '/v2/invoices', body);
  }

  async createRefund(body: JsonObject): Promise<ProviderResponse> {
    return this.#send('POST', '/refunds', body);
  }

  async #send(
    method: 'GET' | 'POST',
    path: string,
    body?: JsonObject,
    versioned = false,
  ): Promise<ProviderResponse> {
    const url = new URL(path, this.#baseUrl);
    const headers: Record<string, string> = {
      authorization: this.#authorization,
      accept: 'application/json',
      'user-agent': 'xendit-proxy-webhook/0.1',
    };
    if (versioned) headers['api-version'] = this.#apiVersion;
    if (body) headers['content-type'] = 'application/json';

    try {
      const response = await request(url, {
        method,
        headers,
        ...(body ? { body: JSON.stringify(body) } : {}),
        headersTimeout: this.#timeoutMs,
        bodyTimeout: this.#timeoutMs,
      });
      const raw = await response.body.text();
      let decoded: JsonObject;
      try {
        decoded = raw ? asJsonObject(JSON.parse(raw) as unknown) : {};
      } catch {
        decoded = { raw_response: raw.slice(0, 4_000) };
      }
      return { statusCode: response.statusCode, body: decoded };
    } catch (error) {
      throw new ProviderTransportError(
        `Xendit request failed: ${errorMessage(error)}`,
        method !== 'GET',
        { cause: error },
      );
    }
  }
}

export function assertProviderSuccess(response: ProviderResponse): void {
  if (response.statusCode < 200 || response.statusCode >= 300) {
    const code = typeof response.body['error_code'] === 'string' ? response.body['error_code'] : 'XENDIT_ERROR';
    const message = typeof response.body['message'] === 'string'
      ? response.body['message']
      : `Xendit returned HTTP ${response.statusCode}`;
    throw new AppError(response.statusCode >= 500 ? 502 : response.statusCode, code, message, response.body);
  }
}
