import type { LoggerOptions } from 'pino';

export function loggerOptions(level: string): LoggerOptions {
  return {
    level,
    redact: {
      paths: [
        'req.headers.authorization',
        'req.headers.x-callback-token',
        'req.headers.apikey',
        'request.headers.authorization',
        'request.headers.x-callback-token',
        'xenditApiKey',
        'adminToken',
        '*.ciphertext',
      ],
      censor: '[REDACTED]',
    },
    serializers: {
      req(request: unknown) {
        if (request === null || typeof request !== 'object') return {};
        const input = request as Record<string, unknown>;
        const path = typeof input['url'] === 'string' ? input['url'].split('?', 1)[0] : undefined;
        return {
          method: typeof input['method'] === 'string' ? input['method'] : undefined,
          path,
          id: typeof input['id'] === 'string' ? input['id'] : undefined,
        };
      },
    },
  };
}
