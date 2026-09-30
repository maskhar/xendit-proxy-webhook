import type { FastifyRequest } from 'fastify';
import type { Config } from '../config/env.js';
import { timingSafeTokenEqual } from '../security/crypto.js';
import { AppError } from '../security/errors.js';

export function authenticateAdmin(config: Config, request: FastifyRequest): void {
  const authorization = request.headers.authorization;
  const candidate = authorization?.startsWith('Bearer ') ? authorization.slice(7) : undefined;
  if (!candidate || !timingSafeTokenEqual(candidate, config.adminToken)) {
    throw new AppError(401, 'UNAUTHORIZED', 'Admin token required');
  }
}
