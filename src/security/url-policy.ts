import { lookup } from 'node:dns/promises';
import ipaddr from 'ipaddr.js';
import { AppError } from './errors.js';

function isPublicAddress(address: string): boolean {
  const parsed = ipaddr.parse(address);
  const range = parsed.range();
  return range === 'unicast';
}

export async function assertSafeDestination(rawUrl: string): Promise<URL> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new AppError(400, 'INVALID_DESTINATION', 'Destination URL is invalid');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.port) {
    throw new AppError(400, 'INVALID_DESTINATION', 'Destination must use HTTPS without credentials or custom port');
  }
  if (url.hostname === 'localhost' || url.hostname.endsWith('.localhost')) {
    throw new AppError(400, 'INVALID_DESTINATION', 'Local destination is blocked');
  }

  const addresses = await lookup(url.hostname, { all: true, verbatim: true });
  if (addresses.length === 0 || addresses.some(({ address }) => !isPublicAddress(address))) {
    throw new AppError(400, 'INVALID_DESTINATION', 'Destination resolves to a non-public address');
  }
  return url;
}
