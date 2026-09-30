import { lookup } from 'node:dns/promises';
import { request as httpsRequest } from 'node:https';
import ipaddr from 'ipaddr.js';
import { AppError } from '../security/errors.js';

export type DeliveryResponse = { statusCode: number; responseExcerpt: string };

function isPublicAddress(address: string): boolean {
  return ipaddr.parse(address).range() === 'unicast';
}

export async function sendWebhook(
  destination: string,
  rawBody: Buffer,
  headers: Record<string, string>,
  timeoutMs: number,
): Promise<DeliveryResponse> {
  const url = new URL(destination);
  if (url.protocol !== 'https:' || url.username || url.password || url.port ||
      url.hostname === 'localhost' || url.hostname.endsWith('.localhost')) {
    throw new AppError(400, 'INVALID_DESTINATION', 'Destination must be public HTTPS on port 443');
  }
  const addresses = await lookup(url.hostname, { all: true, verbatim: true });
  if (addresses.length === 0 || addresses.some((item) => !isPublicAddress(item.address))) {
    throw new AppError(400, 'INVALID_DESTINATION', 'Destination address is not public');
  }
  const pinned = addresses[0];
  if (!pinned) throw new Error('DNS address disappeared');

  return new Promise((resolve, reject) => {
    const request = httpsRequest(url, {
      method: 'POST',
      agent: false,
      timeout: timeoutMs,
      headers: {
        ...headers,
        'content-type': 'application/json',
        'content-length': rawBody.length,
        'user-agent': 'xendit-proxy-webhook/0.1',
      },
      lookup(_hostname, options, callback) {
        if (typeof options === 'object' && options.all) {
          callback(null, [{ address: pinned.address, family: pinned.family }]);
        } else {
          callback(null, pinned.address, pinned.family);
        }
      },
      maxHeaderSize: 16_384,
    }, (response) => {
      const chunks: Buffer[] = [];
      let remaining = 512;
      let settled = false;
      let totalBytes = 0;
      const complete = (): void => {
        if (settled) return;
        settled = true;
        resolve({
          statusCode: response.statusCode ?? 0,
          responseExcerpt: Buffer.concat(chunks).toString('utf8'),
        });
      };
      response.on('data', (chunk: Buffer) => {
        totalBytes += chunk.length;
        if (totalBytes > 1_048_576) {
          reject(new Error('Downstream response exceeded 1 MiB'));
          response.destroy();
          return;
        }
        if (remaining > 0) {
          const slice = chunk.subarray(0, remaining);
          chunks.push(slice);
          remaining -= slice.length;
        }
      });
      response.on('end', complete);
      response.on('close', complete);
      response.on('error', reject);
    });
    request.on('timeout', () => request.destroy(new Error('Downstream delivery timed out')));
    request.on('error', reject);
    request.end(rawBody);
  });
}
