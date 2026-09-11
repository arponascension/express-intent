import { randomBytes } from 'node:crypto';

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function generateRequestId(now: number = Date.now()): string {
  const timePart = encodeTime(now, 12);
  const randomPart = encodeRandom(16);
  return `${timePart}${randomPart}`;
}

function encodeTime(now: number, len: number): string {
  let out = '';
  let value = now;
  for (let i = len - 1; i >= 0; i--) {
    const mod = value % 32;
    out = (ALPHABET[mod] ?? '0') + out;
    value = (value - mod) / 32;
  }
  return out;
}

function encodeRandom(len: number): string {
  const bytes = randomBytes(len);
  let out = '';
  for (let i = 0; i < len; i++) {
    out += ALPHABET[bytes[i]! % 32];
  }
  return out;
}
