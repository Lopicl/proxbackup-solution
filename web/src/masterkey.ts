// SPDX-License-Identifier: AGPL-3.0-or-later

// RSA master key pair generation in the browser, so the private key never
// reaches the console. The output matches proxmox-backup-client key
// create-master-key: master-public.pem is a PKIX "PUBLIC KEY", and
// master-private.pem a passphrase-encrypted PKCS#8 key (PBES2 with
// PBKDF2-HMAC-SHA256 and AES-256-CBC, OpenSSL's default), which
// `key import-with-master-key` reads.

const PBKDF2_ITERATIONS = 200_000

export interface MasterKeyPair {
  publicPem: string
  privatePem: string
}

export async function generateMasterKeyPair(passphrase: string, bits = 4096): Promise<MasterKeyPair> {
  const subtle = crypto.subtle
  if (!subtle) throw new Error('This browser cannot generate keys here (Web Crypto needs HTTPS).')
  const kp = await subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt'],
  )
  // Web Crypto exports RSA keys with the plain rsaEncryption OID whatever the
  // algorithm they were generated for.
  const spki = new Uint8Array(await subtle.exportKey('spki', kp.publicKey))
  const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', kp.privateKey))

  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(16))
  const base = await subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey'])
  const aes = await subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    base,
    { name: 'AES-CBC', length: 256 },
    false,
    ['encrypt'],
  )
  const enc = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv }, aes, pkcs8)) // PKCS#7 padded

  const epki = seq(
    seq(
      OID_PBES2,
      seq(
        seq(OID_PBKDF2, seq(octets(salt), integer(PBKDF2_ITERATIONS), seq(OID_HMAC_SHA256, NULL))),
        seq(OID_AES256_CBC, octets(iv)),
      ),
    ),
    octets(enc),
  )
  return { publicPem: pem('PUBLIC KEY', spki), privatePem: pem('ENCRYPTED PRIVATE KEY', epki) }
}

// Minimal DER encoding.

const OID_PBES2 = hex('06092a864886f70d01050d') // 1.2.840.113549.1.5.13
const OID_PBKDF2 = hex('06092a864886f70d01050c') // 1.2.840.113549.1.5.12
const OID_HMAC_SHA256 = hex('06082a864886f70d0209') // 1.2.840.113549.2.9
const OID_AES256_CBC = hex('060960864801650304012a') // 2.16.840.1.101.3.4.1.42
const NULL = hex('0500')

function hex(s: string): Uint8Array {
  return new Uint8Array(s.match(/../g)!.map((b) => parseInt(b, 16)))
}

function tlv(tag: number, body: Uint8Array): Uint8Array {
  const n = body.length
  const len = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : n < 0x10000 ? [0x82, n >> 8, n & 0xff] : [0x83, n >> 16, (n >> 8) & 0xff, n & 0xff]
  const out = new Uint8Array(1 + len.length + n)
  out[0] = tag
  out.set(len, 1)
  out.set(body, 1 + len.length)
  return out
}

function seq(...parts: Uint8Array[]): Uint8Array {
  const body = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let off = 0
  for (const p of parts) {
    body.set(p, off)
    off += p.length
  }
  return tlv(0x30, body)
}

function octets(b: Uint8Array): Uint8Array {
  return tlv(0x04, b)
}

function integer(n: number): Uint8Array {
  const b: number[] = []
  do {
    b.unshift(n & 0xff)
    n = Math.floor(n / 256)
  } while (n > 0)
  if (b[0] & 0x80) b.unshift(0)
  return tlv(0x02, new Uint8Array(b))
}

function pem(label: string, der: Uint8Array): string {
  let bin = ''
  for (const c of der) bin += String.fromCharCode(c)
  const lines = btoa(bin).match(/.{1,64}/g)!.join('\n')
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`
}
