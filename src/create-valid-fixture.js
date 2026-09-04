// create-valid-fixture.js — "the credential printer"
// Generates (or reuses) an issuer Ed25519 keypair, then builds and signs a
// credential that satisfies every rule in policy.json: correct type, issuer
// DID, audience, status, and required claims. Writes the result to a fixture
// file that verifier.js can consume.
//
// Dependencies:
//   npm install @noble/ed25519 multiformats
//
// Usage:
//   node src/create-valid-fixture.js
//   node src/create-valid-fixture.js --out fixtures/valid-credential.json

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { base58btc } from 'multiformats/bases/base58';

// @noble/ed25519 v3 requires the hash function to be supplied explicitly.
ed25519.hashes.sha512 = sha512;

const PRIVATE_DIR = './private';
const PRIV_KEY_PATH = `${PRIVATE_DIR}/issuer-private-key.hex`;
const PUB_KEY_PATH = `${PRIVATE_DIR}/issuer-public-key.hex`;
const POLICY_PATH = './src/policy.json';

function loadPolicy() {
  if (!existsSync(POLICY_PATH)) {
    throw new Error(`policy.json not found at ${POLICY_PATH}`);
  }
  return JSON.parse(readFileSync(POLICY_PATH, 'utf8'));
}

// Reuses an existing issuer keypair if present; otherwise generates one.
// This is what was missing before and caused the ENOENT error.
async function loadOrCreateIssuerKeys() {
  if (existsSync(PRIV_KEY_PATH) && existsSync(PUB_KEY_PATH)) {
    const priv = readFileSync(PRIV_KEY_PATH, 'utf8').trim();
    const pub = readFileSync(PUB_KEY_PATH, 'utf8').trim();
    return { priv, pub };
  }

  console.log('No issuer keypair found — generating a new one.');
  mkdirSync(PRIVATE_DIR, { recursive: true });

  const privBytes = ed25519.utils.randomSecretKey();
  const pubBytes = await ed25519.getPublicKeyAsync(privBytes);

  const priv = Buffer.from(privBytes).toString('hex');
  const pub = Buffer.from(pubBytes).toString('hex');

  writeFileSync(PRIV_KEY_PATH, priv, { mode: 0o600 });
  writeFileSync(PUB_KEY_PATH, pub);

  console.log(`Generated new issuer keypair:`);
  console.log(`  private: ${PRIV_KEY_PATH} (kept local, never commit this)`);
  console.log(`  public:  ${PUB_KEY_PATH}`);

  return { priv, pub };
}

function didFromPublicKeyHex(pubHex) {
  const pub = Buffer.from(pubHex, 'hex');
  const bytes = new Uint8Array(2 + pub.length);
  bytes.set([0xed, 0x01], 0);      // Ed25519 multicodec prefix
  bytes.set(pub, 2);
  return 'did:key:' + base58btc.encode(bytes);
}

async function buildAndSignCredential(policy, keys) {
  const issuerDid = didFromPublicKeyHex(keys.pub);

  if (policy.requireAudience && !policy.audience) {
    throw new Error('policy.json: requireAudience is true but audience is not set — cannot build a valid fixture');
  }

  const unsigned = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential', policy.acceptedType],
    issuer: issuerDid,
    audience: policy.audience,
    issuanceDate: new Date().toISOString(),
    credentialStatus: { status: policy.requiredStatus },
    credentialSubject: {
      id: 'did:key:zSUBJECT_PLACEHOLDER',
      course: 'decentralized-identity-week6',
      cohort: 'ihifix-2026-cohort-2',
      status: policy.requiredStatus
    }
  };

  // Confirm every claim the policy requires is actually present before signing.
  for (const claim of policy.requiredClaims) {
    if (!(claim in unsigned.credentialSubject)) {
      throw new Error(`Fixture is missing required claim: ${claim} — add it above before signing`);
    }
  }

  const privBytes = Buffer.from(keys.priv, 'hex');
  const message = Buffer.from(JSON.stringify(unsigned));
  const signature = await ed25519.signAsync(message, privBytes);

  return {
    ...unsigned,
    proof: {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: issuerDid,
      signatureValue: Buffer.from(signature).toString('hex')
    }
  };
}

async function main() {
  const outArgIndex = process.argv.indexOf('--out');
  const outPath = outArgIndex !== -1 ? process.argv[outArgIndex + 1] : 'fixtures/valid-credential.json';

  const policy = loadPolicy();
  const keys = await loadOrCreateIssuerKeys();
  const credential = await buildAndSignCredential(policy, keys);

  mkdirSync(outPath.split('/').slice(0, -1).join('/') || '.', { recursive: true });
  writeFileSync(outPath, JSON.stringify(credential, null, 2));

  console.log(`\nFixture written to ${outPath}`);
  console.log(`Issuer DID: ${credential.issuer}`);
  console.log(`\nIf policy.json's acceptedIssuer does not match this DID yet, update it manually — this script intentionally does not modify policy.json.`);
}

main().catch(err => {
  console.error(`Fixture generation failed: ${err.message}`);
  process.exit(1);
});