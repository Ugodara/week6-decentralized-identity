// verifier.js — "the bouncer"
// Loads src/policy.json (the rules) and checks a presented credential,
// holder binding, and requested action against every rule before granting
// access. Fails closed: any missing/ambiguous condition results in denial.
//
// Dependencies:
//   npm install @noble/ed25519 @noble/hashes multiformats
//
// Usage:
//   node src/verifier.js --fixture <path> --holder <did> --action <action>

import { readFileSync } from 'fs';
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { base58btc } from 'multiformats/bases/base58';

ed25519.hashes.sha512 = sha512;

const POLICY_PATH = new URL('./policy.json', import.meta.url);

// --- Reason codes -----------------------------------------------------
// Stable, machine-checkable codes for automated tests and audit logs.
export const ReasonCode = {
  OK: 'OK',
  POLICY_INVALID: 'POLICY_INVALID',
  FIXTURE_UNREADABLE: 'FIXTURE_UNREADABLE',
  TYPE_MISMATCH: 'TYPE_MISMATCH',
  ISSUER_UNTRUSTED: 'ISSUER_UNTRUSTED',
  AUDIENCE_MISMATCH: 'AUDIENCE_MISMATCH',
  STATUS_INVALID: 'STATUS_INVALID',
  CREDENTIAL_EXPIRED: 'CREDENTIAL_EXPIRED',
  CLAIM_MISSING: 'CLAIM_MISSING',
  PROOF_MISSING: 'PROOF_MISSING',
  SIGNATURE_INVALID: 'SIGNATURE_INVALID',
  HOLDER_MISMATCH: 'HOLDER_MISMATCH',
  ACTION_NOT_ALLOWED: 'ACTION_NOT_ALLOWED'
};

export function loadPolicy(path = POLICY_PATH) {
  let raw;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (err) {
    throw new Error(`Cannot read policy.json: ${err.message}`);
  }

  let policy;
  try {
    policy = JSON.parse(raw);
  } catch (err) {
    throw new Error(`policy.json is not valid JSON: ${err.message}`);
  }

  const required = [
    'endpoint', 'acceptedIssuer', 'acceptedType', 'requiredStatus',
    'requiredClaims', 'allowedActions', 'requireAudience', 'failClosed'
  ];
  for (const key of required) {
    if (!(key in policy)) {
      throw new Error(`policy.json is missing required field: ${key}`);
    }
  }
  if (policy.acceptedIssuer === 'REPLACE_WITH_APPROVED_ISSUER_DID') {
    throw new Error('policy.json: acceptedIssuer is still a placeholder');
  }
  if (policy.requireAudience && !policy.audience) {
    throw new Error('policy.json: requireAudience is true but audience is not set');
  }
  return policy;
}

// Decodes a did:key (Ed25519 only, multicodec 0xed01) back to raw public key bytes.
function pubKeyFromDidKey(did) {
  if (typeof did !== 'string' || !did.startsWith('did:key:z')) {
    throw new Error('Unsupported or malformed DID (expected did:key:z...)');
  }
  const bytes = base58btc.decode(did.slice('did:key:'.length));
  if (bytes[0] !== 0xed || bytes[1] !== 0x01) {
    throw new Error('Unsupported key type in DID (expected Ed25519 multicodec 0xed01)');
  }
  return bytes.slice(2);
}

function deny(reasonCode, message) {
  return {
    decision: 'DENY',
    reason_code: reasonCode,
    reason: message,
    timestamp: new Date().toISOString()
  };
}

function allow(credential, action) {
  return {
    decision: 'ALLOW',
    reason_code: ReasonCode.OK,
    action,
    subject: credential.credentialSubject?.id ?? 'unknown',
    timestamp: new Date().toISOString()
  };
}

// Core decision function — checks credential validity, holder binding, and
// the requested action, in that order. Exported for the automated test suite.
export async function verifyCredential(credential, policy, { holder, action } = {}) {
  // 1. Type check
  const types = Array.isArray(credential.type) ? credential.type : [credential.type];
  if (!types.includes(policy.acceptedType)) {
    return deny(ReasonCode.TYPE_MISMATCH, `Expected type ${policy.acceptedType}`);
  }

  // 2. Issuer check
  const issuer = typeof credential.issuer === 'string'
    ? credential.issuer
    : credential.issuer?.id;
  if (issuer !== policy.acceptedIssuer) {
    return deny(ReasonCode.ISSUER_UNTRUSTED, 'Issuer is not in the accepted list');
  }

  // 3. Audience check
  if (policy.requireAudience) {
    const aud = credential.audience ?? credential.aud;
    if (aud !== policy.audience) {
      return deny(ReasonCode.AUDIENCE_MISMATCH, 'Credential audience does not match verifier');
    }
  }

  // 4. Status check
  const status = credential.credentialStatus?.status ?? credential.status;
  if (status !== policy.requiredStatus) {
    return deny(ReasonCode.STATUS_INVALID, `Status is not "${policy.requiredStatus}"`);
  }

  // 5. Freshness check
  if (policy.maxCredentialAgeSeconds) {
    const issuedAt = new Date(credential.issuanceDate ?? credential.iat * 1000);
    if (isNaN(issuedAt.getTime())) {
      return deny(ReasonCode.CREDENTIAL_EXPIRED, 'Missing or invalid issuance timestamp');
    }
    const ageSeconds = (Date.now() - issuedAt.getTime()) / 1000;
    if (ageSeconds > policy.maxCredentialAgeSeconds) {
      return deny(ReasonCode.CREDENTIAL_EXPIRED, 'Credential exceeds max allowed age');
    }
  }

  // 6. Required claims presence
  const subject = credential.credentialSubject ?? {};
  for (const claim of policy.requiredClaims) {
    if (!(claim in subject)) {
      return deny(ReasonCode.CLAIM_MISSING, `Missing required claim: ${claim}`);
    }
  }

  // 7. Signature verification
  const { proof } = credential;
  if (!proof?.signatureValue && !proof?.jws) {
    return deny(ReasonCode.PROOF_MISSING, 'Credential has no proof/signature');
  }
  try {
    const pubKey = pubKeyFromDidKey(issuer);
    const signatureHex = proof.signatureValue ?? proof.jws;
    const signature = Buffer.from(signatureHex, 'hex');
    const unsigned = { ...credential };
    delete unsigned.proof;
    const message = Buffer.from(JSON.stringify(unsigned));
    const valid = await ed25519.verifyAsync(signature, message, pubKey);
    if (!valid) {
      return deny(ReasonCode.SIGNATURE_INVALID, 'Signature does not match issuer key');
    }
  } catch (err) {
    return deny(ReasonCode.SIGNATURE_INVALID, `Signature check error: ${err.message}`);
  }

  // 8. Holder binding — the credential must belong to whoever is presenting it
  if (holder && subject.id !== holder) {
    return deny(ReasonCode.HOLDER_MISMATCH, 'Presented holder does not match credentialSubject.id');
  }

  // 9. Requested action must be in the policy's allow-list
  if (action && !policy.allowedActions.includes(action)) {
    return deny(ReasonCode.ACTION_NOT_ALLOWED, `Action "${action}" is not permitted by policy`);
  }

  return allow(credential, action);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      args[argv[i].slice(2)] = argv[i + 1];
      i++;
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (!args.fixture) {
    console.error('Usage: node src/verifier.js --fixture <path> --holder <did> --action <action>');
    process.exit(1);
  }

  let policy;
  try {
    policy = loadPolicy();
  } catch (err) {
    console.log(JSON.stringify(deny(ReasonCode.POLICY_INVALID, err.message)));
    process.exit(1);
  }

  let credential;
  try {
    credential = JSON.parse(readFileSync(args.fixture, 'utf8'));
  } catch (err) {
    console.log(JSON.stringify(deny(ReasonCode.FIXTURE_UNREADABLE, err.message)));
    process.exit(1);
  }

  const result = await verifyCredential(credential, policy, {
    holder: args.holder,
    action: args.action
  });

  console.log(JSON.stringify(result, null, 2));
  process.exit(result.decision === 'ALLOW' ? 0 : 1);
}

// Only run the CLI when this file is executed directly, not when imported by
// tests. Compares resolved file:// URLs (via pathToFileURL) so this works
// correctly on both POSIX and Windows paths.
import { pathToFileURL } from 'url';
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}