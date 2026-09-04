// tests/verifier.test.js
// Automated test suite for verifier.js. Uses Node's built-in test runner
// (no extra dependencies). Signs fresh in-memory credentials with a
// throwaway keypair so tests never depend on files under private/.
//
// Run with: node --test tests/
// (wired up via `pnpm test` in package.json)

import test from 'node:test';
import assert from 'node:assert/strict';
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { base58btc } from 'multiformats/bases/base58';
import { verifyCredential, ReasonCode } from '../src/verifier.js';

ed25519.hashes.sha512 = sha512;

const POLICY = {
  endpoint: '/training-access',
  acceptedType: 'IhifixTrainingCredential',
  requiredStatus: 'active',
  requiredClaims: ['course', 'cohort', 'status'],
  allowedActions: ['read-training-lab'],
  requireAudience: true,
  audience: 'did:key:zVERIFIER_TEST',
  failClosed: true
};

async function makeIssuer() {
  const priv = ed25519.utils.randomSecretKey();
  const pub = await ed25519.getPublicKeyAsync(priv);
  const bytes = new Uint8Array(2 + pub.length);
  bytes.set([0xed, 0x01], 0);
  bytes.set(pub, 2);
  const did = 'did:key:' + base58btc.encode(bytes);
  return { priv, did };
}

async function sign(credential, priv) {
  const message = Buffer.from(JSON.stringify(credential));
  const signature = await ed25519.signAsync(message, priv);
  return {
    ...credential,
    proof: { type: 'Ed25519Signature2020', signatureValue: Buffer.from(signature).toString('hex') }
  };
}

function baseCredential(issuerDid, overrides = {}) {
  return {
    type: ['VerifiableCredential', 'IhifixTrainingCredential'],
    issuer: issuerDid,
    audience: POLICY.audience,
    issuanceDate: new Date().toISOString(),
    credentialStatus: { status: 'active' },
    credentialSubject: {
      id: 'did:key:zHOLDER_TEST',
      course: 'week6',
      cohort: 'cohort-2',
      status: 'active'
    },
    ...overrides
  };
}

let issuer;
test.before(async () => {
  issuer = await makeIssuer();
});

test('1. valid credential, valid holder, allowed action -> ALLOW', async () => {
  const policy = { ...POLICY, acceptedIssuer: issuer.did };
  const cred = await sign(baseCredential(issuer.did), issuer.priv);
  const result = await verifyCredential(cred, policy, {
    holder: 'did:key:zHOLDER_TEST',
    action: 'read-training-lab'
  });
  assert.equal(result.decision, 'ALLOW');
  assert.equal(result.reason_code, ReasonCode.OK);
});

test('2. wrong credential type -> DENY / TYPE_MISMATCH', async () => {
  const policy = { ...POLICY, acceptedIssuer: issuer.did };
  const cred = await sign(baseCredential(issuer.did, { type: ['VerifiableCredential', 'SomeOtherCredential'] }), issuer.priv);
  const result = await verifyCredential(cred, policy, { action: 'read-training-lab' });
  assert.equal(result.decision, 'DENY');
  assert.equal(result.reason_code, ReasonCode.TYPE_MISMATCH);
});

test('3. untrusted issuer -> DENY / ISSUER_UNTRUSTED', async () => {
  const policy = { ...POLICY, acceptedIssuer: 'did:key:zSOMEONE_ELSE' };
  const cred = await sign(baseCredential(issuer.did), issuer.priv);
  const result = await verifyCredential(cred, policy, { action: 'read-training-lab' });
  assert.equal(result.decision, 'DENY');
  assert.equal(result.reason_code, ReasonCode.ISSUER_UNTRUSTED);
});

test('4. status not active -> DENY / STATUS_INVALID', async () => {
  const policy = { ...POLICY, acceptedIssuer: issuer.did };
  const cred = await sign(baseCredential(issuer.did, { credentialStatus: { status: 'revoked' } }), issuer.priv);
  const result = await verifyCredential(cred, policy, { action: 'read-training-lab' });
  assert.equal(result.decision, 'DENY');
  assert.equal(result.reason_code, ReasonCode.STATUS_INVALID);
});

test('5. tampered signature -> DENY / SIGNATURE_INVALID', async () => {
  const policy = { ...POLICY, acceptedIssuer: issuer.did };
  const cred = await sign(baseCredential(issuer.did), issuer.priv);
  cred.credentialSubject.course = 'tampered-after-signing';
  const result = await verifyCredential(cred, policy, { action: 'read-training-lab' });
  assert.equal(result.decision, 'DENY');
  assert.equal(result.reason_code, ReasonCode.SIGNATURE_INVALID);
});

test('6. disallowed action -> DENY / ACTION_NOT_ALLOWED', async () => {
  const policy = { ...POLICY, acceptedIssuer: issuer.did };
  const cred = await sign(baseCredential(issuer.did), issuer.priv);
  const result = await verifyCredential(cred, policy, {
    holder: 'did:key:zHOLDER_TEST',
    action: 'delete-root-database'
  });
  assert.equal(result.decision, 'DENY');
  assert.equal(result.reason_code, ReasonCode.ACTION_NOT_ALLOWED);
});