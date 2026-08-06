import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import {
  getPublicKey, getXOnlyPubKey, getTaprootAddress,
  privateKeyToWIF, wifToPrivateKey,
  bytesToHex, hexToBytes, bech32Encode, bech32Decode, convertBits,
  decodeAddress, createTransaction, taggedHash,
  BECH32_CONST, BECH32M_CONST
} from '../bitcoin.js';

const vectors = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url)));

const nostrEnc = (hrp, bytes) => bech32Encode(hrp, convertBits(Array.from(bytes), 8, 5), BECH32_CONST);

for (const v of vectors) {
  const label = v.privkey.slice(0, 8) + '…';
  const priv = hexToBytes(v.privkey);

  test(`vector ${label}: public keys`, () => {
    assert.equal(bytesToHex(getXOnlyPubKey(priv)), v.pubkey);
    assert.equal(bytesToHex(getPublicKey(priv)), v.pubkeycompressed);
    assert.equal('did:nostr:' + v.pubkey, v.didnostr);
  });

  test(`vector ${label}: nostr bech32 encodings`, () => {
    assert.equal(nostrEnc('nsec', priv), v.nsec);
    assert.equal(nostrEnc('npub', hexToBytes(v.pubkey)), v.npub);
    assert.equal(nostrEnc('nrepo', hexToBytes(v.pubkey)), v.nrepo);
  });

  test(`vector ${label}: taproot addresses (untweaked x-only key)`, () => {
    assert.equal(getTaprootAddress(priv, 'bc'), v.taproot);
    assert.equal(getTaprootAddress(priv), v.taproottestnet);
    // address decodes back to a p2tr witness program equal to the pubkey
    const decoded = decodeAddress(v.taproottestnet);
    assert.equal(decoded.type, 'p2tr');
    assert.equal(bytesToHex(decoded.hash), v.pubkey);
    // npub and taproot address carry the same payload
    assert.equal(
      bytesToHex(new Uint8Array(convertBits(bech32Decode(v.npub).data, 5, 8, false))),
      v.pubkey
    );
  });

  test(`vector ${label}: WIF`, () => {
    assert.equal(privateKeyToWIF(priv), v.wiftestnet);
    assert.equal(bytesToHex(wifToPrivateKey(v.wiftestnet)), v.privkey);
  });

  test(`vector ${label}: schnorr pubkey matches address key`, () => {
    // key-path spends sign with the plain private key, so the BIP340 pubkey
    // must equal the witness program of the derived address
    assert.equal(bytesToHex(schnorr.getPublicKey(priv)), v.pubkey);
  });
}

// ---- transaction signing: rebuild the BIP341 sighash from the serialized tx
// and verify the witness signature against the address's witness program ----

function txReader(bytes) {
  let pos = 0;
  return {
    take(n) { const r = bytes.slice(pos, pos + n); pos += n; return r; },
    varint() {
      const first = bytes[pos++];
      if (first < 0xfd) return first;
      if (first === 0xfd) { const r = bytes[pos] | (bytes[pos + 1] << 8); pos += 2; return r; }
      throw new Error('varint too large for test');
    },
    get pos() { return pos; }
  };
}

test('createTransaction: valid schnorr key-path signature over BIP341 sighash', async () => {
  const sender = vectors[0];
  const recipient = vectors[1];
  const priv = hexToBytes(sender.privkey);
  const utxo = { txid: 'f'.repeat(64), vout: 1, value: 100000 };

  const tx = await createTransaction(priv, [utxo], recipient.taproottestnet, 50000, 2);
  const bytes = hexToBytes(tx.hex);
  const r = txReader(bytes);

  const version = r.take(4);
  assert.deepEqual(Array.from(r.take(2)), [0x00, 0x01], 'segwit marker+flag');
  const inCount = r.varint();
  assert.equal(inCount, 1);
  const inputs = [];
  for (let i = 0; i < inCount; i++) {
    const txid = r.take(32);
    const vout = r.take(4);
    const scriptLen = r.varint();
    r.take(scriptLen);
    const sequence = r.take(4);
    inputs.push({ txid, vout, sequence });
  }
  assert.equal(bytesToHex(inputs[0].txid), 'f'.repeat(64), 'txid little-endian of all-f');
  const outCount = r.varint();
  assert.equal(outCount, 2, 'payment + change');
  const outputs = [];
  for (let i = 0; i < outCount; i++) {
    const value = r.take(8);
    const script = r.take(r.varint());
    outputs.push({ value, script });
  }
  assert.equal(bytesToHex(outputs[0].script), '5120' + recipient.pubkey, 'payment to recipient key');
  assert.equal(bytesToHex(outputs[1].script), '5120' + sender.pubkey, 'change back to sender key');
  const witnessItems = r.varint();
  assert.equal(witnessItems, 1);
  const sig = r.take(r.varint());
  assert.equal(sig.length, 64, 'SIGHASH_DEFAULT schnorr signature');
  const locktime = r.take(4);
  assert.equal(r.pos, bytes.length, 'no trailing bytes');

  // independently recompute the BIP341 key-path sighash
  const prevoutScript = hexToBytes('5120' + sender.pubkey);
  const amount = new Uint8Array(8);
  new DataView(amount.buffer).setBigUint64(0, BigInt(utxo.value), true);
  const sigMsg = new Uint8Array([
    0x00, 0x00,
    ...version, ...locktime,
    ...sha256(new Uint8Array([...inputs[0].txid, ...inputs[0].vout])),
    ...sha256(amount),
    ...sha256(new Uint8Array([prevoutScript.length, ...prevoutScript])),
    ...sha256(inputs[0].sequence),
    ...sha256(new Uint8Array(outputs.flatMap(o => [...o.value, o.script.length, ...o.script]))),
    0x00,
    0, 0, 0, 0,
  ]);
  const sighash = taggedHash('TapSighash', sigMsg);

  assert.ok(schnorr.verify(sig, sighash, hexToBytes(sender.pubkey)),
    'witness signature verifies against the untweaked output key');
});

// ---- bech32m sanity against an official BIP341 reference vector ----

test('bech32m: BIP341 wallet test vector address', () => {
  // From bip-0341/wallet-test-vectors.json (key-path-only entry): the
  // scriptPubKey 5120<program> encodes to this bip350Address
  const program = hexToBytes('53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343');
  const words = [1].concat(convertBits(Array.from(program), 8, 5));
  assert.equal(
    bech32Encode('bc', words, BECH32M_CONST),
    'bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5'
  );
});
