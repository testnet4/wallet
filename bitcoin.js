// Bitcoin utilities for the Testnet4 Taproot wallet.
// Shared between index.html (via import map -> esm.sh) and the Node test suite.
//
// Address scheme: the x-only public key is used directly as the v1 witness
// program (no BIP341 tweak), so the taproot address is the bech32m encoding of
// the same key as the Nostr npub. Key-path spends sign with the plain private
// key.

import { secp256k1, schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

export const TESTNET4_PREFIX = 'tb';
export const MAINNET_PREFIX = 'bc';
const TESTNET4_WIF_PREFIX = 0xef;
export const BECH32_CONST = 1;
export const BECH32M_CONST = 0x2bc830a3;

// Bech32/Bech32m encoding
const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function bech32Polymod(values) {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((b >> i) & 1) chk ^= GEN[i];
    }
  }
  return chk;
}

function bech32HrpExpand(hrp) {
  const ret = [];
  for (const c of hrp) {
    ret.push(c.charCodeAt(0) >> 5);
  }
  ret.push(0);
  for (const c of hrp) {
    ret.push(c.charCodeAt(0) & 31);
  }
  return ret;
}

function bech32CreateChecksum(hrp, data, spec) {
  const values = bech32HrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
  const polymod = bech32Polymod(values) ^ spec;
  const ret = [];
  for (let i = 0; i < 6; i++) {
    ret.push((polymod >> (5 * (5 - i))) & 31);
  }
  return ret;
}

export function bech32Encode(hrp, data, spec) {
  const combined = data.concat(bech32CreateChecksum(hrp, data, spec));
  let ret = hrp + '1';
  for (const d of combined) {
    ret += BECH32_CHARSET[d];
  }
  return ret;
}

export function bech32Decode(str) {
  const pos = str.lastIndexOf('1');
  const hrp = str.slice(0, pos).toLowerCase();
  const data = [];
  for (let i = pos + 1; i < str.length; i++) {
    const idx = BECH32_CHARSET.indexOf(str[i].toLowerCase());
    if (idx === -1) return null;
    data.push(idx);
  }
  // spec equals BECH32_CONST or BECH32M_CONST when the checksum is valid
  const spec = bech32Polymod(bech32HrpExpand(hrp).concat(data));
  return { hrp, data: data.slice(0, -6), spec };
}

export function convertBits(data, fromBits, toBits, pad = true) {
  let acc = 0;
  let bits = 0;
  const ret = [];
  const maxv = (1 << toBits) - 1;
  for (const value of data) {
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) {
      ret.push((acc << (toBits - bits)) & maxv);
    }
  }
  return ret;
}

// Generate random bytes
export function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

// Hex utilities
export function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

// Base58 encoding for WIF
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes) {
  let num = BigInt('0x' + bytesToHex(bytes));
  let result = '';
  while (num > 0n) {
    result = BASE58_ALPHABET[Number(num % 58n)] + result;
    num = num / 58n;
  }
  for (const byte of bytes) {
    if (byte === 0) result = '1' + result;
    else break;
  }
  return result;
}

function base58Decode(str) {
  let num = 0n;
  for (const char of str) {
    const idx = BASE58_ALPHABET.indexOf(char);
    if (idx === -1) throw new Error('Invalid base58 character');
    num = num * 58n + BigInt(idx);
  }
  let hex = num.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const bytes = hexToBytes(hex);
  const leadingZeros = [];
  for (const char of str) {
    if (char === '1') leadingZeros.push(0);
    else break;
  }
  return new Uint8Array([...leadingZeros, ...bytes]);
}

function base58CheckEncode(payload) {
  const checksum = sha256(sha256(payload)).slice(0, 4);
  return base58Encode(new Uint8Array([...payload, ...checksum]));
}

function base58CheckDecode(str) {
  const bytes = base58Decode(str);
  const payload = bytes.slice(0, -4);
  const checksum = bytes.slice(-4);
  const expectedChecksum = sha256(sha256(payload)).slice(0, 4);
  for (let i = 0; i < 4; i++) {
    if (checksum[i] !== expectedChecksum[i]) {
      throw new Error('Invalid checksum');
    }
  }
  return payload;
}

// Generate private key
export function generatePrivateKey() {
  return randomBytes(32);
}

// Get compressed public key from private key
export function getPublicKey(privateKey) {
  return secp256k1.getPublicKey(privateKey, true);
}

// Get x-only public key (32 bytes) for Taproot / Nostr
export function getXOnlyPubKey(privateKey) {
  const pubKey = secp256k1.getPublicKey(privateKey, true);
  return pubKey.slice(1); // Remove the prefix byte, keep only x-coordinate
}

// Tagged hash (BIP340)
export function taggedHash(tag, data) {
  const tagHash = sha256(new TextEncoder().encode(tag));
  return sha256(new Uint8Array([...tagHash, ...tagHash, ...data]));
}

// Generate Taproot address (P2TR) using bech32m. The x-only public key is the
// witness program directly (untweaked), matching the Nostr npub key.
export function getTaprootAddress(privateKey, hrp = TESTNET4_PREFIX) {
  const xOnlyPubKey = getXOnlyPubKey(privateKey);
  const words = [1].concat(convertBits(Array.from(xOnlyPubKey), 8, 5)); // witness version 1
  return bech32Encode(hrp, words, BECH32M_CONST);
}

// Convert private key to WIF
export function privateKeyToWIF(privateKey) {
  const payload = new Uint8Array([TESTNET4_WIF_PREFIX, ...privateKey, 0x01]);
  return base58CheckEncode(payload);
}

// Convert WIF to private key
export function wifToPrivateKey(wif) {
  const decoded = base58CheckDecode(wif);
  if (decoded[0] !== TESTNET4_WIF_PREFIX) {
    throw new Error('Invalid WIF prefix for testnet');
  }
  return decoded.slice(1, decoded[decoded.length - 1] === 0x01 ? -1 : decoded.length);
}

// Parse a private key in any supported format: 64-char hex, Nostr nsec, or WIF
export function parsePrivateKey(input) {
  const trimmed = input.trim();
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    return hexToBytes(trimmed.toLowerCase());
  }
  if (/^nsec1[a-z0-9]+$/i.test(trimmed)) {
    const decoded = bech32Decode(trimmed);
    if (!decoded || decoded.hrp !== 'nsec' || decoded.spec !== BECH32_CONST) {
      throw new Error('Invalid nsec checksum');
    }
    const bytes = new Uint8Array(convertBits(decoded.data, 5, 8, false));
    if (bytes.length !== 32) throw new Error('Invalid nsec length');
    return bytes;
  }
  return wifToPrivateKey(trimmed);
}

// ===== TRANSACTION BUILDING =====

export function varInt(n) {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, (n >> 8) & 0xff]);
  if (n <= 0xffffffff) return new Uint8Array([0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]);
  throw new Error('Number too large for varInt');
}

function numberToLittleEndian(n, bytes) {
  const result = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i++) {
    result[i] = (n >> (8 * i)) & 0xff;
  }
  return result;
}

function bigintToLittleEndian(n, bytes) {
  const result = new Uint8Array(bytes);
  let temp = BigInt(n);
  for (let i = 0; i < bytes; i++) {
    result[i] = Number(temp & 0xffn);
    temp = temp >> 8n;
  }
  return result;
}

export function decodeAddress(address) {
  if (address.startsWith('tb1') || address.startsWith('TB1')) {
    const decoded = bech32Decode(address);
    if (!decoded) throw new Error('Invalid bech32 address');
    const witnessVersion = decoded.data[0];
    // BIP350: witness v0 uses bech32, v1+ uses bech32m
    const expectedSpec = witnessVersion === 0 ? BECH32_CONST : BECH32M_CONST;
    if (decoded.spec !== expectedSpec) throw new Error('Invalid address checksum');
    const witnessProgram = convertBits(decoded.data.slice(1), 5, 8, false);

    if (witnessVersion === 1 && witnessProgram.length === 32) {
      return { type: 'p2tr', hash: new Uint8Array(witnessProgram), witnessVersion };
    } else if (witnessVersion === 0 && witnessProgram.length === 20) {
      return { type: 'p2wpkh', hash: new Uint8Array(witnessProgram), witnessVersion };
    } else if (witnessVersion === 0 && witnessProgram.length === 32) {
      return { type: 'p2wsh', hash: new Uint8Array(witnessProgram), witnessVersion };
    }
    throw new Error('Unknown witness program');
  }
  throw new Error('Unsupported address format');
}

export function createOutputScript(address) {
  const decoded = decodeAddress(address);
  if (decoded.type === 'p2tr') {
    // P2TR: OP_1 <32-byte-x-only-pubkey>
    return new Uint8Array([0x51, 0x20, ...decoded.hash]);
  } else if (decoded.type === 'p2wpkh') {
    return new Uint8Array([0x00, 0x14, ...decoded.hash]);
  } else if (decoded.type === 'p2wsh') {
    return new Uint8Array([0x00, 0x20, ...decoded.hash]);
  }
  throw new Error('Unsupported address type');
}

export async function createTransaction(privateKey, utxos, toAddress, amount, feeRate) {
  const fromAddress = getTaprootAddress(privateKey);
  const xOnlyPubKey = getXOnlyPubKey(privateKey);

  // Select UTXOs
  let totalInput = 0n;
  const selectedUtxos = [];
  const targetAmount = BigInt(amount);

  // Sort UTXOs by value (largest first for efficiency)
  const sortedUtxos = [...utxos].sort((a, b) => b.value - a.value);

  for (const utxo of sortedUtxos) {
    selectedUtxos.push(utxo);
    totalInput += BigInt(utxo.value);
    // Estimate fee: ~111 vbytes for 1-in-1-out P2TR, add ~58 for each additional input
    const estimatedVbytes = 111 + (selectedUtxos.length - 1) * 58;
    const estimatedFee = BigInt(estimatedVbytes * feeRate);
    if (totalInput >= targetAmount + estimatedFee) break;
  }

  // Calculate fee (P2TR is more efficient than P2WPKH)
  // 10.5 (overhead) + 57.5 per input + 43 per P2TR output
  const vbytes = Math.ceil(10.5 + selectedUtxos.length * 57.5 + 2 * 43);
  const fee = BigInt(vbytes * feeRate);
  const change = totalInput - targetAmount - fee;

  if (change < 0n) {
    throw new Error('Insufficient funds');
  }

  // Build transaction
  const outputs = [{ address: toAddress, value: targetAmount }];
  if (change >= 330n) { // Taproot dust threshold is lower
    outputs.push({ address: fromAddress, value: change });
  }

  // Serialize for signing
  const version = numberToLittleEndian(2, 4);
  const marker = new Uint8Array([0x00]);
  const flag = new Uint8Array([0x01]);
  const inputCount = varInt(selectedUtxos.length);
  const outputCount = varInt(outputs.length);
  const locktime = numberToLittleEndian(0, 4);

  // Create inputs
  const inputs = [];
  for (const utxo of selectedUtxos) {
    const txid = hexToBytes(utxo.txid).reverse();
    const vout = numberToLittleEndian(utxo.vout, 4);
    const scriptSig = new Uint8Array([0x00]); // Empty for segwit
    const sequence = new Uint8Array([0xfd, 0xff, 0xff, 0xff]); // RBF enabled
    inputs.push({ txid, vout, scriptSig, sequence, value: BigInt(utxo.value) });
  }

  // Create outputs
  const outputsData = [];
  for (const output of outputs) {
    const script = createOutputScript(output.address);
    outputsData.push({
      value: bigintToLittleEndian(output.value, 8),
      script
    });
  }

  // Create prevout scripts for signing (P2TR scriptPubKey, untweaked key)
  const prevoutScripts = inputs.map(() => {
    return new Uint8Array([0x51, 0x20, ...xOnlyPubKey]); // OP_1 <32-byte-pubkey>
  });

  // BIP341 Taproot sighash
  // Precompute hash components
  const hashPrevouts = sha256(new Uint8Array(inputs.flatMap(inp => [...inp.txid, ...inp.vout])));
  const hashAmounts = sha256(new Uint8Array(inputs.flatMap(inp => [...bigintToLittleEndian(inp.value, 8)])));
  const hashScriptPubkeys = sha256(new Uint8Array(prevoutScripts.flatMap(script => [script.length, ...script])));
  const hashSequences = sha256(new Uint8Array(inputs.flatMap(inp => [...inp.sequence])));
  const hashOutputs = sha256(new Uint8Array(outputsData.flatMap(out => [...out.value, out.script.length, ...out.script])));

  // Sign each input with Schnorr
  const witnesses = [];

  for (let i = 0; i < inputs.length; i++) {
    // BIP341 signature hash
    const sigHashType = 0x00; // SIGHASH_DEFAULT (same as SIGHASH_ALL for taproot)

    const sigMsg = new Uint8Array([
      0x00, // hash_type epoch
      sigHashType, // sighash type
      ...version,
      ...locktime,
      ...hashPrevouts,
      ...hashAmounts,
      ...hashScriptPubkeys,
      ...hashSequences,
      ...hashOutputs,
      0x00, // spend_type (key path, no annex)
      ...numberToLittleEndian(i, 4), // input index
    ]);

    const sighash = taggedHash('TapSighash', sigMsg);

    // Sign with Schnorr using the plain private key (untweaked output key)
    const signature = schnorr.sign(sighash, privateKey);

    // For SIGHASH_DEFAULT, we don't append the hash type byte
    witnesses.push([signature]);
  }

  // Serialize final transaction
  const txParts = [
    version,
    marker,
    flag,
    inputCount
  ];

  for (const input of inputs) {
    txParts.push(input.txid, input.vout, input.scriptSig, input.sequence);
  }

  txParts.push(outputCount);

  for (const output of outputsData) {
    txParts.push(output.value, new Uint8Array([output.script.length]), output.script);
  }

  for (const witness of witnesses) {
    txParts.push(varInt(witness.length));
    for (const item of witness) {
      txParts.push(varInt(item.length), item);
    }
  }

  txParts.push(locktime);

  const txBytes = new Uint8Array(txParts.reduce((acc, part) => acc + part.length, 0));
  let offset = 0;
  for (const part of txParts) {
    txBytes.set(part, offset);
    offset += part.length;
  }

  return {
    hex: bytesToHex(txBytes),
    fee: Number(fee),
    totalInput: Number(totalInput),
    amount: Number(targetAmount)
  };
}
