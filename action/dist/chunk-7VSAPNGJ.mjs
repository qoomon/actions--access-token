import { createRequire } from 'module';
import { toUint8Array } from './chunk-GXHTACOW.mjs';
import { init_esm_shims } from './chunk-MIA7WKEC.mjs';
import * as zlib from 'zlib';
import { createHash, createHmac } from 'crypto';

createRequire(import.meta.url);

// node_modules/@smithy/core/dist-es/submodules/checksum/crc32/Crc32Node.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/checksum/crc32/Crc32Js.js
init_esm_shims();
var CRC32_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; ++i) {
  let c = i;
  for (let j = 0; j < 8; ++j) {
    c = c & 1 ? 3988292384 ^ c >>> 1 : c >>> 1;
  }
  CRC32_TABLE[i] = c >>> 0;
}
var ONES = 4294967295;
var Crc32Js = class {
  digestLength = 4;
  checksum = ONES;
  update(data) {
    for (let i = 0; i < data.length; ++i) {
      this.checksum = this.checksum >>> 8 ^ CRC32_TABLE[(this.checksum ^ data[i]) & 255];
    }
  }
  digestSync() {
    return (this.checksum ^ ONES) >>> 0;
  }
  async digest() {
    const value = this.digestSync();
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, value, false);
    return out;
  }
  reset() {
    this.checksum = ONES;
  }
};

// node_modules/@smithy/core/dist-es/submodules/checksum/crc32/Crc32Node.js
var zlibCrc32 = typeof zlib.crc32 === "function" ? zlib.crc32 : void 0;
var Crc32Node = zlibCrc32 ? buildNativeClass(zlibCrc32) : Crc32Js;
function buildNativeClass(nativeCrc32) {
  return class Crc32Node {
    digestLength = 4;
    value = 0;
    update(data) {
      this.value = nativeCrc32(data, this.value);
    }
    digestSync() {
      return this.value >>> 0;
    }
    async digest() {
      const out = new Uint8Array(4);
      new DataView(out.buffer).setUint32(0, this.digestSync(), false);
      return out;
    }
    reset() {
      this.value = 0;
    }
  };
}

// node_modules/@smithy/core/dist-es/submodules/checksum/index.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/checksum/sha256/Sha256Js.js
init_esm_shims();
var BLOCK = 64;
var DIGEST_LENGTH = 32;
var MAX_HASHABLE_LENGTH = 2 ** 53 - 1;
var Sha256Js = class _Sha256Js {
  digestLength = DIGEST_LENGTH;
  state = Int32Array.from(INIT);
  w;
  buffer = new Uint8Array(64);
  bufferLength = 0;
  bytesHashed = 0;
  finished = false;
  inner;
  outer;
  constructor(secret) {
    if (secret) {
      const key = _Sha256Js.normalizeKey(secret);
      this.inner = new _Sha256Js();
      this.outer = new _Sha256Js();
      const { inner, outer } = this;
      const pad = new Uint8Array(BLOCK * 2);
      for (let i = 0; i < BLOCK; ++i) {
        pad[i] = 54 ^ key[i];
        pad[i + BLOCK] = 92 ^ key[i];
      }
      inner.update(pad.subarray(0, BLOCK));
      outer.update(pad.subarray(BLOCK));
    }
  }
  update(data) {
    if (this.finished) {
      throw new Error("Attempted to update an already finished HMAC.");
    }
    if (this.inner) {
      this.inner.update(data);
      return;
    }
    const chunk = toUint8Array(data);
    let position = 0;
    let { byteLength } = chunk;
    this.bytesHashed += byteLength;
    if (this.bytesHashed * 8 > MAX_HASHABLE_LENGTH) {
      throw new Error("Cannot hash more than 2^53 - 1 bits");
    }
    while (byteLength > 0) {
      this.buffer[this.bufferLength++] = chunk[position++];
      byteLength--;
      if (this.bufferLength === BLOCK) {
        this.hashBuffer();
        this.bufferLength = 0;
      }
    }
  }
  async digest() {
    const { inner, outer } = this;
    if (inner && outer) {
      if (this.finished) {
        throw new Error("Attempted to digest an already finished HMAC.");
      }
      this.finished = true;
      const innerDigest = inner.digestSync();
      outer.update(innerDigest);
      return outer.digestSync();
    }
    return this.digestSync();
  }
  reset() {
    this.state = Int32Array.from(INIT);
    this.buffer = new Uint8Array(64);
    this.bufferLength = 0;
    this.bytesHashed = 0;
  }
  digestSync() {
    const state = this.state.slice();
    const buffer = this.buffer.slice();
    let bufferLength = this.bufferLength;
    const bitsHashed = this.bytesHashed * 8;
    const bufferView = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    bufferView.setUint8(bufferLength++, 128);
    if ((bufferLength - 1) % BLOCK >= BLOCK - 8) {
      for (let i = bufferLength; i < BLOCK; ++i) {
        bufferView.setUint8(i, 0);
      }
      this.hashBufferWith(state, buffer);
      bufferLength = 0;
    }
    for (let i = bufferLength; i < BLOCK - 8; ++i) {
      bufferView.setUint8(i, 0);
    }
    bufferView.setUint32(BLOCK - 8, Math.floor(bitsHashed / 4294967296), false);
    bufferView.setUint32(BLOCK - 4, bitsHashed, false);
    this.hashBufferWith(state, buffer);
    const out = new Uint8Array(DIGEST_LENGTH);
    for (let i = 0; i < 8; ++i) {
      out[i * 4] = state[i] >>> 24 & 255;
      out[i * 4 + 1] = state[i] >>> 16 & 255;
      out[i * 4 + 2] = state[i] >>> 8 & 255;
      out[i * 4 + 3] = state[i] >>> 0 & 255;
    }
    return out;
  }
  static normalizeKey(secret) {
    const key = toUint8Array(secret);
    if (key.byteLength > BLOCK) {
      const h = new _Sha256Js();
      h.update(key);
      const out = h.digestSync();
      const padded = new Uint8Array(BLOCK);
      padded.set(out);
      return padded;
    }
    if (key.byteLength < BLOCK) {
      const padded = new Uint8Array(BLOCK);
      padded.set(key);
      return padded;
    }
    return key;
  }
  hashBuffer() {
    this.hashBufferWith(this.state, this.buffer);
  }
  hashBufferWith(state, buffer) {
    const w = this.w ??= new Int32Array(64);
    let s0 = state[0], s1 = state[1], s2 = state[2], s3 = state[3], s4 = state[4], s5 = state[5], s6 = state[6], s7 = state[7];
    for (let i = 0; i < BLOCK; ++i) {
      if (i < 16) {
        w[i] = (buffer[i * 4] & 255) << 24 | (buffer[i * 4 + 1] & 255) << 16 | (buffer[i * 4 + 2] & 255) << 8 | buffer[i * 4 + 3] & 255;
      } else {
        let u = w[i - 2];
        const t12 = (u >>> 17 | u << 15) ^ (u >>> 19 | u << 13) ^ u >>> 10;
        u = w[i - 15];
        const t22 = (u >>> 7 | u << 25) ^ (u >>> 18 | u << 14) ^ u >>> 3;
        w[i] = (t12 + w[i - 7] | 0) + (t22 + w[i - 16] | 0);
      }
      const t1 = (((s4 >>> 6 | s4 << 26) ^ (s4 >>> 11 | s4 << 21) ^ (s4 >>> 25 | s4 << 7)) + (s4 & s5 ^ ~s4 & s6) | 0) + (s7 + (K[i] + w[i] | 0) | 0) | 0;
      const t2 = ((s0 >>> 2 | s0 << 30) ^ (s0 >>> 13 | s0 << 19) ^ (s0 >>> 22 | s0 << 10)) + (s0 & s1 ^ s0 & s2 ^ s1 & s2) | 0;
      s7 = s6;
      s6 = s5;
      s5 = s4;
      s4 = s3 + t1 | 0;
      s3 = s2;
      s2 = s1;
      s1 = s0;
      s0 = t1 + t2 | 0;
    }
    state[0] += s0;
    state[1] += s1;
    state[2] += s2;
    state[3] += s3;
    state[4] += s4;
    state[5] += s5;
    state[6] += s6;
    state[7] += s7;
  }
};
var INIT = new Int32Array([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]);
var K = new Int32Array([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);

// node_modules/@smithy/core/dist-es/submodules/checksum/sha256/Sha256Node.js
init_esm_shims();
var hasNativeCrypto = (() => {
  try {
    createHash("sha256");
    return true;
  } catch {
    return false;
  }
})();
var Sha256Node = hasNativeCrypto ? buildNativeClass2() : Sha256Js;
function buildNativeClass2() {
  return class Sha256Node {
    digestLength = 32;
    secret;
    hash;
    isHmac;
    finished = false;
    constructor(secret) {
      this.secret = secret;
      this.isHmac = !!secret;
      this.hash = this.createHash();
    }
    update(data) {
      if (this.finished) {
        throw new Error("Attempted to update an already finished hash.");
      }
      this.hash.update(data);
    }
    async digest() {
      let buf;
      if (this.isHmac) {
        this.finished = true;
        buf = this.hash.digest();
      } else {
        buf = this.hash.copy().digest();
      }
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    }
    reset() {
      this.hash = this.createHash();
      this.finished = false;
    }
    createHash() {
      return this.secret ? createHmac("sha256", toBuffer(this.secret)) : createHash("sha256");
    }
  };
}
function toBuffer(data) {
  if (typeof data === "string") {
    return data;
  }
  if (ArrayBuffer.isView(data)) {
    return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  }
  return Buffer.from(data);
}

export { Crc32Node, Sha256Node };
