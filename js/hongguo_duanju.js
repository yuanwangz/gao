

// 红果果[短]：全自包含红果短剧源（不依赖 hongguo-bridge 等本地插件）。
// 数据层：官网(hongguoduanju.com) SSR _ROUTER_DATA 做短剧分类/榜单/详情，
//        番茄小说 App API(bookapi/search/tab) 做真人剧/漫剧/AI剧分类与搜索——需字节系全套签名头。
//        搜索：App 搜索接口 2026-10 起返回 200 空包，已自动回退官网 /api/search/result（context 取 ttwid）。
// 签名层：x-gorgon/x-ladon/x-helios/x-medusa 全套纯 JS 实现（SM3/变种MD5/自研哈希三分支/手写protobuf/自定义AES变体），
//         算法块自实测可用的 Fastify 版(1:1)移植，勿随意改动常量与位运算顺序。
// 播放层：video_model 拿清晰度 → fallback_api 拿 video_list → spade URL 解密 → spade_a 派生 CENC 内容密钥；
//        proxy_rule 按客户端 __range 拉远端 1MB 段、AES-128-CTR 逐样本解密后 base64 回传（206 分段，免落盘秒开）。
// 依赖沙箱能力：req() + getProxyUrl()；加密、Range 拉流与 CENC 解密全在手机本地完成。

var __AC = (function () {
  // apple_js_crypto.js —— 纯 JS 加密库（MD5/SM3/SHA512/AES-128-CTR/AES-128-CBC）
  // 目标：可在无 node:crypto 的受限 JS 沙箱（iOS/鸿蒙）运行。返回类型兼容 Buffer 子集。
  /* apple_js_crypto 内联：纯JS加密库，无 node:crypto */

  /*
   * [js-sha512]{@link https://github.com/emn178/js-sha512}
   *
   * @version 0.9.0
   * @author Chen, Yi-Cyuan [emn178@gmail.com]
   * @copyright Chen, Yi-Cyuan 2014-2024
   * @license MIT
   */
  /*jslint bitwise: true */
  var JSSHA512 = (function () {
    'use strict';

    var INPUT_ERROR = 'input is invalid type';
    var FINALIZE_ERROR = 'finalize already called';
    var WINDOW = typeof window === 'object';
    var root = WINDOW ? window : {};
    if (root.JS_SHA512_NO_WINDOW) {
      WINDOW = false;
    }
    var WEB_WORKER = !WINDOW && typeof self === 'object';
    var NODE_JS = !root.JS_SHA512_NO_NODE_JS && typeof process === 'object' && process.versions && process.versions.node;
    if (NODE_JS) {
      root = global;
    } else if (WEB_WORKER) {
      root = self;
    }
    var COMMON_JS = !root.JS_SHA512_NO_COMMON_JS && typeof module === 'object' && module.exports;
    var AMD = typeof define === 'function' && define.amd;
    var ARRAY_BUFFER = !root.JS_SHA512_NO_ARRAY_BUFFER && typeof ArrayBuffer !== 'undefined';
    var HEX_CHARS = '0123456789abcdef'.split('');
    var EXTRA = [-2147483648, 8388608, 32768, 128];
    var SHIFT = [24, 16, 8, 0];
    var K = [
      0x428A2F98, 0xD728AE22, 0x71374491, 0x23EF65CD,
      0xB5C0FBCF, 0xEC4D3B2F, 0xE9B5DBA5, 0x8189DBBC,
      0x3956C25B, 0xF348B538, 0x59F111F1, 0xB605D019,
      0x923F82A4, 0xAF194F9B, 0xAB1C5ED5, 0xDA6D8118,
      0xD807AA98, 0xA3030242, 0x12835B01, 0x45706FBE,
      0x243185BE, 0x4EE4B28C, 0x550C7DC3, 0xD5FFB4E2,
      0x72BE5D74, 0xF27B896F, 0x80DEB1FE, 0x3B1696B1,
      0x9BDC06A7, 0x25C71235, 0xC19BF174, 0xCF692694,
      0xE49B69C1, 0x9EF14AD2, 0xEFBE4786, 0x384F25E3,
      0x0FC19DC6, 0x8B8CD5B5, 0x240CA1CC, 0x77AC9C65,
      0x2DE92C6F, 0x592B0275, 0x4A7484AA, 0x6EA6E483,
      0x5CB0A9DC, 0xBD41FBD4, 0x76F988DA, 0x831153B5,
      0x983E5152, 0xEE66DFAB, 0xA831C66D, 0x2DB43210,
      0xB00327C8, 0x98FB213F, 0xBF597FC7, 0xBEEF0EE4,
      0xC6E00BF3, 0x3DA88FC2, 0xD5A79147, 0x930AA725,
      0x06CA6351, 0xE003826F, 0x14292967, 0x0A0E6E70,
      0x27B70A85, 0x46D22FFC, 0x2E1B2138, 0x5C26C926,
      0x4D2C6DFC, 0x5AC42AED, 0x53380D13, 0x9D95B3DF,
      0x650A7354, 0x8BAF63DE, 0x766A0ABB, 0x3C77B2A8,
      0x81C2C92E, 0x47EDAEE6, 0x92722C85, 0x1482353B,
      0xA2BFE8A1, 0x4CF10364, 0xA81A664B, 0xBC423001,
      0xC24B8B70, 0xD0F89791, 0xC76C51A3, 0x0654BE30,
      0xD192E819, 0xD6EF5218, 0xD6990624, 0x5565A910,
      0xF40E3585, 0x5771202A, 0x106AA070, 0x32BBD1B8,
      0x19A4C116, 0xB8D2D0C8, 0x1E376C08, 0x5141AB53,
      0x2748774C, 0xDF8EEB99, 0x34B0BCB5, 0xE19B48A8,
      0x391C0CB3, 0xC5C95A63, 0x4ED8AA4A, 0xE3418ACB,
      0x5B9CCA4F, 0x7763E373, 0x682E6FF3, 0xD6B2B8A3,
      0x748F82EE, 0x5DEFB2FC, 0x78A5636F, 0x43172F60,
      0x84C87814, 0xA1F0AB72, 0x8CC70208, 0x1A6439EC,
      0x90BEFFFA, 0x23631E28, 0xA4506CEB, 0xDE82BDE9,
      0xBEF9A3F7, 0xB2C67915, 0xC67178F2, 0xE372532B,
      0xCA273ECE, 0xEA26619C, 0xD186B8C7, 0x21C0C207,
      0xEADA7DD6, 0xCDE0EB1E, 0xF57D4F7F, 0xEE6ED178,
      0x06F067AA, 0x72176FBA, 0x0A637DC5, 0xA2C898A6,
      0x113F9804, 0xBEF90DAE, 0x1B710B35, 0x131C471B,
      0x28DB77F5, 0x23047D84, 0x32CAAB7B, 0x40C72493,
      0x3C9EBE0A, 0x15C9BEBC, 0x431D67C4, 0x9C100D4C,
      0x4CC5D4BE, 0xCB3E42B6, 0x597F299C, 0xFC657E2A,
      0x5FCB6FAB, 0x3AD6FAEC, 0x6C44198C, 0x4A475817
    ];

    var OUTPUT_TYPES = ['hex', 'array', 'digest', 'arrayBuffer'];

    var blocks = [];

    var isArray = Array.isArray;
    if (root.JS_SHA512_NO_NODE_JS || !isArray) {
      isArray = function (obj) {
        return Object.prototype.toString.call(obj) === '[object Array]';
      };
    }

    var isView = ArrayBuffer.isView;
    if (ARRAY_BUFFER && (root.JS_SHA512_NO_ARRAY_BUFFER_IS_VIEW || !isView)) {
      isView = function (obj) {
        return typeof obj === 'object' && obj.buffer && obj.buffer.constructor === ArrayBuffer;
      };
    }

    // [message: string, isString: bool]
    var formatMessage = function (message) {
      var type = typeof message;
      if (type === 'string') {
        return [message, true];
      }
      if (type !== 'object' || message === null) {
        throw new Error(INPUT_ERROR);
      }
      if (ARRAY_BUFFER && message.constructor === ArrayBuffer) {
        return [new Uint8Array(message), false];
      }
      if (!isArray(message) && !isView(message)) {
        throw new Error(INPUT_ERROR);
      }
      return [message, false];
    }

    var createOutputMethod = function (outputType, bits) {
      return function (message) {
        return new Sha512(bits, true).update(message)[outputType]();
      };
    };

    var createMethod = function (bits) {
      var method = createOutputMethod('hex', bits);
      method.create = function () {
        return new Sha512(bits);
      };
      method.update = function (message) {
        return method.create().update(message);
      };
      for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
        var type = OUTPUT_TYPES[i];
        method[type] = createOutputMethod(type, bits);
      }
      return method;
    };

    var createHmacOutputMethod = function (outputType, bits) {
      return function (key, message) {
        return new HmacSha512(key, bits, true).update(message)[outputType]();
      };
    };

    var createHmacMethod = function (bits) {
      var method = createHmacOutputMethod('hex', bits);
      method.create = function (key) {
        return new HmacSha512(key, bits);
      };
      method.update = function (key, message) {
        return method.create(key).update(message);
      };
      for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
        var type = OUTPUT_TYPES[i];
        method[type] = createHmacOutputMethod(type, bits);
      }
      return method;
    };

    function Sha512(bits, sharedMemory) {
      if (sharedMemory) {
        blocks[0] = blocks[1] = blocks[2] = blocks[3] = blocks[4] =
          blocks[5] = blocks[6] = blocks[7] = blocks[8] =
          blocks[9] = blocks[10] = blocks[11] = blocks[12] =
          blocks[13] = blocks[14] = blocks[15] = blocks[16] =
          blocks[17] = blocks[18] = blocks[19] = blocks[20] =
          blocks[21] = blocks[22] = blocks[23] = blocks[24] =
          blocks[25] = blocks[26] = blocks[27] = blocks[28] =
          blocks[29] = blocks[30] = blocks[31] = blocks[32] = 0;
        this.blocks = blocks;
      } else {
        this.blocks = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
      }

      if (bits == 384) {
        this.h0h = 0xCBBB9D5D;
        this.h0l = 0xC1059ED8;
        this.h1h = 0x629A292A;
        this.h1l = 0x367CD507;
        this.h2h = 0x9159015A;
        this.h2l = 0x3070DD17;
        this.h3h = 0x152FECD8;
        this.h3l = 0xF70E5939;
        this.h4h = 0x67332667;
        this.h4l = 0xFFC00B31;
        this.h5h = 0x8EB44A87;
        this.h5l = 0x68581511;
        this.h6h = 0xDB0C2E0D;
        this.h6l = 0x64F98FA7;
        this.h7h = 0x47B5481D;
        this.h7l = 0xBEFA4FA4;
      } else if (bits == 256) {
        this.h0h = 0x22312194;
        this.h0l = 0xFC2BF72C;
        this.h1h = 0x9F555FA3;
        this.h1l = 0xC84C64C2;
        this.h2h = 0x2393B86B;
        this.h2l = 0x6F53B151;
        this.h3h = 0x96387719;
        this.h3l = 0x5940EABD;
        this.h4h = 0x96283EE2;
        this.h4l = 0xA88EFFE3;
        this.h5h = 0xBE5E1E25;
        this.h5l = 0x53863992;
        this.h6h = 0x2B0199FC;
        this.h6l = 0x2C85B8AA;
        this.h7h = 0x0EB72DDC;
        this.h7l = 0x81C52CA2;
      } else if (bits == 224) {
        this.h0h = 0x8C3D37C8;
        this.h0l = 0x19544DA2;
        this.h1h = 0x73E19966;
        this.h1l = 0x89DCD4D6;
        this.h2h = 0x1DFAB7AE;
        this.h2l = 0x32FF9C82;
        this.h3h = 0x679DD514;
        this.h3l = 0x582F9FCF;
        this.h4h = 0x0F6D2B69;
        this.h4l = 0x7BD44DA8;
        this.h5h = 0x77E36F73;
        this.h5l = 0x04C48942;
        this.h6h = 0x3F9D85A8;
        this.h6l = 0x6A1D36C8;
        this.h7h = 0x1112E6AD;
        this.h7l = 0x91D692A1;
      } else { // 512
        this.h0h = 0x6A09E667;
        this.h0l = 0xF3BCC908;
        this.h1h = 0xBB67AE85;
        this.h1l = 0x84CAA73B;
        this.h2h = 0x3C6EF372;
        this.h2l = 0xFE94F82B;
        this.h3h = 0xA54FF53A;
        this.h3l = 0x5F1D36F1;
        this.h4h = 0x510E527F;
        this.h4l = 0xADE682D1;
        this.h5h = 0x9B05688C;
        this.h5l = 0x2B3E6C1F;
        this.h6h = 0x1F83D9AB;
        this.h6l = 0xFB41BD6B;
        this.h7h = 0x5BE0CD19;
        this.h7l = 0x137E2179;
      }
      this.bits = bits;

      this.block = this.start = this.bytes = this.hBytes = 0;
      this.finalized = this.hashed = false;
    }

    Sha512.prototype.update = function (message) {
      if (this.finalized) {
        throw new Error(FINALIZE_ERROR);
      }
      var result = formatMessage(message);
      message = result[0];
      var isString = result[1];
      var code, index = 0, i, length = message.length, blocks = this.blocks;

      while (index < length) {
        if (this.hashed) {
          this.hashed = false;
          blocks[0] = this.block;
          this.block = blocks[1] = blocks[2] = blocks[3] = blocks[4] =
            blocks[5] = blocks[6] = blocks[7] = blocks[8] =
            blocks[9] = blocks[10] = blocks[11] = blocks[12] =
            blocks[13] = blocks[14] = blocks[15] = blocks[16] =
            blocks[17] = blocks[18] = blocks[19] = blocks[20] =
            blocks[21] = blocks[22] = blocks[23] = blocks[24] =
            blocks[25] = blocks[26] = blocks[27] = blocks[28] =
            blocks[29] = blocks[30] = blocks[31] = blocks[32] = 0;
        }

        if (isString) {
          for (i = this.start; index < length && i < 128; ++index) {
            code = message.charCodeAt(index);
            if (code < 0x80) {
              blocks[i >>> 2] |= code << SHIFT[i++ & 3];
            } else if (code < 0x800) {
              blocks[i >>> 2] |= (0xc0 | (code >>> 6)) << SHIFT[i++ & 3];
              blocks[i >>> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
            } else if (code < 0xd800 || code >= 0xe000) {
              blocks[i >>> 2] |= (0xe0 | (code >>> 12)) << SHIFT[i++ & 3];
              blocks[i >>> 2] |= (0x80 | ((code >>> 6) & 0x3f)) << SHIFT[i++ & 3];
              blocks[i >>> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
            } else {
              code = 0x10000 + (((code & 0x3ff) << 10) | (message.charCodeAt(++index) & 0x3ff));
              blocks[i >>> 2] |= (0xf0 | (code >>> 18)) << SHIFT[i++ & 3];
              blocks[i >>> 2] |= (0x80 | ((code >>> 12) & 0x3f)) << SHIFT[i++ & 3];
              blocks[i >>> 2] |= (0x80 | ((code >>> 6) & 0x3f)) << SHIFT[i++ & 3];
              blocks[i >>> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
            }
          }
        } else {
          for (i = this.start; index < length && i < 128; ++index) {
            blocks[i >>> 2] |= message[index] << SHIFT[i++ & 3];
          }
        }

        this.lastByteIndex = i;
        this.bytes += i - this.start;
        if (i >= 128) {
          this.block = blocks[32];
          this.start = i - 128;
          this.hash();
          this.hashed = true;
        } else {
          this.start = i;
        }
      }
      if (this.bytes > 4294967295) {
        this.hBytes += this.bytes / 4294967296 << 0;
        this.bytes = this.bytes % 4294967296;
      }
      return this;
    };

    Sha512.prototype.finalize = function () {
      if (this.finalized) {
        return;
      }
      this.finalized = true;
      var blocks = this.blocks, i = this.lastByteIndex;
      blocks[32] = this.block;
      blocks[i >>> 2] |= EXTRA[i & 3];
      this.block = blocks[32];
      if (i >= 112) {
        if (!this.hashed) {
          this.hash();
        }
        blocks[0] = this.block;
        blocks[1] = blocks[2] = blocks[3] = blocks[4] =
          blocks[5] = blocks[6] = blocks[7] = blocks[8] =
          blocks[9] = blocks[10] = blocks[11] = blocks[12] =
          blocks[13] = blocks[14] = blocks[15] = blocks[16] =
          blocks[17] = blocks[18] = blocks[19] = blocks[20] =
          blocks[21] = blocks[22] = blocks[23] = blocks[24] =
          blocks[25] = blocks[26] = blocks[27] = blocks[28] =
          blocks[29] = blocks[30] = blocks[31] = blocks[32] = 0;
      }
      blocks[30] = this.hBytes << 3 | this.bytes >>> 29;
      blocks[31] = this.bytes << 3;
      this.hash();
    };

    Sha512.prototype.hash = function () {
      var h0h = this.h0h, h0l = this.h0l, h1h = this.h1h, h1l = this.h1l,
        h2h = this.h2h, h2l = this.h2l, h3h = this.h3h, h3l = this.h3l,
        h4h = this.h4h, h4l = this.h4l, h5h = this.h5h, h5l = this.h5l,
        h6h = this.h6h, h6l = this.h6l, h7h = this.h7h, h7l = this.h7l,
        blocks = this.blocks, j, s0h, s0l, s1h, s1l, c1, c2, c3, c4,
        abh, abl, dah, dal, cdh, cdl, bch, bcl,
        majh, majl, t1h, t1l, t2h, t2l, chh, chl;

      for (j = 32; j < 160; j += 2) {
        t1h = blocks[j - 30];
        t1l = blocks[j - 29];
        s0h = ((t1h >>> 1) | (t1l << 31)) ^ ((t1h >>> 8) | (t1l << 24)) ^ (t1h >>> 7);
        s0l = ((t1l >>> 1) | (t1h << 31)) ^ ((t1l >>> 8) | (t1h << 24)) ^ ((t1l >>> 7) | t1h << 25);

        t1h = blocks[j - 4];
        t1l = blocks[j - 3];
        s1h = ((t1h >>> 19) | (t1l << 13)) ^ ((t1l >>> 29) | (t1h << 3)) ^ (t1h >>> 6);
        s1l = ((t1l >>> 19) | (t1h << 13)) ^ ((t1h >>> 29) | (t1l << 3)) ^ ((t1l >>> 6) | t1h << 26);

        t1h = blocks[j - 32];
        t1l = blocks[j - 31];
        t2h = blocks[j - 14];
        t2l = blocks[j - 13];

        c1 = (t2l & 0xFFFF) + (t1l & 0xFFFF) + (s0l & 0xFFFF) + (s1l & 0xFFFF);
        c2 = (t2l >>> 16) + (t1l >>> 16) + (s0l >>> 16) + (s1l >>> 16) + (c1 >>> 16);
        c3 = (t2h & 0xFFFF) + (t1h & 0xFFFF) + (s0h & 0xFFFF) + (s1h & 0xFFFF) + (c2 >>> 16);
        c4 = (t2h >>> 16) + (t1h >>> 16) + (s0h >>> 16) + (s1h >>> 16) + (c3 >>> 16);

        blocks[j] = (c4 << 16) | (c3 & 0xFFFF);
        blocks[j + 1] = (c2 << 16) | (c1 & 0xFFFF);
      }

      var ah = h0h, al = h0l, bh = h1h, bl = h1l, ch = h2h, cl = h2l, dh = h3h, dl = h3l, eh = h4h, el = h4l, fh = h5h, fl = h5l, gh = h6h, gl = h6l, hh = h7h, hl = h7l;
      bch = bh & ch;
      bcl = bl & cl;
      for (j = 0; j < 160; j += 8) {
        s0h = ((ah >>> 28) | (al << 4)) ^ ((al >>> 2) | (ah << 30)) ^ ((al >>> 7) | (ah << 25));
        s0l = ((al >>> 28) | (ah << 4)) ^ ((ah >>> 2) | (al << 30)) ^ ((ah >>> 7) | (al << 25));

        s1h = ((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((el >>> 9) | (eh << 23));
        s1l = ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((eh >>> 9) | (el << 23));

        abh = ah & bh;
        abl = al & bl;
        majh = abh ^ (ah & ch) ^ bch;
        majl = abl ^ (al & cl) ^ bcl;

        chh = (eh & fh) ^ (~eh & gh);
        chl = (el & fl) ^ (~el & gl);

        t1h = blocks[j];
        t1l = blocks[j + 1];
        t2h = K[j];
        t2l = K[j + 1];

        c1 = (t2l & 0xFFFF) + (t1l & 0xFFFF) + (chl & 0xFFFF) + (s1l & 0xFFFF) + (hl & 0xFFFF);
        c2 = (t2l >>> 16) + (t1l >>> 16) + (chl >>> 16) + (s1l >>> 16) + (hl >>> 16) + (c1 >>> 16);
        c3 = (t2h & 0xFFFF) + (t1h & 0xFFFF) + (chh & 0xFFFF) + (s1h & 0xFFFF) + (hh & 0xFFFF) + (c2 >>> 16);
        c4 = (t2h >>> 16) + (t1h >>> 16) + (chh >>> 16) + (s1h >>> 16) + (hh >>> 16) + (c3 >>> 16);

        t1h = (c4 << 16) | (c3 & 0xFFFF);
        t1l = (c2 << 16) | (c1 & 0xFFFF);

        c1 = (majl & 0xFFFF) + (s0l & 0xFFFF);
        c2 = (majl >>> 16) + (s0l >>> 16) + (c1 >>> 16);
        c3 = (majh & 0xFFFF) + (s0h & 0xFFFF) + (c2 >>> 16);
        c4 = (majh >>> 16) + (s0h >>> 16) + (c3 >>> 16);

        t2h = (c4 << 16) | (c3 & 0xFFFF);
        t2l = (c2 << 16) | (c1 & 0xFFFF);

        c1 = (dl & 0xFFFF) + (t1l & 0xFFFF);
        c2 = (dl >>> 16) + (t1l >>> 16) + (c1 >>> 16);
        c3 = (dh & 0xFFFF) + (t1h & 0xFFFF) + (c2 >>> 16);
        c4 = (dh >>> 16) + (t1h >>> 16) + (c3 >>> 16);

        hh = (c4 << 16) | (c3 & 0xFFFF);
        hl = (c2 << 16) | (c1 & 0xFFFF);

        c1 = (t2l & 0xFFFF) + (t1l & 0xFFFF);
        c2 = (t2l >>> 16) + (t1l >>> 16) + (c1 >>> 16);
        c3 = (t2h & 0xFFFF) + (t1h & 0xFFFF) + (c2 >>> 16);
        c4 = (t2h >>> 16) + (t1h >>> 16) + (c3 >>> 16);

        dh = (c4 << 16) | (c3 & 0xFFFF);
        dl = (c2 << 16) | (c1 & 0xFFFF);

        s0h = ((dh >>> 28) | (dl << 4)) ^ ((dl >>> 2) | (dh << 30)) ^ ((dl >>> 7) | (dh << 25));
        s0l = ((dl >>> 28) | (dh << 4)) ^ ((dh >>> 2) | (dl << 30)) ^ ((dh >>> 7) | (dl << 25));

        s1h = ((hh >>> 14) | (hl << 18)) ^ ((hh >>> 18) | (hl << 14)) ^ ((hl >>> 9) | (hh << 23));
        s1l = ((hl >>> 14) | (hh << 18)) ^ ((hl >>> 18) | (hh << 14)) ^ ((hh >>> 9) | (hl << 23));

        dah = dh & ah;
        dal = dl & al;
        majh = dah ^ (dh & bh) ^ abh;
        majl = dal ^ (dl & bl) ^ abl;

        chh = (hh & eh) ^ (~hh & fh);
        chl = (hl & el) ^ (~hl & fl);

        t1h = blocks[j + 2];
        t1l = blocks[j + 3];
        t2h = K[j + 2];
        t2l = K[j + 3];

        c1 = (t2l & 0xFFFF) + (t1l & 0xFFFF) + (chl & 0xFFFF) + (s1l & 0xFFFF) + (gl & 0xFFFF);
        c2 = (t2l >>> 16) + (t1l >>> 16) + (chl >>> 16) + (s1l >>> 16) + (gl >>> 16) + (c1 >>> 16);
        c3 = (t2h & 0xFFFF) + (t1h & 0xFFFF) + (chh & 0xFFFF) + (s1h & 0xFFFF) + (gh & 0xFFFF) + (c2 >>> 16);
        c4 = (t2h >>> 16) + (t1h >>> 16) + (chh >>> 16) + (s1h >>> 16) + (gh >>> 16) + (c3 >>> 16);

        t1h = (c4 << 16) | (c3 & 0xFFFF);
        t1l = (c2 << 16) | (c1 & 0xFFFF);

        c1 = (majl & 0xFFFF) + (s0l & 0xFFFF);
        c2 = (majl >>> 16) + (s0l >>> 16) + (c1 >>> 16);
        c3 = (majh & 0xFFFF) + (s0h & 0xFFFF) + (c2 >>> 16);
        c4 = (majh >>> 16) + (s0h >>> 16) + (c3 >>> 16);

        t2h = (c4 << 16) | (c3 & 0xFFFF);
        t2l = (c2 << 16) | (c1 & 0xFFFF);

        c1 = (cl & 0xFFFF) + (t1l & 0xFFFF);
        c2 = (cl >>> 16) + (t1l >>> 16) + (c1 >>> 16);
        c3 = (ch & 0xFFFF) + (t1h & 0xFFFF) + (c2 >>> 16);
        c4 = (ch >>> 16) + (t1h >>> 16) + (c3 >>> 16);

        gh = (c4 << 16) | (c3 & 0xFFFF);
        gl = (c2 << 16) | (c1 & 0xFFFF);

        c1 = (t2l & 0xFFFF) + (t1l & 0xFFFF);
        c2 = (t2l >>> 16) + (t1l >>> 16) + (c1 >>> 16);
        c3 = (t2h & 0xFFFF) + (t1h & 0xFFFF) + (c2 >>> 16);
        c4 = (t2h >>> 16) + (t1h >>> 16) + (c3 >>> 16);

        ch = (c4 << 16) | (c3 & 0xFFFF);
        cl = (c2 << 16) | (c1 & 0xFFFF);

        s0h = ((ch >>> 28) | (cl << 4)) ^ ((cl >>> 2) | (ch << 30)) ^ ((cl >>> 7) | (ch << 25));
        s0l = ((cl >>> 28) | (ch << 4)) ^ ((ch >>> 2) | (cl << 30)) ^ ((ch >>> 7) | (cl << 25));

        s1h = ((gh >>> 14) | (gl << 18)) ^ ((gh >>> 18) | (gl << 14)) ^ ((gl >>> 9) | (gh << 23));
        s1l = ((gl >>> 14) | (gh << 18)) ^ ((gl >>> 18) | (gh << 14)) ^ ((gh >>> 9) | (gl << 23));

        cdh = ch & dh;
        cdl = cl & dl;
        majh = cdh ^ (ch & ah) ^ dah;
        majl = cdl ^ (cl & al) ^ dal;

        chh = (gh & hh) ^ (~gh & eh);
        chl = (gl & hl) ^ (~gl & el);

        t1h = blocks[j + 4];
        t1l = blocks[j + 5];
        t2h = K[j + 4];
        t2l = K[j + 5];

        c1 = (t2l & 0xFFFF) + (t1l & 0xFFFF) + (chl & 0xFFFF) + (s1l & 0xFFFF) + (fl & 0xFFFF);
        c2 = (t2l >>> 16) + (t1l >>> 16) + (chl >>> 16) + (s1l >>> 16) + (fl >>> 16) + (c1 >>> 16);
        c3 = (t2h & 0xFFFF) + (t1h & 0xFFFF) + (chh & 0xFFFF) + (s1h & 0xFFFF) + (fh & 0xFFFF) + (c2 >>> 16);
        c4 = (t2h >>> 16) + (t1h >>> 16) + (chh >>> 16) + (s1h >>> 16) + (fh >>> 16) + (c3 >>> 16);

        t1h = (c4 << 16) | (c3 & 0xFFFF);
        t1l = (c2 << 16) | (c1 & 0xFFFF);

        c1 = (majl & 0xFFFF) + (s0l & 0xFFFF);
        c2 = (majl >>> 16) + (s0l >>> 16) + (c1 >>> 16);
        c3 = (majh & 0xFFFF) + (s0h & 0xFFFF) + (c2 >>> 16);
        c4 = (majh >>> 16) + (s0h >>> 16) + (c3 >>> 16);

        t2h = (c4 << 16) | (c3 & 0xFFFF);
        t2l = (c2 << 16) | (c1 & 0xFFFF);

        c1 = (bl & 0xFFFF) + (t1l & 0xFFFF);
        c2 = (bl >>> 16) + (t1l >>> 16) + (c1 >>> 16);
        c3 = (bh & 0xFFFF) + (t1h & 0xFFFF) + (c2 >>> 16);
        c4 = (bh >>> 16) + (t1h >>> 16) + (c3 >>> 16);

        fh = (c4 << 16) | (c3 & 0xFFFF);
        fl = (c2 << 16) | (c1 & 0xFFFF);

        c1 = (t2l & 0xFFFF) + (t1l & 0xFFFF);
        c2 = (t2l >>> 16) + (t1l >>> 16) + (c1 >>> 16);
        c3 = (t2h & 0xFFFF) + (t1h & 0xFFFF) + (c2 >>> 16);
        c4 = (t2h >>> 16) + (t1h >>> 16) + (c3 >>> 16);

        bh = (c4 << 16) | (c3 & 0xFFFF);
        bl = (c2 << 16) | (c1 & 0xFFFF);

        s0h = ((bh >>> 28) | (bl << 4)) ^ ((bl >>> 2) | (bh << 30)) ^ ((bl >>> 7) | (bh << 25));
        s0l = ((bl >>> 28) | (bh << 4)) ^ ((bh >>> 2) | (bl << 30)) ^ ((bh >>> 7) | (bl << 25));

        s1h = ((fh >>> 14) | (fl << 18)) ^ ((fh >>> 18) | (fl << 14)) ^ ((fl >>> 9) | (fh << 23));
        s1l = ((fl >>> 14) | (fh << 18)) ^ ((fl >>> 18) | (fh << 14)) ^ ((fh >>> 9) | (fl << 23));

        bch = bh & ch;
        bcl = bl & cl;
        majh = bch ^ (bh & dh) ^ cdh;
        majl = bcl ^ (bl & dl) ^ cdl;

        chh = (fh & gh) ^ (~fh & hh);
        chl = (fl & gl) ^ (~fl & hl);

        t1h = blocks[j + 6];
        t1l = blocks[j + 7];
        t2h = K[j + 6];
        t2l = K[j + 7];

        c1 = (t2l & 0xFFFF) + (t1l & 0xFFFF) + (chl & 0xFFFF) + (s1l & 0xFFFF) + (el & 0xFFFF);
        c2 = (t2l >>> 16) + (t1l >>> 16) + (chl >>> 16) + (s1l >>> 16) + (el >>> 16) + (c1 >>> 16);
        c3 = (t2h & 0xFFFF) + (t1h & 0xFFFF) + (chh & 0xFFFF) + (s1h & 0xFFFF) + (eh & 0xFFFF) + (c2 >>> 16);
        c4 = (t2h >>> 16) + (t1h >>> 16) + (chh >>> 16) + (s1h >>> 16) + (eh >>> 16) + (c3 >>> 16);

        t1h = (c4 << 16) | (c3 & 0xFFFF);
        t1l = (c2 << 16) | (c1 & 0xFFFF);

        c1 = (majl & 0xFFFF) + (s0l & 0xFFFF);
        c2 = (majl >>> 16) + (s0l >>> 16) + (c1 >>> 16);
        c3 = (majh & 0xFFFF) + (s0h & 0xFFFF) + (c2 >>> 16);
        c4 = (majh >>> 16) + (s0h >>> 16) + (c3 >>> 16);

        t2h = (c4 << 16) | (c3 & 0xFFFF);
        t2l = (c2 << 16) | (c1 & 0xFFFF);

        c1 = (al & 0xFFFF) + (t1l & 0xFFFF);
        c2 = (al >>> 16) + (t1l >>> 16) + (c1 >>> 16);
        c3 = (ah & 0xFFFF) + (t1h & 0xFFFF) + (c2 >>> 16);
        c4 = (ah >>> 16) + (t1h >>> 16) + (c3 >>> 16);

        eh = (c4 << 16) | (c3 & 0xFFFF);
        el = (c2 << 16) | (c1 & 0xFFFF);

        c1 = (t2l & 0xFFFF) + (t1l & 0xFFFF);
        c2 = (t2l >>> 16) + (t1l >>> 16) + (c1 >>> 16);
        c3 = (t2h & 0xFFFF) + (t1h & 0xFFFF) + (c2 >>> 16);
        c4 = (t2h >>> 16) + (t1h >>> 16) + (c3 >>> 16);

        ah = (c4 << 16) | (c3 & 0xFFFF);
        al = (c2 << 16) | (c1 & 0xFFFF);
      }

      c1 = (h0l & 0xFFFF) + (al & 0xFFFF);
      c2 = (h0l >>> 16) + (al >>> 16) + (c1 >>> 16);
      c3 = (h0h & 0xFFFF) + (ah & 0xFFFF) + (c2 >>> 16);
      c4 = (h0h >>> 16) + (ah >>> 16) + (c3 >>> 16);

      this.h0h = (c4 << 16) | (c3 & 0xFFFF);
      this.h0l = (c2 << 16) | (c1 & 0xFFFF);

      c1 = (h1l & 0xFFFF) + (bl & 0xFFFF);
      c2 = (h1l >>> 16) + (bl >>> 16) + (c1 >>> 16);
      c3 = (h1h & 0xFFFF) + (bh & 0xFFFF) + (c2 >>> 16);
      c4 = (h1h >>> 16) + (bh >>> 16) + (c3 >>> 16);

      this.h1h = (c4 << 16) | (c3 & 0xFFFF);
      this.h1l = (c2 << 16) | (c1 & 0xFFFF);

      c1 = (h2l & 0xFFFF) + (cl & 0xFFFF);
      c2 = (h2l >>> 16) + (cl >>> 16) + (c1 >>> 16);
      c3 = (h2h & 0xFFFF) + (ch & 0xFFFF) + (c2 >>> 16);
      c4 = (h2h >>> 16) + (ch >>> 16) + (c3 >>> 16);

      this.h2h = (c4 << 16) | (c3 & 0xFFFF);
      this.h2l = (c2 << 16) | (c1 & 0xFFFF);

      c1 = (h3l & 0xFFFF) + (dl & 0xFFFF);
      c2 = (h3l >>> 16) + (dl >>> 16) + (c1 >>> 16);
      c3 = (h3h & 0xFFFF) + (dh & 0xFFFF) + (c2 >>> 16);
      c4 = (h3h >>> 16) + (dh >>> 16) + (c3 >>> 16);

      this.h3h = (c4 << 16) | (c3 & 0xFFFF);
      this.h3l = (c2 << 16) | (c1 & 0xFFFF);

      c1 = (h4l & 0xFFFF) + (el & 0xFFFF);
      c2 = (h4l >>> 16) + (el >>> 16) + (c1 >>> 16);
      c3 = (h4h & 0xFFFF) + (eh & 0xFFFF) + (c2 >>> 16);
      c4 = (h4h >>> 16) + (eh >>> 16) + (c3 >>> 16);

      this.h4h = (c4 << 16) | (c3 & 0xFFFF);
      this.h4l = (c2 << 16) | (c1 & 0xFFFF);

      c1 = (h5l & 0xFFFF) + (fl & 0xFFFF);
      c2 = (h5l >>> 16) + (fl >>> 16) + (c1 >>> 16);
      c3 = (h5h & 0xFFFF) + (fh & 0xFFFF) + (c2 >>> 16);
      c4 = (h5h >>> 16) + (fh >>> 16) + (c3 >>> 16);

      this.h5h = (c4 << 16) | (c3 & 0xFFFF);
      this.h5l = (c2 << 16) | (c1 & 0xFFFF);

      c1 = (h6l & 0xFFFF) + (gl & 0xFFFF);
      c2 = (h6l >>> 16) + (gl >>> 16) + (c1 >>> 16);
      c3 = (h6h & 0xFFFF) + (gh & 0xFFFF) + (c2 >>> 16);
      c4 = (h6h >>> 16) + (gh >>> 16) + (c3 >>> 16);

      this.h6h = (c4 << 16) | (c3 & 0xFFFF);
      this.h6l = (c2 << 16) | (c1 & 0xFFFF);

      c1 = (h7l & 0xFFFF) + (hl & 0xFFFF);
      c2 = (h7l >>> 16) + (hl >>> 16) + (c1 >>> 16);
      c3 = (h7h & 0xFFFF) + (hh & 0xFFFF) + (c2 >>> 16);
      c4 = (h7h >>> 16) + (hh >>> 16) + (c3 >>> 16);

      this.h7h = (c4 << 16) | (c3 & 0xFFFF);
      this.h7l = (c2 << 16) | (c1 & 0xFFFF);
    };

    Sha512.prototype.hex = function () {
      this.finalize();

      var h0h = this.h0h, h0l = this.h0l, h1h = this.h1h, h1l = this.h1l,
        h2h = this.h2h, h2l = this.h2l, h3h = this.h3h, h3l = this.h3l,
        h4h = this.h4h, h4l = this.h4l, h5h = this.h5h, h5l = this.h5l,
        h6h = this.h6h, h6l = this.h6l, h7h = this.h7h, h7l = this.h7l,
        bits = this.bits;

      var hex = HEX_CHARS[(h0h >>> 28) & 0x0F] + HEX_CHARS[(h0h >>> 24) & 0x0F] +
        HEX_CHARS[(h0h >>> 20) & 0x0F] + HEX_CHARS[(h0h >>> 16) & 0x0F] +
        HEX_CHARS[(h0h >>> 12) & 0x0F] + HEX_CHARS[(h0h >>> 8) & 0x0F] +
        HEX_CHARS[(h0h >>> 4) & 0x0F] + HEX_CHARS[h0h & 0x0F] +
        HEX_CHARS[(h0l >>> 28) & 0x0F] + HEX_CHARS[(h0l >>> 24) & 0x0F] +
        HEX_CHARS[(h0l >>> 20) & 0x0F] + HEX_CHARS[(h0l >>> 16) & 0x0F] +
        HEX_CHARS[(h0l >>> 12) & 0x0F] + HEX_CHARS[(h0l >>> 8) & 0x0F] +
        HEX_CHARS[(h0l >>> 4) & 0x0F] + HEX_CHARS[h0l & 0x0F] +
        HEX_CHARS[(h1h >>> 28) & 0x0F] + HEX_CHARS[(h1h >>> 24) & 0x0F] +
        HEX_CHARS[(h1h >>> 20) & 0x0F] + HEX_CHARS[(h1h >>> 16) & 0x0F] +
        HEX_CHARS[(h1h >>> 12) & 0x0F] + HEX_CHARS[(h1h >>> 8) & 0x0F] +
        HEX_CHARS[(h1h >>> 4) & 0x0F] + HEX_CHARS[h1h & 0x0F] +
        HEX_CHARS[(h1l >>> 28) & 0x0F] + HEX_CHARS[(h1l >>> 24) & 0x0F] +
        HEX_CHARS[(h1l >>> 20) & 0x0F] + HEX_CHARS[(h1l >>> 16) & 0x0F] +
        HEX_CHARS[(h1l >>> 12) & 0x0F] + HEX_CHARS[(h1l >>> 8) & 0x0F] +
        HEX_CHARS[(h1l >>> 4) & 0x0F] + HEX_CHARS[h1l & 0x0F] +
        HEX_CHARS[(h2h >>> 28) & 0x0F] + HEX_CHARS[(h2h >>> 24) & 0x0F] +
        HEX_CHARS[(h2h >>> 20) & 0x0F] + HEX_CHARS[(h2h >>> 16) & 0x0F] +
        HEX_CHARS[(h2h >>> 12) & 0x0F] + HEX_CHARS[(h2h >>> 8) & 0x0F] +
        HEX_CHARS[(h2h >>> 4) & 0x0F] + HEX_CHARS[h2h & 0x0F] +
        HEX_CHARS[(h2l >>> 28) & 0x0F] + HEX_CHARS[(h2l >>> 24) & 0x0F] +
        HEX_CHARS[(h2l >>> 20) & 0x0F] + HEX_CHARS[(h2l >>> 16) & 0x0F] +
        HEX_CHARS[(h2l >>> 12) & 0x0F] + HEX_CHARS[(h2l >>> 8) & 0x0F] +
        HEX_CHARS[(h2l >>> 4) & 0x0F] + HEX_CHARS[h2l & 0x0F] +
        HEX_CHARS[(h3h >>> 28) & 0x0F] + HEX_CHARS[(h3h >>> 24) & 0x0F] +
        HEX_CHARS[(h3h >>> 20) & 0x0F] + HEX_CHARS[(h3h >>> 16) & 0x0F] +
        HEX_CHARS[(h3h >>> 12) & 0x0F] + HEX_CHARS[(h3h >>> 8) & 0x0F] +
        HEX_CHARS[(h3h >>> 4) & 0x0F] + HEX_CHARS[h3h & 0x0F];
      if (bits >= 256) {
        hex += HEX_CHARS[(h3l >>> 28) & 0x0F] + HEX_CHARS[(h3l >>> 24) & 0x0F] +
          HEX_CHARS[(h3l >>> 20) & 0x0F] + HEX_CHARS[(h3l >>> 16) & 0x0F] +
          HEX_CHARS[(h3l >>> 12) & 0x0F] + HEX_CHARS[(h3l >>> 8) & 0x0F] +
          HEX_CHARS[(h3l >>> 4) & 0x0F] + HEX_CHARS[h3l & 0x0F];
      }
      if (bits >= 384) {
        hex += HEX_CHARS[(h4h >>> 28) & 0x0F] + HEX_CHARS[(h4h >>> 24) & 0x0F] +
          HEX_CHARS[(h4h >>> 20) & 0x0F] + HEX_CHARS[(h4h >>> 16) & 0x0F] +
          HEX_CHARS[(h4h >>> 12) & 0x0F] + HEX_CHARS[(h4h >>> 8) & 0x0F] +
          HEX_CHARS[(h4h >>> 4) & 0x0F] + HEX_CHARS[h4h & 0x0F] +
          HEX_CHARS[(h4l >>> 28) & 0x0F] + HEX_CHARS[(h4l >>> 24) & 0x0F] +
          HEX_CHARS[(h4l >>> 20) & 0x0F] + HEX_CHARS[(h4l >>> 16) & 0x0F] +
          HEX_CHARS[(h4l >>> 12) & 0x0F] + HEX_CHARS[(h4l >>> 8) & 0x0F] +
          HEX_CHARS[(h4l >>> 4) & 0x0F] + HEX_CHARS[h4l & 0x0F] +
          HEX_CHARS[(h5h >>> 28) & 0x0F] + HEX_CHARS[(h5h >>> 24) & 0x0F] +
          HEX_CHARS[(h5h >>> 20) & 0x0F] + HEX_CHARS[(h5h >>> 16) & 0x0F] +
          HEX_CHARS[(h5h >>> 12) & 0x0F] + HEX_CHARS[(h5h >>> 8) & 0x0F] +
          HEX_CHARS[(h5h >>> 4) & 0x0F] + HEX_CHARS[h5h & 0x0F] +
          HEX_CHARS[(h5l >>> 28) & 0x0F] + HEX_CHARS[(h5l >>> 24) & 0x0F] +
          HEX_CHARS[(h5l >>> 20) & 0x0F] + HEX_CHARS[(h5l >>> 16) & 0x0F] +
          HEX_CHARS[(h5l >>> 12) & 0x0F] + HEX_CHARS[(h5l >>> 8) & 0x0F] +
          HEX_CHARS[(h5l >>> 4) & 0x0F] + HEX_CHARS[h5l & 0x0F];
      }
      if (bits == 512) {
        hex += HEX_CHARS[(h6h >>> 28) & 0x0F] + HEX_CHARS[(h6h >>> 24) & 0x0F] +
          HEX_CHARS[(h6h >>> 20) & 0x0F] + HEX_CHARS[(h6h >>> 16) & 0x0F] +
          HEX_CHARS[(h6h >>> 12) & 0x0F] + HEX_CHARS[(h6h >>> 8) & 0x0F] +
          HEX_CHARS[(h6h >>> 4) & 0x0F] + HEX_CHARS[h6h & 0x0F] +
          HEX_CHARS[(h6l >>> 28) & 0x0F] + HEX_CHARS[(h6l >>> 24) & 0x0F] +
          HEX_CHARS[(h6l >>> 20) & 0x0F] + HEX_CHARS[(h6l >>> 16) & 0x0F] +
          HEX_CHARS[(h6l >>> 12) & 0x0F] + HEX_CHARS[(h6l >>> 8) & 0x0F] +
          HEX_CHARS[(h6l >>> 4) & 0x0F] + HEX_CHARS[h6l & 0x0F] +
          HEX_CHARS[(h7h >>> 28) & 0x0F] + HEX_CHARS[(h7h >>> 24) & 0x0F] +
          HEX_CHARS[(h7h >>> 20) & 0x0F] + HEX_CHARS[(h7h >>> 16) & 0x0F] +
          HEX_CHARS[(h7h >>> 12) & 0x0F] + HEX_CHARS[(h7h >>> 8) & 0x0F] +
          HEX_CHARS[(h7h >>> 4) & 0x0F] + HEX_CHARS[h7h & 0x0F] +
          HEX_CHARS[(h7l >>> 28) & 0x0F] + HEX_CHARS[(h7l >>> 24) & 0x0F] +
          HEX_CHARS[(h7l >>> 20) & 0x0F] + HEX_CHARS[(h7l >>> 16) & 0x0F] +
          HEX_CHARS[(h7l >>> 12) & 0x0F] + HEX_CHARS[(h7l >>> 8) & 0x0F] +
          HEX_CHARS[(h7l >>> 4) & 0x0F] + HEX_CHARS[h7l & 0x0F];
      }
      return hex;
    };

    Sha512.prototype.toString = Sha512.prototype.hex;

    Sha512.prototype.digest = function () {
      this.finalize();

      var h0h = this.h0h, h0l = this.h0l, h1h = this.h1h, h1l = this.h1l,
        h2h = this.h2h, h2l = this.h2l, h3h = this.h3h, h3l = this.h3l,
        h4h = this.h4h, h4l = this.h4l, h5h = this.h5h, h5l = this.h5l,
        h6h = this.h6h, h6l = this.h6l, h7h = this.h7h, h7l = this.h7l,
        bits = this.bits;

      var arr = [
        (h0h >>> 24) & 0xFF, (h0h >>> 16) & 0xFF, (h0h >>> 8) & 0xFF, h0h & 0xFF,
        (h0l >>> 24) & 0xFF, (h0l >>> 16) & 0xFF, (h0l >>> 8) & 0xFF, h0l & 0xFF,
        (h1h >>> 24) & 0xFF, (h1h >>> 16) & 0xFF, (h1h >>> 8) & 0xFF, h1h & 0xFF,
        (h1l >>> 24) & 0xFF, (h1l >>> 16) & 0xFF, (h1l >>> 8) & 0xFF, h1l & 0xFF,
        (h2h >>> 24) & 0xFF, (h2h >>> 16) & 0xFF, (h2h >>> 8) & 0xFF, h2h & 0xFF,
        (h2l >>> 24) & 0xFF, (h2l >>> 16) & 0xFF, (h2l >>> 8) & 0xFF, h2l & 0xFF,
        (h3h >>> 24) & 0xFF, (h3h >>> 16) & 0xFF, (h3h >>> 8) & 0xFF, h3h & 0xFF
      ];

      if (bits >= 256) {
        arr.push((h3l >>> 24) & 0xFF, (h3l >>> 16) & 0xFF, (h3l >>> 8) & 0xFF, h3l & 0xFF);
      }
      if (bits >= 384) {
        arr.push(
          (h4h >>> 24) & 0xFF, (h4h >>> 16) & 0xFF, (h4h >>> 8) & 0xFF, h4h & 0xFF,
          (h4l >>> 24) & 0xFF, (h4l >>> 16) & 0xFF, (h4l >>> 8) & 0xFF, h4l & 0xFF,
          (h5h >>> 24) & 0xFF, (h5h >>> 16) & 0xFF, (h5h >>> 8) & 0xFF, h5h & 0xFF,
          (h5l >>> 24) & 0xFF, (h5l >>> 16) & 0xFF, (h5l >>> 8) & 0xFF, h5l & 0xFF
        );
      }
      if (bits == 512) {
        arr.push(
          (h6h >>> 24) & 0xFF, (h6h >>> 16) & 0xFF, (h6h >>> 8) & 0xFF, h6h & 0xFF,
          (h6l >>> 24) & 0xFF, (h6l >>> 16) & 0xFF, (h6l >>> 8) & 0xFF, h6l & 0xFF,
          (h7h >>> 24) & 0xFF, (h7h >>> 16) & 0xFF, (h7h >>> 8) & 0xFF, h7h & 0xFF,
          (h7l >>> 24) & 0xFF, (h7l >>> 16) & 0xFF, (h7l >>> 8) & 0xFF, h7l & 0xFF
        );
      }
      return arr;
    };

    Sha512.prototype.array = Sha512.prototype.digest;

    Sha512.prototype.arrayBuffer = function () {
      this.finalize();

      var bits = this.bits;
      var buffer = new ArrayBuffer(bits / 8);
      var dataView = new DataView(buffer);
      dataView.setUint32(0, this.h0h);
      dataView.setUint32(4, this.h0l);
      dataView.setUint32(8, this.h1h);
      dataView.setUint32(12, this.h1l);
      dataView.setUint32(16, this.h2h);
      dataView.setUint32(20, this.h2l);
      dataView.setUint32(24, this.h3h);

      if (bits >= 256) {
        dataView.setUint32(28, this.h3l);
      }
      if (bits >= 384) {
        dataView.setUint32(32, this.h4h);
        dataView.setUint32(36, this.h4l);
        dataView.setUint32(40, this.h5h);
        dataView.setUint32(44, this.h5l);
      }
      if (bits == 512) {
        dataView.setUint32(48, this.h6h);
        dataView.setUint32(52, this.h6l);
        dataView.setUint32(56, this.h7h);
        dataView.setUint32(60, this.h7l);
      }
      return buffer;
    };

    Sha512.prototype.clone = function () {
      var hash = new Sha512(this.bits, false);
      this.copyTo(hash);
      return hash;
    };

    Sha512.prototype.copyTo = function (hash) {
      var i = 0, attrs = [
        'h0h', 'h0l', 'h1h', 'h1l', 'h2h', 'h2l', 'h3h', 'h3l', 'h4h', 'h4l', 'h5h', 'h5l', 'h6h', 'h6l', 'h7h', 'h7l',
        'start', 'bytes', 'hBytes', 'finalized', 'hashed', 'lastByteIndex'
      ];
      for (i = 0; i < attrs.length; ++i) {
        hash[attrs[i]] = this[attrs[i]];
      }
      for (i = 0; i < this.blocks.length; ++i) {
        hash.blocks[i] = this.blocks[i];
      }
    };

    function HmacSha512(key, bits, sharedMemory) {
      var i, result = formatMessage(key);
      key = result[0];
      if (result[1]) {
        var bytes = [], length = key.length, index = 0, code;
        for (var i = 0; i < length; ++i) {
          code = key.charCodeAt(i);
          if (code < 0x80) {
            bytes[index++] = code;
          } else if (code < 0x800) {
            bytes[index++] = (0xc0 | (code >>> 6));
            bytes[index++] = (0x80 | (code & 0x3f));
          } else if (code < 0xd800 || code >= 0xe000) {
            bytes[index++] = (0xe0 | (code >>> 12));
            bytes[index++] = (0x80 | ((code >>> 6) & 0x3f));
            bytes[index++] = (0x80 | (code & 0x3f));
          } else {
            code = 0x10000 + (((code & 0x3ff) << 10) | (key.charCodeAt(++i) & 0x3ff));
            bytes[index++] = (0xf0 | (code >>> 18));
            bytes[index++] = (0x80 | ((code >>> 12) & 0x3f));
            bytes[index++] = (0x80 | ((code >>> 6) & 0x3f));
            bytes[index++] = (0x80 | (code & 0x3f));
          }
        }
        key = bytes;
      }

      if (key.length > 128) {
        key = (new Sha512(bits, true)).update(key).array();
      }

      var oKeyPad = [], iKeyPad = [];
      for (var i = 0; i < 128; ++i) {
        var b = key[i] || 0;
        oKeyPad[i] = 0x5c ^ b;
        iKeyPad[i] = 0x36 ^ b;
      }

      Sha512.call(this, bits, sharedMemory);

      this.update(iKeyPad);
      this.oKeyPad = oKeyPad;
      this.inner = true;
      this.sharedMemory = sharedMemory;
    }
    HmacSha512.prototype = new Sha512();

    HmacSha512.prototype.finalize = function () {
      Sha512.prototype.finalize.call(this);
      if (this.inner) {
        this.inner = false;
        var innerHash = this.array();
        Sha512.call(this, this.bits, this.sharedMemory);
        this.update(this.oKeyPad);
        this.update(innerHash);
        Sha512.prototype.finalize.call(this);
      }
    };

    HmacSha512.prototype.clone = function () {
      var hash = new HmacSha512([], this.bits, false);
      this.copyTo(hash);
      hash.inner = this.inner;
      for (var i = 0; i < this.oKeyPad.length; ++i) {
        hash.oKeyPad[i] = this.oKeyPad[i];
      }
      return hash;
    };

    var exports = createMethod(512);
    exports.sha512 = exports;
    exports.sha384 = createMethod(384);
    exports.sha512_256 = createMethod(256);
    exports.sha512_224 = createMethod(224);
    exports.sha512.hmac = createHmacMethod(512);
    exports.sha384.hmac = createHmacMethod(384);
    exports.sha512_256.hmac = createHmacMethod(256);
    exports.sha512_224.hmac = createHmacMethod(224);
    return exports;
  })();



  // ---------- Buffer 兼容层（仅当沙箱无全局 Buffer 时启用） ----------
  function makeBufferPolyfill() {
    const u8 = Uint8Array;
    class B extends u8 {
      static from(input, enc) {
        if (typeof input === 'string') {
          if (!enc || enc === 'utf8' || enc === 'utf-8') { // utf8
            const bytes = new B(textEncoder().encode(input).length);
            bytes.set(textEncoder().encode(input)); return bytes;
          }
          if (enc === 'hex') { const n = input.length >> 1, out = new B(n); for (let i = 0; i < n; i++) out[i] = parseInt(input.substr(i * 2, 2), 16); return out; }
          if (enc === 'base64') { return B.from(base64ToBytes(input)); }
          if (enc === 'ascii' || enc === 'latin1') { const out = new B(input.length); for (let i = 0; i < input.length; i++) out[i] = input.charCodeAt(i) & 0xff; return out; }
          throw new Error('enc ' + enc);
        }
        if (input instanceof u8 || Array.isArray(input)) return new B(input);
        throw new Error('from type');
      }
      static alloc(size, fill) { const b = new B(size); if (fill != null) b.fill(fill); return b; }
      static concat(list) {
        let total = 0; for (const b of list) total += b.length;
        const out = new B(total); let o = 0;
        for (const b of list) { out.set(b, o); o += b.length; }
        return out;
      }
      toString(enc, start, end) {
        enc = enc || 'utf8';
        const from = start == null ? 0 : Math.max(0, Number(start));
        const to = end == null ? this.length : Math.min(this.length, Number(end));
        const d = (from === 0 && to === this.length) ? this : this.subarray(from, to);
        if (enc === 'hex') { let s = ''; for (let i = 0; i < d.length; i++) s += (d[i] < 16 ? '0' : '') + d[i].toString(16); return s; }
        if (enc === 'base64') return bytesToBase64(d);
        if (enc === 'ascii' || enc === 'latin1') { let s = ''; for (let i = 0; i < d.length; i++) s += String.fromCharCode(d[i]); return s; }
        // utf8
        return textDecoder().decode(d);
      }
      write(str, offset, enc) { const b = B.from(str, enc || 'utf8'); this.set(b, offset || 0); return this.length; }
      fill(value, s, e) { for (let i = s || 0; i < (e == null ? this.length : e); i++) this[i] = value; return this; }
      indexOf(needle, from) {
        const nb = needle instanceof u8 ? needle : B.from(needle);
        outer: for (let i = from || 0; i <= this.length - nb.length; i++) {
          for (let j = 0; j < nb.length; j++) if (this[i + j] !== nb[j]) continue outer;
          return i;
        }
        return -1;
      }
      copy(target, tstart, s, e) { const ss = s || 0, se = e == null ? this.length : e; for (let i = ss; i < se; i++) target[tstart + i - ss] = this[i]; return se - ss; }
      readUInt32BE(o) { return ((this[o] << 24) | (this[o + 1] << 16) | (this[o + 2] << 8) | this[o + 3]) >>> 0; }
      readUInt32LE(o) { return ((this[o + 3] << 24) | (this[o + 2] << 16) | (this[o + 1] << 8) | this[o]) >>> 0; }
      writeUInt32BE(v, o) { this[o] = (v >>> 24) & 255; this[o + 1] = (v >>> 16) & 255; this[o + 2] = (v >>> 8) & 255; this[o + 3] = v & 255; return o + 4; }
      writeUInt32LE(v, o) { this[o] = v & 255; this[o + 1] = (v >>> 8) & 255; this[o + 2] = (v >>> 16) & 255; this[o + 3] = (v >>> 24) & 255; return o + 4; }
      readBigUInt64BE(o) { const hi = this.readUInt32BE(o), lo = this.readUInt32BE(o + 4); return (BigInt(hi) << 32n) | BigInt(lo); }
      readBigUInt64LE(o) { const lo = this.readUInt32LE(o), hi = this.readUInt32LE(o + 4); return (BigInt(hi) << 32n) | BigInt(lo); }
      subarray(a, b) { const u = u8.prototype.subarray.call(this, a, b); return new B(u); }
      slice(a, b) { return this.subarray(a, b); }
      reverse() { let i = 0, j = this.length - 1; while (i < j) { const t = this[i]; this[i] = this[j]; this[j] = t; i++; j--; } return this; }
      writeBigUInt64BE(v, o) { o = o || 0; this.writeUInt32BE(Number(v >> 32n) >>> 0, o); this.writeUInt32BE(Number(v & 0xffffffffn) >>> 0, o + 4); return o + 8; }
      writeBigUInt64LE(v, o) { o = o || 0; this.writeUInt32LE(Number(v & 0xffffffffn) >>> 0, o); this.writeUInt32LE(Number(v >> 32n) >>> 0, o + 4); return o + 8; }
      writeFloatLE(v, o) { o = o || 0; const f = new Float32Array(1); f[0] = v; const b = new Uint8Array(f.buffer); for (let i = 0; i < 4; i++) this[o + i] = b[i]; return o + 4; }
    }
    return B;
  }

  function utf8Encode(str) {
    const bytes = [];
    for (let i = 0; i < str.length; i++) {
      let c = str.charCodeAt(i);
      if (c < 0x80) bytes.push(c);
      else if (c < 0x800) { bytes.push(0xc0 | (c >> 6), 0x80 | (c & 63)); }
      else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
        const c2 = str.charCodeAt(++i);
        const cp = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
        bytes.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
      } else { bytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63)); }
    }
    return new Uint8Array(bytes);
  }
  function utf8Decode(u8) {
    let out = '';
    for (let i = 0; i < u8.length;) {
      const b = u8[i];
      if (b < 0x80) { out += String.fromCharCode(b); i++; }
      else if ((b & 0xe0) === 0xc0) { out += String.fromCharCode(((b & 31) << 6) | (u8[i + 1] & 63)); i += 2; }
      else if ((b & 0xf0) === 0xe0) { out += String.fromCharCode(((b & 15) << 12) | ((u8[i + 1] & 63) << 6) | (u8[i + 2] & 63)); i += 3; }
      else { const cp = ((b & 7) << 18) | ((u8[i + 1] & 63) << 12) | ((u8[i + 2] & 63) << 6) | (u8[i + 3] & 63); const cc = cp - 0x10000; out += String.fromCharCode(0xd800 + (cc >> 10), 0xdc00 + (cc & 1023)); i += 4; }
    }
    return out;
  }
  const B64C = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  function base64ToBytes(s) {
    const lookup = new Uint8Array(128); for (let i = 0; i < 64; i++) lookup[B64C.charCodeAt(i)] = i;
    const clean = s.replace(/=/g, '');
    const bytes = [];
    for (let i = 0; i < clean.length; i += 4) {
      const c0 = lookup[clean.charCodeAt(i)], c1 = lookup[clean.charCodeAt(i + 1)];
      const c2 = i + 2 < clean.length ? lookup[clean.charCodeAt(i + 2)] : 64, c3 = i + 3 < clean.length ? lookup[clean.charCodeAt(i + 3)] : 64;
      bytes.push((c0 << 2) | (c1 >> 4));
      if (c2 < 64) bytes.push(((c1 & 15) << 4) | (c2 >> 2));
      if (c3 < 64) bytes.push(((c2 & 3) << 6) | c3);
    }
    return new Uint8Array(bytes);
  }
  function bytesToBase64(bytes) {
    let out = '';
    for (let i = 0; i < bytes.length; i += 3) {
      const b0 = bytes[i], b1 = i + 1 < bytes.length ? bytes[i + 1] : 0, b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
      out += B64C[b0 >> 2] + B64C[((b0 & 3) << 4) | (b1 >> 4)];
      out += (i + 1 < bytes.length) ? B64C[((b1 & 15) << 2) | (b2 >> 6)] : '=';
      out += (i + 2 < bytes.length) ? B64C[b2 & 63] : '=';
    }
    return out;
  }
  function textEncoder() { return { encode: (s) => utf8Encode(s) }; }
  function textDecoder() { return { decode: (u) => utf8Decode(u) }; }

  // ---------- 通用工具 ----------
  function u32x(v) { return v >>> 0; }
  function rotr32(v, n) { n &= 31; return u32x((v >>> n) | (v << (32 - n))); }
  function rotl32(v, n) { n &= 31; return u32x((v << n) | (v >>> (32 - n))); }
  function rd32le(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }
  function rd32be(b, o) { return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0; }
  function wr32le(b, o, v) { b[o] = v & 255; b[o + 1] = (v >>> 8) & 255; b[o + 2] = (v >>> 16) & 255; b[o + 3] = (v >>> 24) & 255; }
  function wr32be(b, o, v) { b[o] = (v >>> 24) & 255; b[o + 1] = (v >>> 16) & 255; b[o + 2] = (v >>> 8) & 255; b[o + 3] = v & 255; }

  // ---------- MD5 ----------
  function md5Bytes(msg) {
    // returns 16-byte Uint8Array
    const len = msg.length;
    const bitLen = BigInt(len * 8);
    const padded = new Uint8Array(((len + 8) >> 6 << 6) + 64);
    padded.set(msg);
    padded[len] = 0x80;
    // append 64-bit LE length at end
    let p = padded.length - 8;
    for (let i = 0; i < 8; i++) padded[p + i] = Number((bitLen >> BigInt(8 * i)) & 0xffn);
    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    const s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
    const K = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391];
    for (let off = 0; off < padded.length; off += 64) {
      const M = [];
      for (let i = 0; i < 16; i++) M.push(rd32le(padded, off + i * 4));
      let A = a0, B = b0, C = c0, D = d0;
      for (let i = 0; i < 64; i++) {
        let F, g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
        else { F = C ^ (B | ~D); g = (7 * i) % 16; }
        F = u32x(F + A + K[i] + M[g]);
        A = D; D = C; C = B;
        B = u32x(B + rotl32(F, s[i]));
      }
      a0 = u32x(a0 + A); b0 = u32x(b0 + B); c0 = u32x(c0 + C); d0 = u32x(d0 + D);
    }
    const out = new Uint8Array(16);
    wr32le(out, 0, a0); wr32le(out, 4, b0); wr32le(out, 8, c0); wr32le(out, 12, d0);
    return out;
  }

  // ---------- SM3 ----------
  function sm3Bytes(msg) {
    const len = msg.length;
    const bitLen = len * 8;
    const k = (-(len + 1 + 8) % 64 + 64) % 64;
    const padded = new Uint8Array(len + 1 + k + 8);
    padded.set(msg); padded[len] = 0x80;
    // 64-bit BE length（避免 JS >>> 对移位计数取模 32 的坑，用显式高低 32 位）
    const bitHi = Math.floor(bitLen / 0x100000000), bitLo = bitLen % 0x100000000;
    padded[padded.length - 8] = (bitHi >>> 24) & 0xff;
    padded[padded.length - 7] = (bitHi >>> 16) & 0xff;
    padded[padded.length - 6] = (bitHi >>> 8) & 0xff;
    padded[padded.length - 5] = bitHi & 0xff;
    padded[padded.length - 4] = (bitLo >>> 24) & 0xff;
    padded[padded.length - 3] = (bitLo >>> 16) & 0xff;
    padded[padded.length - 2] = (bitLo >>> 8) & 0xff;
    padded[padded.length - 1] = bitLo & 0xff;
    const IV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e];
    const Tj = new Array(64).fill(0x79cc4519);
    for (let j = 16; j < 64; j++) Tj[j] = 0x7a879d8a;
    let V = IV.slice();
    const W = new Array(68), Wp = new Array(64);
    for (let off = 0; off < padded.length; off += 64) {
      const Bb = new Array(16);
      for (let i = 0; i < 16; i++) Bb[i] = rd32be(padded, off + i * 4);
      for (let j = 0; j < 16; j++) W[j] = Bb[j];
      for (let j = 16; j < 68; j++) W[j] = u32x(P1(u32x(W[j - 16] ^ W[j - 9] ^ rotl32(W[j - 3], 15))) ^ rotl32(W[j - 13], 7) ^ W[j - 6]);
      for (let j = 0; j < 64; j++) Wp[j] = u32x(W[j] ^ W[j + 4]);
      let A = V[0], B = V[1], C = V[2], D = V[3], E = V[4], F = V[5], G = V[6], H = V[7];
      for (let j = 0; j < 64; j++) {
        const SS1 = u32x(rotl32(u32x(rotl32(A, 12) + E + rotl32(Tj[j], j & 31)), 7));
        const SS2 = u32x(SS1 ^ rotl32(A, 12));
        let TT1 = u32x(FFj(j, A, B, C) + D + SS2 + Wp[j]);
        let TT2 = u32x(GGj(j, E, F, G) + H + SS1 + W[j]);
        D = C; C = rotl32(B, 9); B = A; A = TT1;
        H = G; G = rotl32(F, 19); F = E; E = P0(TT2);
      }
      V[0] = u32x(V[0] ^ A); V[1] = u32x(V[1] ^ B); V[2] = u32x(V[2] ^ C); V[3] = u32x(V[3] ^ D);
      V[4] = u32x(V[4] ^ E); V[5] = u32x(V[5] ^ F); V[6] = u32x(V[6] ^ G); V[7] = u32x(V[7] ^ H);
    }
    const out = new Uint8Array(32);
    for (let i = 0; i < 8; i++) wr32be(out, i * 4, V[i]);
    return out;
  }
  function P0(x) { return u32x(x ^ rotl32(x, 9) ^ rotl32(x, 17)); }
  function P1(x) { return u32x(x ^ rotl32(x, 15) ^ rotl32(x, 23)); }
  function FFj(j, x, y, z) { return j < 16 ? u32x(x ^ y ^ z) : u32x((x & y) | (x & z) | (y & z)); }
  function GGj(j, x, y, z) { return j < 16 ? u32x(x ^ y ^ z) : u32x((x & y) | (~x & z)); }

  // ---------- SHA-512 ----------
  const K512 = [0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn, 0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n, 0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n, 0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n, 0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9cacn, 0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n, 0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n, 0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n, 0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn, 0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn, 0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n, 0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n, 0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n, 0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n, 0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn, 0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn, 0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n, 0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn, 0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn, 0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n];
  function sha512Bytes(msg) {
    const d = JSSHA512.digest(msg);
    const out = new Uint8Array(64);
    for (let i = 0; i < 64; i++) out[i] = d[i] & 0xff;
    return out;
  }
  function big64(v) { return BigInt.asUintN(64, v); }
  function ror64(x, n) { return big64((x >> n) | (x << (64n - n))); }
  function readBigBE(b, o) { let v = 0n; for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(b[o + i]); return v; }
  function writeBigBE(b, o, v) { for (let i = 7; i >= 0; i--) { b[o + i] = Number(v & 0xffn); v >>= 8n; } }

  // ---------- AES-128 ----------
  function gfMul(a, b) {
    let p = 0, aa = a, bb = b;
    for (let i = 0; i < 8; i++) { if (bb & 1) p ^= aa; const h = aa & 0x80; aa = (aa << 1) & 0xff; if (h) aa ^= 0x1b; bb >>= 1; }
    return p;
  }
  function buildAesSBox() {
    // exp/log over GF(2^8) poly 0x11b
    const exp = new Uint8Array(256), log = new Uint8Array(256);
    // 0x02 在 0x11b 下不是本原元（周期仅 204），必须用本原元 0x03 生成完整指数/对数表
    let x = 1;
    for (let i = 0; i < 255; i++) {
      exp[i] = x; log[x] = i;
      const x2 = (x << 1) ^ ((x & 0x80) ? 0x11b : 0);
      x = (x2 ^ x) & 0xff; // x*3
    }
    exp[255] = 1;
    const s = new Uint8Array(256);
    for (let i = 0; i < 256; i++) {
      let inv = i === 0 ? 0 : exp[(255 - log[i]) % 255];
      let b = inv, r = 0;
      for (let j = 0; j < 8; j++) {
        const bit = ((b >> j) & 1) ^ ((b >> ((j + 4) & 7)) & 1) ^ ((b >> ((j + 5) & 7)) & 1) ^ ((b >> ((j + 6) & 7)) & 1) ^ ((b >> ((j + 7) & 7)) & 1);
        r |= bit << j;
      }
      s[i] = r ^ 0x63;
    }
    return s;
  }
  const SBOX = buildAesSBox();
  const ISBOX = (() => { const inv = new Uint8Array(256); for (let i = 0; i < 256; i++) inv[SBOX[i]] = i; return inv; })();
  const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8];
  function aesKeySchedule(key) {
    // key: 16 bytes, returns 11 round keys each 16 bytes
    const w = new Uint8Array(176);
    w.set(key, 0);
    for (let i = 4; i < 44; i++) {
      let t0 = w[(i - 1) * 4], t1 = w[(i - 1) * 4 + 1], t2 = w[(i - 1) * 4 + 2], t3 = w[(i - 1) * 4 + 3];
      if (i % 4 === 0) {
        t0 = SBOX[t1]; t1 = SBOX[t2]; t2 = SBOX[t3]; t3 = SBOX[w[(i - 1) * 4]];
        t0 ^= RCON[(i / 4) - 1];
      }
      w[i * 4] = w[(i - 4) * 4] ^ t0; w[i * 4 + 1] = w[(i - 4) * 4 + 1] ^ t1; w[i * 4 + 2] = w[(i - 4) * 4 + 2] ^ t2; w[i * 4 + 3] = w[(i - 4) * 4 + 3] ^ t3;
    }
    return w;
  }
  function aesEncryptBlock(state, w) {
    // state 16 bytes in place
    const st = new Uint8Array(16);
    for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) st[c * 4 + r] = state[r + 4 * c];
    addRoundKey(st, w, 0);
    for (let round = 1; round < 10; round++) {
      for (let i = 0; i < 16; i++) st[i] = SBOX[st[i]];
      shiftRows(st, false);
      mixColumns(st, false);
      addRoundKey(st, w, round);
    }
    for (let i = 0; i < 16; i++) st[i] = SBOX[st[i]];
    shiftRows(st, false);
    addRoundKey(st, w, 10);
    for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) state[r + 4 * c] = st[c * 4 + r];
    return state;
  }
  function aesDecryptBlock(state, w) {
    const st = new Uint8Array(16);
    for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) st[c * 4 + r] = state[r + 4 * c];
    addRoundKey(st, w, 10);
    for (let round = 9; round >= 1; round--) {
      shiftRows(st, true);
      for (let i = 0; i < 16; i++) st[i] = ISBOX[st[i]];
      addRoundKey(st, w, round);
      mixColumns(st, true);
    }
    shiftRows(st, true);
    for (let i = 0; i < 16; i++) st[i] = ISBOX[st[i]];
    addRoundKey(st, w, 0);
    for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) state[r + 4 * c] = st[c * 4 + r];
    return state;
  }
  function addRoundKey(st, w, round) { const o = round * 16; for (let i = 0; i < 16; i++) st[i] ^= w[o + i]; }
  function shiftRows(st, inv) {
    // st is column-major: st[c*4+r]。行 r 循环左移 r 字节：
    //   加密 ShiftRows：新列 c = 旧列 c+r；解密 InvShiftRows（右移）：新列 c = 旧列 c-r
    const out = new Uint8Array(16);
    for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) { const src = inv ? (c - r + 4) % 4 : (c + r) % 4; out[c * 4 + r] = st[src * 4 + r]; }
    st.set(out);
  }
  function mixColumns(st, inv) {
    const out = new Uint8Array(16);
    for (let c = 0; c < 4; c++) {
      const a = [st[c * 4], st[c * 4 + 1], st[c * 4 + 2], st[c * 4 + 3]];
      let o0, o1, o2, o3;
      if (!inv) {
        o0 = gfMul(a[0], 2) ^ gfMul(a[1], 3) ^ a[2] ^ a[3];
        o1 = a[0] ^ gfMul(a[1], 2) ^ gfMul(a[2], 3) ^ a[3];
        o2 = a[0] ^ a[1] ^ gfMul(a[2], 2) ^ gfMul(a[3], 3);
        o3 = gfMul(a[0], 3) ^ a[1] ^ a[2] ^ gfMul(a[3], 2);
      } else {
        o0 = gfMul(a[0], 14) ^ gfMul(a[1], 11) ^ gfMul(a[2], 13) ^ gfMul(a[3], 9);
        o1 = gfMul(a[0], 9) ^ gfMul(a[1], 14) ^ gfMul(a[2], 11) ^ gfMul(a[3], 13);
        o2 = gfMul(a[0], 13) ^ gfMul(a[1], 9) ^ gfMul(a[2], 14) ^ gfMul(a[3], 11);
        o3 = gfMul(a[0], 11) ^ gfMul(a[1], 13) ^ gfMul(a[2], 9) ^ gfMul(a[3], 14);
      }
      out[c * 4] = o0; out[c * 4 + 1] = o1; out[c * 4 + 2] = o2; out[c * 4 + 3] = o3;
    }
    st.set(out);
  }
  function incCounter(iv, n) {
    // iv: 16-byte big-endian counter, n = number of 16-byte blocks to advance
    const out = new Uint8Array(iv);
    let carry = n;
    for (let i = 15; i >= 0 && carry; i--) { const s = out[i] + carry; out[i] = s & 0xff; carry = s >> 8; }
    return out;
  }
  var __AESW_CACHE = new Map();
  function __aesKeyScheduleCached(key) {
    // 性能关键：AES 密钥扩展很贵，而同一段视频里所有样本的 key 完全相同。
    // 原实现每个加密样本都调一次 aesKeySchedule（44 轮），1MB 段几百样本 => 几百次扩展（转圈主因）。
    var h = '';
    for (var i = 0; i < key.length; i++) h += (key[i] < 16 ? '0' : '') + key[i].toString(16);
    var w = __AESW_CACHE.get(h);
    if (!w) { w = aesKeySchedule(key); if (__AESW_CACHE.size > 16) __AESW_CACHE.clear(); __AESW_CACHE.set(h, w); }
    return w;
  }
  // ===== T-table AES-128（仅用于 CTR keystream 的加密方向）=====
  // 原实现每 16 字节逐字节查 SBOX + gfMul 做 MixColumns，纯 JS 下极慢（实测 1MB 段 288ms）。
  // T-table 把 SubBytes+ShiftRows+MixColumns 合并成 4 张 256 项查表，实测 11ms（26x）。
  var __TT = (function () {
    var S = SBOX;
    function mul(x, y) { var p = 0; for (var i = 0; i < 8; i++) { if (y & 1) p ^= x; var h = x & 128; x = (x << 1) & 255; if (h) x ^= 0x1b; y >>= 1; } return p; }
    var T0 = new Uint32Array(256), T1 = new Uint32Array(256), T2 = new Uint32Array(256), T3 = new Uint32Array(256);
    for (var i = 0; i < 256; i++) {
      var sv = S[i], s2 = mul(sv, 2), s3 = mul(sv, 3);
      T0[i] = ((s2 << 24) | (sv << 16) | (sv << 8) | s3) >>> 0;
      T1[i] = ((s3 << 24) | (s2 << 16) | (sv << 8) | sv) >>> 0;
      T2[i] = ((sv << 24) | (s3 << 16) | (s2 << 8) | sv) >>> 0;
      T3[i] = ((sv << 24) | (sv << 16) | (s3 << 8) | s2) >>> 0;
    }
    var RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    var cache = new Map();
    function schedule(key) {
      var h = '';
      for (var i = 0; i < 16; i++) h += (key[i] < 16 ? '0' : '') + key[i].toString(16);
      var rk = cache.get(h);
      if (rk) return rk;
      var w = new Uint32Array(44);
      for (var j = 0; j < 4; j++) w[j] = ((key[4 * j] << 24) | (key[4 * j + 1] << 16) | (key[4 * j + 2] << 8) | key[4 * j + 3]) >>> 0;
      for (var k = 4; k < 44; k++) {
        var t = w[k - 1];
        if (k % 4 === 0) {
          t = ((t << 8) | (t >>> 24)) >>> 0;
          t = (((S[(t >>> 24) & 255] << 24) | (S[(t >>> 16) & 255] << 16) | (S[(t >>> 8) & 255] << 8) | S[t & 255]) >>> 0) ^ (RCON[(k / 4) - 1] << 24);
        }
        w[k] = (w[k - 4] ^ t) >>> 0;
      }
      rk = { w: w };
      if (cache.size > 16) cache.clear();
      cache.set(h, rk);
      return rk;
    }
    function block(b, rk) {
      var w = rk.w;
      var s0 = (((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) ^ w[0]) >>> 0;
      var s1 = (((b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7]) ^ w[1]) >>> 0;
      var s2 = (((b[8] << 24) | (b[9] << 16) | (b[10] << 8) | b[11]) ^ w[2]) >>> 0;
      var s3 = (((b[12] << 24) | (b[13] << 16) | (b[14] << 8) | b[15]) ^ w[3]) >>> 0;
      for (var r = 1; r < 10; r++) {
        var o = r * 4;
        var t0 = (T0[(s0 >>> 24) & 255] ^ T1[(s1 >>> 16) & 255] ^ T2[(s2 >>> 8) & 255] ^ T3[s3 & 255] ^ w[o]) >>> 0;
        var t1 = (T0[(s1 >>> 24) & 255] ^ T1[(s2 >>> 16) & 255] ^ T2[(s3 >>> 8) & 255] ^ T3[s0 & 255] ^ w[o + 1]) >>> 0;
        var t2 = (T0[(s2 >>> 24) & 255] ^ T1[(s3 >>> 16) & 255] ^ T2[(s0 >>> 8) & 255] ^ T3[s1 & 255] ^ w[o + 2]) >>> 0;
        var t3 = (T0[(s3 >>> 24) & 255] ^ T1[(s0 >>> 16) & 255] ^ T2[(s1 >>> 8) & 255] ^ T3[s2 & 255] ^ w[o + 3]) >>> 0;
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
      }
      var o2 = 40;
      var b0 = (((S[(s0 >>> 24) & 255] << 24) | (S[(s1 >>> 16) & 255] << 16) | (S[(s2 >>> 8) & 255] << 8) | S[s3 & 255]) ^ w[o2]) >>> 0;
      var b1 = (((S[(s1 >>> 24) & 255] << 24) | (S[(s2 >>> 16) & 255] << 16) | (S[(s3 >>> 8) & 255] << 8) | S[s0 & 255]) ^ w[o2 + 1]) >>> 0;
      var b2 = (((S[(s2 >>> 24) & 255] << 24) | (S[(s3 >>> 16) & 255] << 16) | (S[(s0 >>> 8) & 255] << 8) | S[s1 & 255]) ^ w[o2 + 2]) >>> 0;
      var b3 = (((S[(s3 >>> 24) & 255] << 24) | (S[(s0 >>> 16) & 255] << 16) | (S[(s1 >>> 8) & 255] << 8) | S[s2 & 255]) ^ w[o2 + 3]) >>> 0;
      b[0] = (b0 >>> 24) & 255; b[1] = (b0 >>> 16) & 255; b[2] = (b0 >>> 8) & 255; b[3] = b0 & 255;
      b[4] = (b1 >>> 24) & 255; b[5] = (b1 >>> 16) & 255; b[6] = (b1 >>> 8) & 255; b[7] = b1 & 255;
      b[8] = (b2 >>> 24) & 255; b[9] = (b2 >>> 16) & 255; b[10] = (b2 >>> 8) & 255; b[11] = b2 & 255;
      b[12] = (b3 >>> 24) & 255; b[13] = (b3 >>> 16) & 255; b[14] = (b3 >>> 8) & 255; b[15] = b3 & 255;
    }
    return { block: block, schedule: schedule };
  })();
  function makeCTR(key, iv) {
    const w = __aesKeyScheduleCached(key);
    let counter = new Uint8Array(iv); // 递增计数器，保持原始值
    let ks = new Uint8Array(0); let kpos = 0;
    const __rk = __TT.schedule(new Uint8Array(key));
    function refill() {
      const block = new Uint8Array(16);
      block.set(counter);
      __TT.block(block, __rk); // T-table 加密计数器副本（与原 aesEncryptBlock 输出逐字节一致）
      ks = block;
      kpos = 0;
    }
    refill(); // 首次填充 keystream
    return {
      update(input) {
        const out = new Uint8Array(input.length);
        for (let i = 0; i < input.length; i++) {
          if (kpos >= 16) { counter = incCounter(counter, 1); refill(); }
          out[i] = input[i] ^ ks[kpos++];
        }
        return out;
      },
      final() { return new Uint8Array(0); }
    };
  }
  function makeCBCDecrypt(key, iv) {
    const w = __aesKeyScheduleCached(key);
    let prev = new Uint8Array(iv);
    const outAll = [];
    return {
      update(input) {
        for (let o = 0; o < input.length; o += 16) {
          const block = input.subarray(o, o + 16);
          const dec = new Uint8Array(block); aesDecryptBlock(dec, w);
          for (let i = 0; i < 16; i++) dec[i] ^= prev[i];
          prev = new Uint8Array(block);
          outAll.push(dec);
        }
        return new Uint8Array(0); // 收集在 final 返回（兼容本文件用法）
      },
      final() { return concatU8(outAll); },
      setAutoPadding() { }
    };
  }
  function concatU8(list) { let t = 0; for (const b of list) t += b.length; const o = new Uint8Array(t); let p = 0; for (const b of list) { o.set(b, p); p += b.length; } return o; }

  // ---------- 统一入口 ----------
  function makeCrypto(BufferCtor) {
    const wrap = (u8) => BufferCtor.from(u8);
    return {
      createHash(alg) {
        let parts = [];
        return {
          update(d) { if (typeof d === 'string') parts.push(textEncoder().encode(d)); else parts.push(d); return this; },
          digest(enc) {
            const data = concatU8(parts.map((p) => (p instanceof Uint8Array ? p : p)));
            let out;
            if (alg === 'md5') out = md5Bytes(data);
            else if (alg === 'sm3') out = sm3Bytes(data);
            else if (alg === 'sha512') out = sha512Bytes(data);
            else throw new Error('hash ' + alg);
            if (enc === 'hex') { let s = ''; for (let i = 0; i < out.length; i++) s += (out[i] < 16 ? '0' : '') + out[i].toString(16); return s; }
            return wrap(out);
          }
        };
      },
      createDecipheriv(alg, key, iv) {
        if (alg === 'aes-128-ctr') { const c = makeCTR(new Uint8Array(key), new Uint8Array(iv)); return { update: (d) => wrap(c.update(new Uint8Array(d))), final: () => wrap(c.final()) }; }
        if (alg === 'aes-128-cbc') { const c = makeCBCDecrypt(new Uint8Array(key), new Uint8Array(iv)); return { update: (d) => { c.update(new Uint8Array(d)); return wrap(new Uint8Array(0)); }, final: () => wrap(c.final()), setAutoPadding: () => { } }; }
        throw new Error('cipher ' + alg);
      }
    };
  }
  return { makeBufferPolyfill, makeCrypto };
})();
var Buffer;
if (typeof globalThis !== 'undefined' && globalThis.Buffer && typeof globalThis.Buffer.alloc === 'function') Buffer = globalThis.Buffer;
else if (typeof global !== 'undefined' && global.Buffer && typeof global.Buffer.alloc === 'function') Buffer = global.Buffer;
else Buffer = __AC.makeBufferPolyfill();
var crypto = __AC.makeCrypto(Buffer);

const SITE = 'https://hongguoduanju.com';
const VIDEO_API = 'https://api5-normal-sinfonlineb.fqnovel.com/novel/player/multi_video_model/v1/';
const APP_SEARCH_API = 'https://api5-normal-sinfonlinea.fqnovel.com/reading/bookapi/search/tab/v';
// 官网搜索接口：App 搜索接口 2026-10 起对旧签名直接回 200 空包，搜索统一回退到这里
const WEB_SEARCH_API = SITE + '/api/search/result';
const WEB_SEARCH_CONTEXT_API = SITE + '/api/search/context';
const VIDEO_UA = 'com.phoenix.read/71332 (Linux; U; Android 16; zh_CN; 25053RT47C; Build/BP2A.250605.031.A3; Cronet/TTNetVersion:04657795 2026-01-23 QuicVersion:c67e9834 2025-09-08)';
const APP_UA = 'com.phoenix.read/72232 (Linux; U; Android 16; zh_CN; 25053RT47C; Build/BP2A.250605.031.A3)';
function randomDeviceId() {
  let out = String(Math.floor(Math.random() * 9) + 1);
  while (out.length < 17) out += String(Math.floor(Math.random() * 10));
  return out;
}
let DEVICE = {
  iid: randomDeviceId(), device_id: randomDeviceId(), ac: 'wifi', channel: 'update_64', aid: '8662', app_name: 'novelread',
  version_code: '71332', version_name: '7.1.3.32', device_platform: 'android', os: 'android',
  ssmix: 'a', device_type: '25053RT47C', device_brand: 'Redmi', language: 'zh', os_api: '36',
  os_version: '16', manifest_version_code: '71332', resolution: '1280*2772', dpi: '520',
  update_version_code: '71332', host_abi: 'arm64-v8a', dragon_device_type: 'phone', pv_player: '71332',
  compliance_status: '0', need_personal_recommend: '1', player_so_load: '1', is_android_pad_screen: '0',
};
const APP_DEVICE = {
  ...DEVICE, version_code: '72232', version_name: '7.2.2.32', manifest_version_code: '72232',
  update_version_code: '72232', pv_player: '72232',
};
const SELECTOR_GROUPS = [
  { key: 'background', name: '全部背景', items: [['现代', 'cate_757'], ['都市', 'cate_1'], ['古代', 'cate_758'], ['乡村', 'cate_11'], ['年代', 'cate_79'], ['架空', 'cate_452'], ['职场', 'cate_127'], ['民国', 'cate_390'], ['校园', 'cate_4'], ['宫廷', 'cate_1153'], ['荒岛', 'cate_1162']] },
  { key: 'topic', name: '全部主题', items: [['现言', 'cate_1021'], ['女性成长', 'cate_1048'], ['脑洞', 'cate_262'], ['奇幻', 'cate_1020'], ['玄幻', 'cate_1019'], ['古言', 'cate_439'], ['战神', 'cate_1038'], ['宫斗', 'cate_246'], ['仙侠', 'cate_1013'], ['权谋', 'cate_1047'], ['种田', 'cate_1180'], ['年代爱情', 'cate_1022'], ['悬疑', 'cate_165'], ['喜剧', 'cate_303'], ['青春', 'cate_297'], ['志怪', 'cate_1027'], ['民国爱情', 'cate_1025'], ['灵异', 'cate_751'], ['家国情怀', 'cate_1235'], ['法律', 'cate_1136'], ['刑侦', 'cate_1148'], ['抗战', 'cate_504'], ['武侠', 'cate_1172'], ['民国传奇', 'cate_1240'], ['动作', 'cate_302'], ['求生', 'cate_1168'], ['科幻', 'cate_1092'], ['恐怖', 'cate_1219'], ['商战', 'cate_1225']] },
  { key: 'setting', name: '全部设定', items: [['打脸虐渣', 'cate_1051'], ['大男主', 'cate_1207'], ['大女主', 'cate_760'], ['马甲', 'cate_266'], ['重生', 'cate_36'], ['穿越', 'cate_37'], ['系统', 'cate_19'], ['先婚后爱', 'cate_265'], ['家长里短', 'cate_862'], ['小人物', 'cate_1010'], ['破镜重圆', 'cate_475'], ['神豪', 'cate_20'], ['豪门', 'cate_936'], ['强者回归', 'cate_1045'], ['异能', 'cate_598'], ['传承觉醒', 'cate_1007'], ['虐恋', 'cate_1008'], ['医生', 'cate_487'], ['强强联合', 'cate_1049'], ['赘婿逆袭', 'cate_1044'], ['甜宠', 'cate_96'], ['娱乐圈', 'cate_43'], ['神医', 'cate_26'], ['青梅竹马', 'cate_387'], ['姐弟恋', 'cate_762'], ['玄学', 'cate_929'], ['追妻火葬场', 'cate_616'], ['业界精英', 'cate_1293'], ['一见钟情', 'cate_477'], ['福宝', 'cate_1291'], ['捞偏门', 'cate_1287'], ['反派主角', 'cate_1042'], ['萌宠', 'cate_428'], ['方言', 'cate_1255'], ['双向救赎', 'cate_1200'], ['白月光', 'cate_615'], ['灵魂互换', 'cate_831'], ['病娇', 'cate_380'], ['暴富', 'cate_1191'], ['黑道', 'cate_826'], ['丧尸', 'cate_582'], ['特种兵', 'cate_375']] },
  { key: 'gender', name: '全部受众', items: [['男频', '1'], ['女频', '0']] },
  { key: 'time', name: '全部时间', items: [['7天内上新', '1'], ['14天内上新', '2'], ['30天内上新', '3'], ['90天内上新', '4']] },
  { key: 'sort_type', name: '全部推荐', items: [['最新', '2'], ['最热', '1']] },
];
const CATEGORY_CONFIG = {
  short: { type_name: '短剧', kind: 'category', query: 'tab=1&sort_type=1' },
  human: { type_name: '真人剧', kind: 'app', tabType: 11, keyword: '短剧', fallback: 'hot-real-drama' },
  comic: { type_name: '漫剧', kind: 'app', tabType: 19, keyword: '热门', fallback: 'hot-comic-drama' },
  ai: { type_name: 'AI剧', kind: 'app', tabType: 11, keyword: 'AI剧', fallback: 'hot-ai-drama' },
  rank_hot: { type_name: '红果热播榜', kind: 'rank', route: 'hot-drama' },
  rank_human: { type_name: '真人剧热播榜', kind: 'rank', route: 'hot-real-drama' },
  rank_comic: { type_name: '漫剧热播榜', kind: 'rank', route: 'hot-comic-drama' },
  rank_ai: { type_name: 'AI剧热播榜', kind: 'rank', route: 'hot-ai-drama' },
};
const CATEGORIES = Object.entries(CATEGORY_CONFIG).map(([type_id, value]) => ({ type_id, type_name: value.type_name }));
const FILTER_GROUPS = SELECTOR_GROUPS.map((group) => ({
  key: group.key,
  name: group.name,
  value: [{ n: '全部', v: '' }, ...group.items.map(([n, v]) => ({ n, v }))],
}));
const FILTERS = Object.fromEntries(Object.keys(CATEGORY_CONFIG).map((typeId) => [typeId, FILTER_GROUPS]));
const RANK_ROUTE_RE = /^(hot-drama|hot-real-drama|hot-comic-drama|hot-ai-drama)$/;
const PAGE_SIZE = 24;
const SEG_SIZE = 1024 * 1024; // proxy 单段回传上限：钳制 Range 防止整文件 base64 撑爆内存
const pageCache = new Map();
const streamCache = new Map();
const videoInfoCache = new Map();
const appSearchCache = new Map();
const webSearchSession = { cookie: '', time: 0 };
let appSearchBlockedUntil = 0;

// ---------- 秒播缓存（1MB 对齐分段 + 段内预读 + 后10集首段预热）----------
const MAX_REPLY_BYTES = 4 * 1024 * 1024; // 首次最多回 4MB，与下一集预热量对齐，避免命中首段后仍等待额外 7MB
const CACHE_MAX_SEGS = 64;       // 明文分段缓存上限约 64MB，给当前播放和后续集启动段留足空间
const CACHE_MAX_HEADS = 16;      // 每集首段(seg0，切集秒播用)最多保留个数
const PREFETCH_EPISODES = 3;     // 只预热紧邻的后 3 集；继续观看时滚动补充
const READ_AHEAD_SEGS = 3;       // 当前集向前预读 3 个 1MB 段，避免抢占起播带宽
const WARM_PAUSE_MS = 500;       // 后续集之间留出带宽给当前播放
const ENABLE_BEACON = false;     // 正式版关闭外部耗时上报，避免额外 HTTPS 连接
// 真机耗时信标：把每段请求的命中/耗时回报到服务器访问日志，便于精确定位卡顿
var __BG_LAST = 0;
function __beacon(tag, msg) {
  if (!ENABLE_BEACON) return;
  try {
    var https = require('https');
    var u = 'https://hw.361123.xyz/m/index.config.js.md5?t=hg17-' + encodeURIComponent(String(tag).slice(0, 20)) +
            '&e=' + encodeURIComponent(String(msg).slice(0, 150));
    var rq = https.get(u, { timeout: 5000 }, function (rs) { rs.resume(); });
    rq.on('error', function () {});
    rq.setTimeout(5000, function () { try { rq.destroy(); } catch (e) {} });
  } catch (e) {}
}
const segCache = new Map();      // key=vid|q|segIndex -> {start,end,total,data(Buffer),at}
const segPending = new Map();    // 同一对齐段并发去重
const episodeNext = new Map();   // vid -> 后面 PREFETCH_EPISODES 集的 vid 数组
const episodeQueue = [];         // 后续集预热串行队列
const episodeQueued = new Set(); // 已入队 vid|q 去重
const bgTasks = [];              // 后台任务引用，防止被沙箱回收
let episodeActive = false;
function bg(p) { const t = (p && p.catch) ? p.catch(() => { }) : Promise.resolve(); bgTasks.push(t); if (bgTasks.length > 120) bgTasks.splice(0, bgTasks.length - 120); return t; }
function segKey(vid, quality, segIndex) { return String(vid) + '|' + String(quality) + '|' + segIndex; }
function cacheTrim() {
  // 超上限时优先淘汰最旧的播放段(seg0 之外)；首段是切集秒播关键，尽量保留
  while (segCache.size > CACHE_MAX_SEGS) {
    let removed = false;
    for (const pair of segCache) {
      if (pair[1].start !== 0) { segCache.delete(pair[0]); removed = true; break; }
    }
    if (!removed) segCache.delete(segCache.keys().next().value);
  }
  // 首段单独设上限，防止连看很多集后首段只增不减
  let headCount = 0;
  for (const pair of segCache) if (pair[1].start === 0) headCount += 1;
  for (const pair of segCache) {
    if (headCount <= CACHE_MAX_HEADS) break;
    if (pair[1].start === 0) { segCache.delete(pair[0]); headCount -= 1; }
  }
}
function cacheTouch(key) { const row = segCache.get(key); if (row) { segCache.delete(key); row.at = Date.now(); segCache.set(key, row); } return row; }

function str(value, fallback = '') { return String(value == null ? fallback : value).trim(); }
function pageNumber(value) { const n = Number.parseInt(value, 10); return Number.isFinite(n) && n > 0 ? n : 1; }
function cleanUrl(value) { return str(value).replace(/\\\//g, '/').replace(/\\u0026/g, '&').replace(/&amp;/g, '&'); }
function jsonBody(value) { try { return JSON.parse(value); } catch { return null; } }
function playKey(vid, quality = 'auto') { return `${str(vid)}|${str(quality) || 'auto'}`; }
function runtimeProxyBase() {
  try {
    const getter = typeof getProxyUrl !== 'undefined' ? getProxyUrl : null;
    const value = typeof getter === 'function' ? getter() : getter;
    const base = str(value).split('#')[0];
    if (/^https?:\/\/(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?\//i.test(base)) {
      return base + (base.includes('?') ? '&' : '?');
    }
  } catch (e) { }
  return 'toast://当前猫源客户端没有启用本机代理';
}
// 签名对 query 字节级敏感：python urllib.parse.quote 的 ['!'*'()'] 兜底编码行为须保持一致
function pythonUrlEncode(values) {
  return Object.entries(values).map(([key, value]) => {
    const encode = (item) => encodeURIComponent(String(item == null ? '' : item))
      .replace(/[!'()]/g, (ch) => `%${ch.charCodeAt(0).toString(16).toUpperCase()}`);
    return `${encode(key)}=${encode(value)}`;
  }).join('&');
}

function headerValue(headers, name) {
  const wanted = String(name).toLowerCase();
  const source = headers && typeof headers === 'object' ? headers : {};
  for (const key of Object.keys(source)) if (String(key).toLowerCase() === wanted) {
    const value = source[key];
    return Array.isArray(value) ? String(value[0] || '') : String(value == null ? '' : value);
  }
  return '';
}

async function localHttp(url, options = {}) {
  return await new Promise(function (resolve, reject) {
    var settled = false;
    function done(err, value) {
      if (settled) return;
      settled = true;
      if (err) reject(err); else resolve(value);
    }
    function send(target, redirects) {
      try {
        var u = new URL(target);
        var mod = u.protocol === 'https:' ? require('https') : require('http');
        var method = String(options.method || (options.data != null ? 'POST' : 'GET')).toUpperCase();
        var headers = Object.assign({}, options.headers || {});
        var body = null;
        if (method !== 'GET' && method !== 'HEAD' && options.data != null) {
          body = Buffer.isBuffer(options.data) ? options.data : Buffer.from(String(options.data), 'utf8');
          if (!headers['Content-Length'] && !headers['content-length']) headers['Content-Length'] = String(body.length);
        }
        var rq = mod.request({
          protocol: u.protocol, hostname: u.hostname, port: u.port || undefined,
          path: u.pathname + u.search, method: method, headers: headers
        }, function (rs) {
          var code = Number(rs.statusCode || 0);
          var loc = rs.headers && rs.headers.location;
          if (options.redirect !== false && loc && [301, 302, 303, 307, 308].indexOf(code) >= 0 && redirects < 6) {
            rs.resume();
            return send(new URL(loc, target).href, redirects + 1);
          }
          var chunks = [];
          rs.on('data', function (c) { chunks.push(Buffer.from(c)); });
          rs.on('end', function () {
            var data = Buffer.concat(chunks);
            done(null, { status: code, headers: rs.headers || {}, data: options.responseType === 'arraybuffer' ? data : data.toString('utf8') });
          });
          rs.on('error', function (e) { done(e); });
        });
        rq.on('error', function (e) { done(e); });
        rq.setTimeout(Number(options.timeout || 30000), function () { rq.destroy(new Error('请求超时')); });
        if (body) rq.write(body);
        rq.end();
      } catch (e) { done(e); }
    }
    send(url, 0);
  });
}

async function getText(url, options = {}) {
  const resp = await localHttp(url, { headers: { 'User-Agent': VIDEO_UA, 'Accept-Language': 'zh-CN,zh;q=0.9', ...(options.headers || {}) }, timeout: options.timeout || 20000, responseType: 'text' });
  if (resp.status < 200 || resp.status >= 300) throw new Error(`HTTP ${resp.status}: ${url}`);
  return resp.data;
}

// ---------- 官网 SSR 数据 ----------

function extractAssignedJson(source, marker = '_ROUTER_DATA') {
  const start = source.indexOf(marker);
  if (start < 0) throw new Error('页面没有路由数据');
  const first = source.indexOf('{', start);
  if (first < 0) throw new Error('路由数据格式错误');
  let depth = 0; let quote = false; let escaped = false;
  for (let i = first; i < source.length; i += 1) {
    const ch = source[i];
    if (quote) { if (escaped) escaped = false; else if (ch === '\\') escaped = true; else if (ch === '"') quote = false; continue; }
    if (ch === '"') quote = true;
    else if (ch === '{' || ch === '[') depth += 1;
    else if (ch === '}' || ch === ']') { depth -= 1; if (depth === 0) return JSON.parse(source.slice(first, i + 1)); }
  }
  throw new Error('路由数据不完整');
}

async function routerData(url) {
  const cached = pageCache.get(url);
  if (cached && Date.now() - cached.time < 180000) return cached.value;
  const value = extractAssignedJson(await getText(url));
  pageCache.set(url, { time: Date.now(), value });
  return value;
}

// 一级/搜索/推荐的卡片必须是 TVBox 风格字段：引擎 setResult 只认 url/title/desc/img 并转成 vod_*，
// 直接返回 vod_name/vod_pic 会在转换中全部丢失（列表有条目但名称图片全空）
function itemToCard(item) {
  const source = item?.video_data && typeof item.video_data === 'object' ? item.video_data : item;
  const categoryList = Array.isArray(source?.category_list) ? source.category_list.map((value) => value?.name || value).filter(Boolean) : [];
  const tags = Array.isArray(source?.tags) ? source.tags : categoryList;
  const count = Number(source?.episode_cnt || source?.series_episode_info?.episode_cnt || 0);
  return {
    url: str(source?.series_id), title: str(source?.series_name || source?.series_title || item?.name), img: cleanUrl(source?.series_cover),
    desc: str(source?.episode_right_text) || (count ? `全${count}集` : ''),
    tname: tags.slice(0, 5).join('/'), content: str(source?.series_intro),
  };
}

function categoryData(data) {
  const page = data?.loaderData?.['category_$'] || data?.loaderData?.category_page || data || {};
  return page.recommendList || page.categoryData?.recommendList || [];
}

async function currentCategoryPage(typeId, page = 1) {
  const slugs = { short: 'real-drama', human: 'real-drama', comic: 'comic-drama', ai: 'ai-drama' };
  const slug = slugs[typeId] || 'real-drama';
  const query = page > 1 ? `?page=${page}&` : '?';
  const data = jsonBody(await getText(`${SITE}/category/${slug}${query}__loader=category_%24&__ssrDirect=true`));
  if (!data) throw new Error('分类 loader 返回非 JSON');
  return categoryData(data);
}

function parseJoinedJson(text) {
  const data = {}; const raw = str(text);
  let start = -1, depth = 0, quoted = false, escaped = false;
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i];
    if (quoted) { if (escaped) escaped = false; else if (ch === '\\') escaped = true; else if (ch === '"') quoted = false; continue; }
    if (ch === '"') quoted = true;
    else if (ch === '{' || ch === '[') { if (depth === 0) start = i; depth += 1; }
    else if (ch === '}' || ch === ']') { depth -= 1; if (depth === 0 && start >= 0) { const part = jsonBody(raw.slice(start, i + 1)); if (part && typeof part === 'object') Object.assign(data, part); start = -1; } }
  }
  return data;
}

async function currentRankPage(route, page = 1) {
  const query = page > 1 ? `?page=${page}&` : '?';
  const loader = encodeURIComponent(`rank_${route}/page`);
  const text = await getText(`${SITE}/rank/${route}${query}__loader=${loader}&__ssrDirect=true`);
  const data = jsonBody(text) || parseJoinedJson(text);
  const rows = data?.content?.rankList || data?.rankList || [];
  return rows.map(rankItemToCard).filter((item) => item.url && item.title);
}

function decodeHtml(value) {
  return str(value)
    .replace(/&quot;/g, '"')
    .replace(/&#x2F;|&#47;/gi, '/')
    .replace(/&#x27;|&#39;/gi, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

function rankData(html) {
  const match = html.match(/data-fn-name="r"[^>]*data-fn-args="([^"]+)"/);
  if (!match) throw new Error('榜单页面没有数据');
  const args = jsonBody(decodeHtml(match[1]));
  const payload = Array.isArray(args) ? args[2] : null;
  if (!payload?.isSuccess || !Array.isArray(payload.rankList)) throw new Error('榜单数据格式错误');
  return payload;
}

function rankItemToCard(item) {
  return itemToCard({
    series_id: item?.seriesId || item?.series_id || item?.id,
    series_name: item?.title || item?.seriesTitle || item?.series_name,
    series_cover: item?.cover || item?.seriesCover || item?.series_cover,
    series_intro: item?.description || item?.intro || item?.seriesIntro,
    episode_cnt: item?.episodeCount || item?.episode_cnt,
    tags: item?.tags,
  });
}

async function rankPage(route, page = 1) {
  if (!RANK_ROUTE_RE.test(route)) throw new Error('不支持的榜单');
  const suffix = page > 1 ? `?page=${page}` : '';
  const payload = rankData(await getText(`${SITE}/rank/${route}${suffix}`));
  const pagination = payload.pagination || {};
  const list = payload.rankList.map(rankItemToCard).filter((item) => item.url && item.title);
  return {
    list,
    pagination: {
      totalPages: Number(pagination.totalPages || 1),
      pageNum: Number(pagination.pageNum || page),
      pageSize: Number(pagination.pageSize || list.length || PAGE_SIZE),
      total: Number(pagination.total || pagination.totalCount || (Number(pagination.totalPages || 1) * Number(pagination.pageSize || list.length || PAGE_SIZE))),
    },
  };
}

function categoryType(value) {
  const raw = str(value).replace(/^category\?/, '').replace(/^type_id=/, '');
  if (CATEGORY_CONFIG[raw]) return raw;
  const query = new URLSearchParams(raw);
  const route = str(query.get('rank') || query.get('route'));
  if (RANK_ROUTE_RE.test(route)) return Object.entries(CATEGORY_CONFIG).find(([, item]) => item.route === route && item.kind === 'rank')?.[0] || 'rank_hot';
  return 'short';
}

function filterValues(value) {
  if (typeof value === 'string') {
    const candidates = [value];
    try { candidates.push(decodeURIComponent(value)); } catch (e) { }
    for (const candidate of candidates) {
      try {
        const parsed = JSON.parse(candidate);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return filterValues(parsed);
      } catch (e) { }
      const query = Object.fromEntries(new URLSearchParams(candidate).entries());
      if (Object.keys(query).length) return filterValues(query);
    }
    return {};
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const result = {};
  for (const [key, item] of Object.entries(value)) {
    if (key === 'filters') continue;
    if (item !== undefined && item !== null && str(item) && str(item) !== '-1') result[key] = str(item);
  }
  return result;
}

async function categoryPage(query, page = 1) {
  const params = new URLSearchParams(query);
  if (page > 1) params.set('page', String(page));
  return routerData(`${SITE}/category?${params}`);
}

// ---------- App 搜索（签名接口） ----------

function appFilterKeyword(config, filters) {
  const names = [];
  for (const value of Object.values(filters || {})) {
    const item = SELECTOR_GROUPS.flatMap((group) => group.items).find(([, id]) => id === value);
    if (item) names.push(item[0]);
  }
  return [config.keyword, ...names].filter(Boolean).join(' ');
}

async function appCategoryPage(typeId, config, filters, page) {
  const keyword = appFilterKeyword(config, filters);
  let result = await appSearchPage(keyword, config.tabType, page, PAGE_SIZE);
  if (!result.list.length && keyword !== config.keyword) result = await appSearchPage(config.keyword, config.tabType, page, PAGE_SIZE);
  return {
    page, pagecount: result.hasMore ? page + 1 : page, limit: PAGE_SIZE,
    total: (page - 1) * PAGE_SIZE + result.list.length + (result.hasMore ? 1 : 0), list: result.list,
    type_id: typeId,
  };
}

function appSearchParams(keyword, tabType, limit, cursor = {}, page = 1) {
  const values = {
    ...APP_DEVICE,
    query: str(keyword), count: String(limit), offset: String(Math.max(0, (page - 1) * limit)), tab_type: String(tabType),
    bookshelf_search_plan: '4', use_correct: 'true', user_is_login: '0',
  };
  if (cursor.search_id) values.search_id = cursor.search_id;
  if (cursor.passback) values.passback = cursor.passback;
  return values;
}

function appSearchCells(cell) {
  const result = [];
  if (cell && typeof cell === 'object') result.push(cell);
  if (typeof cell?.lynx_data === 'string') {
    const payload = jsonBody(cell.lynx_data);
    for (const item of Array.isArray(payload?.cell_data) ? payload.cell_data : []) {
      if (item && typeof item === 'object') result.push(item);
    }
  }
  return result;
}

function appSearchVod(cell) {
  const video = Array.isArray(cell?.video_data) ? cell.video_data.find((item) => item && typeof item === 'object') : null;
  if (!video) return null;
  const title = cell?.search_high_light?.title?.text || video.title || cell.cell_name;
  const id = video.series_id || cell.book_id || cell.search_result_id;
  if (!id || !title) return null;
  return {
    url: str(id), title: str(title), img: cleanUrl(video.cover || video.cover_url),
    desc: video.episode_cnt ? `全${video.episode_cnt}集` : str(video.rec_text || video.sub_title),
    tname: str(video.video_desc || video.sub_title), content: str(video.video_desc),
  };
}

async function appSearchPage(keyword, tabType, page = 1, limit = 20) {
  if (Date.now() < appSearchBlockedUntil) throw new Error('App search unavailable');
  const cacheKey = `${tabType}|${keyword}|${page}`; const cached = appSearchCache.get(cacheKey);
  if (cached && Date.now() - cached.time < 300000) return cached.value;
  let cursor = {};
  if (page > 1) {
    const previous = await appSearchPage(keyword, tabType, page - 1, limit);
    cursor = previous.cursor || {};
  }
  let data;
  try {
    data = await signedAppGet(appSearchParams(keyword, tabType, limit, cursor, page));
  } catch (e) {
    // 接口已死时避免每次搜索都白等一轮签名请求，10 分钟内直接走官网兜底
    if (/App search failed: 200/.test(String(e.message))) appSearchBlockedUntil = Date.now() + 600000;
    throw e;
  }
  const tabs = Array.isArray(data.search_tabs) ? data.search_tabs : Array.isArray(data.data?.search_tabs) ? data.data.search_tabs : [];
  const tab = tabs.find((item) => Number(item?.tab_type) === Number(tabType)) || {};
  const list = []; const seen = new Set();
  for (const cell of Array.isArray(tab.data) ? tab.data : []) {
    for (const item of appSearchCells(cell)) {
      const vod = appSearchVod(item);
      if (vod && !seen.has(vod.url)) { seen.add(vod.url); list.push(vod); }
    }
  }
  const value = {
    list, hasMore: Boolean(tab.has_more),
    cursor: { search_id: str(tab.search_id), passback: str(tab.passback), next_offset: str(tab.next_offset) },
  };
  appSearchCache.set(cacheKey, { time: Date.now(), value }); return value;
}

// ---------- 官网搜索（App 搜索接口失效后的兜底） ----------

function webSearchHeaders(cookie, referer) {
  return {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    Accept: 'application/json, text/plain, */*',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    Referer: referer || (SITE + '/'),
    Origin: SITE,
    ...(cookie ? { Cookie: cookie } : {}),
  };
}

function responseCookies(headers) {
  const raw = headers && headers['set-cookie'];
  const values = Array.isArray(raw) ? raw : raw ? [raw] : [];
  return values.map((item) => str(item).split(';')[0]).filter(Boolean).join('; ');
}

async function webSearchCookie() {
  if (webSearchSession.cookie && Date.now() - webSearchSession.time < 600000) return webSearchSession.cookie;
  try {
    const resp = await localHttp(WEB_SEARCH_CONTEXT_API, { headers: webSearchHeaders('', SITE + '/'), timeout: 15000, responseType: 'text' });
    const cookie = responseCookies(resp.headers);
    if (cookie) {
      webSearchSession.cookie = cookie;
      webSearchSession.time = Date.now();
      return cookie;
    }
  } catch (e) { }
  return '';
}

async function webSearchPage(keyword, page = 1) {
  const word = str(keyword).slice(0, 30);
  if (!word) return { list: [], hasMore: false };
  const params = new URLSearchParams({ query: word });
  if (page > 1) params.set('page', String(page));
  let cookie = await webSearchCookie();
  let resp = await localHttp(`${WEB_SEARCH_API}?${params}`, {
    headers: webSearchHeaders(cookie, `${SITE}/search/${encodeURIComponent(word)}`),
    timeout: 20000,
    responseType: 'text',
  });
  // ttwid 失效或上下文过期时换一次新会话再试
  if (resp.status !== 200 && cookie) {
    webSearchSession.cookie = '';
    cookie = await webSearchCookie();
    resp = await localHttp(`${WEB_SEARCH_API}?${params}`, {
      headers: webSearchHeaders(cookie, `${SITE}/search/${encodeURIComponent(word)}`),
      timeout: 20000,
      responseType: 'text',
    });
  }
  const data = jsonBody(resp.data);
  if (resp.status !== 200 || !data || !Array.isArray(data.searchList)) {
    const reason = data ? (data.message || data.code || resp.status) : `${resp.status} 空响应`;
    throw new Error(`web search failed: ${reason}`);
  }
  const list = []; const seen = new Set();
  for (const item of data.searchList) {
    const vod = itemToCard(item);
    if (vod.url && vod.title && !seen.has(vod.url)) { seen.add(vod.url); list.push(vod); }
  }
  return {
    list,
    hasMore: Boolean(data.hasMore),
    pageNum: Number(data.pageNum || page),
    totalPages: Number(data.totalPages || 0),
    total: Number(data.totalCount || 0),
  };
}

// ---------- 字节系签名算法（实测黑盒，勿改常量/位序） ----------

function md5(value) { return crypto.createHash('md5').update(value).digest('hex').toUpperCase(); }
function sm3(value) { return crypto.createHash('sm3').update(value).digest(); }
function u32(value) { return Number(value) >>> 0; }
function rol32(value, count) { const n = count & 31; const x = u32(value); return u32((x << n) | (x >>> (32 - n))); }
function ror32(value, count) { const n = count & 31; const x = u32(value); return u32((x >>> n) | (x << (32 - n))); }
function ror64(value, count) { const n = BigInt(count) & 63n; const x = BigInt.asUintN(64, BigInt(value)); return BigInt.asUintN(64, (x >> n) | (x << (64n - n))); }
function le32(value) { const b = Buffer.alloc(4); b.writeUInt32LE(u32(value)); return b; }
function be32(value) { const b = Buffer.alloc(4); b.writeUInt32BE(u32(value)); return b; }
function zigzag(value) { const n = BigInt(value); return n < 0n ? ((-n) * 2n - 1n) : n * 2n; }
function varint(value) { let n = BigInt(value); const out = []; while (n > 127n) { out.push(Number((n & 127n) | 128n)); n >>= 7n; } out.push(Number(n)); return Buffer.from(out); }
function protoField(tag, value, type = 'string') {
  if (value === undefined || value === null || value === '') return Buffer.alloc(0);
  if (type === 'bytes' || type === 'string' || type === 'message') {
    const body = type === 'bytes' ? Buffer.from(value) : type === 'message' ? value : Buffer.from(String(value));
    return Buffer.concat([varint((BigInt(tag) << 3n) | 2n), varint(body.length), body]);
  }
  if (type === 'float') { const body = Buffer.alloc(4); body.writeFloatLE(Number(value)); return Buffer.concat([varint((BigInt(tag) << 3n) | 5n), body]); }
  return Buffer.concat([varint(BigInt(tag) << 3n), varint(type === 'sint' ? zigzag(value) : value)]);
}
function proto(fields) { return Buffer.concat(fields.map(([tag, value, type]) => protoField(tag, value, type))); }
function getIv(iv, data) { let value = u32(iv); for (let i = 0; i < data.length; i += 1) { if ((i & 1) === 0) value = u32((value >>> 4) ^ value ^ (value << 6) ^ data[i]); else value = u32(~((value >>> 7) ^ value ^ (data[i] | (value << 12)))); } return value; }
function sumMd5(data) { let check = 0x20220420; for (let i = 0; i < 12; i += 1) { const temp = (i & 1) === 0 ? (check >>> 3) ^ check : (check >>> 5) ^ check; check = (i & 1) === 0 ? data[i] ^ (check << 7) : data[i] | (check << 11); if ((i & 1) !== 0) check = ~check; check = u32(check ^ temp); } return u32((check | 4) ^ 0x1000000); }
const BRANCH2_SV = [0xa7aefe20, 0x7149f1d6, 0x47e4ca07, 0xe9b58f67, 0x93b924de, 0xc614d0f5, 0x38afe0ef, 0xb2bbad73, 0xe24444c3, 0x9d3aec9b, 0xdf7b37e4, 0xd8b16d40, 0xf8ac31b8, 0x76b9a90b, 0x31d833ee, 0x953fce64, 0x353595a4, 0x4609c13b, 0x36925008, 0x8c6d0925, 0x5df5c177, 0x1cfbf52b, 0x8a4fa7f0, 0x114ca35e, 0x8193f984, 0x7a7a8733, 0x316ab4d5, 0x3c20cfc9, 0xa6d84453, 0x3a18500c, 0x798ec47a, 0x97a76b28, 0x66c4ff96, 0x51716443, 0xdd2fc3b, 0xb5696da7, 0xbbeb3ac5, 0x5c53d204, 0xd32608ce, 0x7279b9ec, 0xf4188ecf, 0xf7d793db, 0x332cc491, 0xab76ae15, 0x9bebe727, 0x18a01384, 0x5be9f8a7, 0x5f90a754, 0x39b663c0, 0x36673c83, 0x7c92f514, 0x9d7d94d7, 0xe2e8d9aa, 0x5f7e9ea9, 0x7abd4551, 0x569e05da, 0x40a25632, 0x3df5a9a5, 0xbab37d80, 0x454286dc, 0x3f5d4e78, 0x3d7b75d, 0xb1fe4af7, 0xa5ab26a3];
const BRANCH2_ORDERS = Buffer.from('0f0704000908030a060b050d0e010c020f05080c0009020103070e060b0a0d04060500070c000a04080f010b0d09020e060b02050403080101070a000d0c090e0d070e0f0b0208030c0509010004060a0d0902060f0b0a040807000c0503010e0c090f07060f030e020d0405010b0a000c050a090e0802040407030f01060b000b0f0408020a0700090d06010e03050c0b060a0508020c03070f0e090d0001040906080f050800040a0b030d01020c0e090d0c0604070a03030f00080105020e01000d0f090a0b0e0402080703060c0501080a0c0f0905060b000304020e070d04080f000c0f0e0d0a01060207090503040205080d0b0a0606000e0f070c09030a08040f000b01060d0c0709030e05020a070b050f00020e0108030d0c0609040d070f08050f06040b0a0e0c090002030d0c020704010b0e0e08060f09050003', 'hex');
function md5V3Step(kind, a, b, c, d, m, shift, constant) { let f; if (kind === 0) f = (b & c) | ((~b) & d); else if (kind === 1) f = (b & d) | (c & (~d)); else if (kind === 2) f = b ^ c ^ d; else f = c ^ (b | (~d)); return u32(b + rol32(u32(a + f + m + constant), shift)); }
function md5SumV3(message, countV2, orders, countV1) {
  const sv = BRANCH2_SV.map((value) => ror32(value, countV1)); const start = [ror32(0x79e0f2fb, countV2), ror32(0xc8b52570, countV2), ror32(0xebc2f8cd, countV2), ror32(0x7c104d93, countV2)]; const endCount = (countV2 + 6) & 255; const end = [ror32(0x19be4866, endCount), ror32(0xe85986b4, endCount), ror32(0xe19b326e, endCount), ror32(0x71d1d7d4, endCount)]; const m = []; for (let i = 0; i < 16; i += 1) m.push(message.readUInt32LE(i * 4)); let [a, b, c, d] = start;
  const run = (kind, order, shifts, offset) => { for (let i = 0; i < 16; i += 1) { const phase = i & 3; const next = phase === 0 ? md5V3Step(kind, a, b, c, d, m[orders[offset + i]], shifts[i], sv[offset + i]) : phase === 1 ? md5V3Step(kind, d, a, b, c, m[orders[offset + i]], shifts[i], sv[offset + i]) : phase === 2 ? md5V3Step(kind, c, d, a, b, m[orders[offset + i]], shifts[i], sv[offset + i]) : md5V3Step(kind, b, c, d, a, m[orders[offset + i]], shifts[i], sv[offset + i]); if (phase === 0) a = next; else if (phase === 1) d = next; else if (phase === 2) c = next; else b = next; } };
  run(0, orders, [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22], 0);
  run(1, orders, [5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20], 16);
  run(2, orders, [4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23], 32);
  run(3, orders, [6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21], 48);
  const ret = Buffer.alloc(16); ret.writeUInt32LE(u32((start[0] + a) ^ end[0]), 0); ret.writeUInt32LE(u32((start[1] + b) ^ end[1]), 4); ret.writeUInt32LE(u32((start[2] + c) ^ end[2]), 8); ret.writeUInt32LE(u32((start[3] + d) ^ end[3]), 12); return Buffer.concat([ret, le32(sumMd5(ret))]);
}
function branch2F13(iv, querySm3, bodyMd5, tsBytes, khronos) { const v = (iv & 13) * 86; const ivV0 = ((v >>> 15) & 255) + ((v >>> 8) & 255); const n1 = [0x8980f29b, 0xeb549c7f, 0xb08726db, 0xd40cb5e6, 0xe8f559e4][ivV0]; const countV1 = (n1 + khronos + 1) & 255; const countV2 = u32(n1 + khronos); const shift = (countV2 + 5) & 7; const seed = [0x84, 0x96, 0x77, 0x9d, 0xd4, 0x15, 0x0b, 0xf8]; const pad = Buffer.from(seed.map((value) => ((value | (value << 8)) >> shift) & 255)); const input = Buffer.concat([querySm3, bodyMd5, tsBytes, pad, Buffer.from('a0010000', 'hex')]); return md5SumV3(input, countV2, BRANCH2_ORDERS.subarray(ivV0 << 6, (ivV0 + 1) << 6), countV1); }
function bxor(a, b) { const out = Buffer.alloc(Math.min(a.length, b.length)); for (let i = 0; i < out.length; i += 1) out[i] = a[i] ^ b[i]; return out; }
function hashF13(querySm3, bodyMd5, tsBytes, khronos) {
  const iv = getIv(getIv(getIv(0x20230928, querySm3), bodyMd5), tsBytes); const low = iv & 15; const ivV0 = (low * 171) >> 9; const branch = low - ivV0 * 3;
  if (branch === 2) return branch2F13(iv, querySm3, bodyMd5, tsBytes, khronos);
  if (branch !== 0) return Buffer.concat([querySm3.subarray(0, 16), bodyMd5, le32(sumMd5(Buffer.concat([querySm3, bodyMd5])))]);
  const ivV1List = [0xc4a78580, 0xb3c0fd39, 0xc58c5686, 0xc9aa3ba7, 0xf5a7adf2, 0x963c2ed1]; const ivV1 = ivV1List[ivV0]; const countV1 = (ivV1 + khronos + 1) & 255; const countV2 = u32(ivV1 + khronos);
  const tt02 = [0xebb64faf, 0x7aadcc2, 0xcf3187bf, 0xe01138ff, 0x6d0bfcff, 0x5a30a3be, 0xb41ad638, 0x34180eb8, 0xf233eb6f, 0xb1a584cc, 0xccc30dc7, 0x47d1db51, 0xd55653de, 0x70a84fa1, 0x57473c12, 0xf76f0288, 0x2c077f0a, 0xda0dcad0, 0xfbb86f6c, 0xfdc4cf00, 0x688a020d, 0xe676c6a6, 0x8cd6338b, 0x1a3c8d0e, 0xcce8b06b, 0x6ad0ed0b, 0xa0522717, 0xdc71ac83, 0x2285db71, 0xd5b4dda6, 0x736f8650, 0x6560306c, 0x617ce2a6, 0xe423417e, 0xa40e143, 0x544e4032, 0x88dffb2a, 0x716c1ae0, 0x4c467a88, 0x5b23bb3, 0xe1d0b866, 0xbaa3dcb8, 0xae3374d3, 0xc3381a50, 0x1702f75b, 0xfe6da368, 0xf0b4cf48, 0x4e0ffbb8, 0x72aad10d, 0x26c53a3d, 0xf2bce0f6, 0xb4557581, 0x4a257fdd, 0x8c3182a2, 0xab0b3b86, 0x3d5dfb14, 0x4f103634, 0xd37b52d7, 0x444eff16, 0xeb0a33d1, 0x6ca86f6e, 0x284ba7, 0x8387cfa, 0x5fb37586];
  const tt = tt02.map((value) => ror32(value, countV1)); const n0 = (countV2 + 2) & 7; const seed = [0xfa, 0x45, 0x61, 0xd7]; const pad = Buffer.from(seed.map((value) => ((value | (value << 8)) >> n0) & 255));
  const data = Buffer.concat([querySm3, bodyMd5, tsBytes, pad, Buffer.from('00000000000001a0', 'hex')]); const di = []; for (let i = 0; i < data.length; i += 4) di.push(data.readUInt32BE(i)); let di0 = di[0]; for (let i = 0; i < 112; i += 1) { const di1 = di[i + 1]; const di14 = di[i + 14]; const r1 = rol32(di1, 14) ^ rol32(di1, 25) ^ (di1 >>> 3); const r2 = rol32(di14, 13) ^ rol32(di14, 15) ^ (di14 >>> 10); di.push(u32(di0 + di[i + 9] + r1 + r2)); di0 = di1; }
  const init = [0x7aba4fc8, 0x67166507, 0x6403fa00, 0x340f512f, 984304912, 3005047866, 2874125293, 2152413264].map((v) => ror32(v, countV2 & 31)); const chosen = [[101, 5, 7, 6, 3, 2, 1, 0, 5, 4, 3], [96, 0, 6, 7, 5, 3, 2, 1, 5, 4, 4], [96, 7, 6, 2, 1, 4, 0, 5, 4, 3, 5], [99, 3, 6, 2, 4, 5, 1, 0, 0, 7, 6], [96, 0, 5, 6, 7, 3, 1, 2, 5, 4, 4], [100, 2, 0, 3, 5, 4, 6, 7, 2, 1, 5]][ivV0]; let d = init.slice(); for (let i = 0; i < chosen[0]; i += 1) { const base = ivV1 + i; const n0v = di[base & 127]; const n1 = ((d[chosen[3]] ^ d[chosen[4]]) & d[chosen[1]]) ^ d[chosen[3]]; const n2 = rol32(d[chosen[1]], 26) ^ rol32(d[chosen[1]], 21) ^ rol32(d[chosen[1]], 7); const n4 = u32(n0v + n1 + n2 + tt[base & 63] + d[chosen[5]]); const n5 = rol32(d[chosen[2]], 30) ^ rol32(d[chosen[2]], 19) ^ rol32(d[chosen[2]], 10); const n6 = (d[chosen[2]] & d[chosen[6]]) | ((d[chosen[2]] | d[chosen[6]]) & d[chosen[7]]); const n7 = u32(n5 + n6); const old = d[chosen[9]]; d.unshift(d.pop()); d[chosen[10]] = u32(n7 + n4); d[chosen[8]] = u32(old + n4); }
  const ret = Buffer.alloc(32); for (let i = 0; i < 8; i += 1) ret.writeUInt32BE(u32(d[i] + init[i]), i * 4); const folded = bxor(ret.subarray(0, 16), ret.subarray(16)); folded.copy(ret, 0); return Buffer.concat([ret.subarray(0, 16), le32(sumMd5(ret.subarray(0, 16)))]);
}
function reverseBits(value) { let result = 0; for (let i = 0; i < 8; i += 1) result = (result << 1) | ((value >> i) & 1); return result; }
function rc4Gorgon(data, key) {
  const s = Array.from({ length: 256 }, (_v, i) => i); let j = 0;
  for (let i = 0; i < 256; i += 1) { j = (j + s[i] + key[i % key.length]) & 255; s[i] = s[j]; }
  let i = 0; j = 0;
  return Buffer.from(data.map((value) => { i += 1; const x = s[i]; j += x; const y = s[j & 255]; s[i] = y; return value ^ s[(y + y) & 255]; }));
}
function xGorgon(query, body, timestamp, random) {
  const sdk = Buffer.alloc(4); sdk.writeUInt32LE(67503104);
  const input = Buffer.concat([crypto.createHash('md5').update(query).digest().subarray(0, 4), body ? crypto.createHash('md5').update(body).digest().subarray(0, 4) : Buffer.alloc(4), Buffer.alloc(4), sdk, be32(timestamp)]);
  const key = [0x4a, 0x40, 0x16, (random >> 8) & 255, 0x47, 0x6c, 0x01, random & 255]; const out = rc4Gorgon([...input], key);
  for (let i = 0; i < out.length; i += 1) { let value = out[i]; value = ((value >> 4) | (value << 4)) & 255; const next = i + 1 < out.length ? out[i + 1] : out[0]; out[i] = (~(reverseBits((next ^ value) & 255) ^ 20)) & 255; }
  return Buffer.concat([Buffer.from('8404', 'hex'), Buffer.from([random & 255, (random >> 8) & 255, 0x40, 0x01]), out]).toString('hex');
}
function deviceProto(deviceId, version) { return proto([[1, 1, 'sint'], [2, 2, 'sint'], [3, '8662'], [4, deviceId], [5, 'Ai6svO3PyrwDOUSmO6ZcResxu'], [6, '!noperm!'], [7, -888888, 'sint'], [8, -888888, 'sint'], [9, 3, 'sint'], [10, -888888, 'sint'], [11, '!notset!'], [12, 'Asia/Shanghai,8'], [13, 'zh_CN'], [14, 4, 'sint'], [16, 255.24993896484375, 'float'], [17, 35.58599090576172, 'float'], [18, 3.467449188232422, 'float'], [19, 3.467449188232422, 'float'], [20, 255.1754913330078, 'float'], [21, 42.17544174194336, 'float'], [22, '16'], [23, 41, 'sint'], [24, 36, 'sint'], [25, 1728388016635, 'sint'], [26, 1728388016635, 'sint'], [27, 1728388016635, 'sint'], [28, 1728388016637, 'sint'], [29, -1, 'sint'], [30, '25053RT47C'], [31, 'Redmi'], [32, '25053RT47C'], [33, '25053RT47C'], [34, 'Xiaomi'], [35, 'Redmi'], [36, 'Redmi'], [38, 31, 'sint']]); }
const SBOX = Buffer.from('+n0Ia5xZs0sEXznQOEqRmQBnpiCf9U2Ccybu3xhmgzOAAxn72f6uqqmwUsYL83klTni0NqxdGieeiNu9PGPsSRXBMB/cuFbUbM3KCUPINaPvHvSW0vwOcnuUhNHqRVpiAj/TEoE0K91+5ijypUYTATsh9mE3KSoN7Yyvv51cuyR2D3XkU4nhmI2xmmVwT1RMWKtub4sjxAcRDLrPoKSO2AU9FLLadMPX577Wf95IFj6FkKFVt3dCIsmGUC4X+WQxLJvxbRxEaOPpqJOXyzJX6+Vxaq3AzMfF/WAdoi1Hp+JRaV56zgpBtpWP97mH4DoGEIq1+FvV8LyS/3wvwugbQOwb2r26mJEMsiuDQTRn+wrYdrVGBVlhI3WQhyrjUBVMrLF5667llUcEaPCGPVGLD8qO5LlO8hKCvA7V9+8oJc9bXelqVQLhM76T5/WtnT45JKji+hdX0HoNCDDWuKON/QeaxB5uImSX0h2wv0VmP2zd2yeApxHcpsVS+MC2yFwAc2B7oBkTqsk1SEvTpM2fmfMQREBUfin0Bh+iq6EvPPavhWI2IX9e3yAas7Tm/3KEj2UmlFp36kN4x0rMLBRrxuh0U/zUHM4xcAMYjJY4MonxOl/X+alpt2M3WMI7w3HLnpIBigtNiJu7T21v4P6lSd5WFgntnMEt7oF92XzRLkJbTcGmXepE/UVOG6E/0YnhfS+q26utWcuxzpooyeD2cDlK1/8w9d28VzsRjbLuALbmGlp8+d7EzS6Au7lMpZ+ECMZvQmzwJ+eLOpxR+2chdUExp8ogQyq3v9l68rX4jCwjg0+PYKAEEzcU4wHFY2ZcdIHfWL1okD3SszT0GZMyKdZJrg1L2AeerB4tC0C4crp2EHGo5FYdSP7lwkeR2ocmnR+Ia8CYviUJlzOjhRZef9xuVOn3qcjow3fQgivsAmKKkg4+sA8F8/GWeDiGNhg8JM8KtFPMYWWkx5TVFX5t73kiNRJqjlIGVXtGZFCV4gzt0xcDopuZ6xz8r9Rzafpf9ywev8jh8592gHFIqpStZPuJxmDDMrNN0uBE3V+oscdoIzTJbRJ/t+sVvqnReJOgDJKk10fjisJwqyZBmnmn2BSFj8BvVtCMEbkuPOKdzw7eA11GPs04Qw8zWtkaZWwiO/wwpojqN6K0jY5RnNZA7vn4hPSul+nKCkVnVwQvg1zVxcSCtqORmB9KrJaBbssbCQivGJVJfVTt+hYxOtq4ZvWl8f4QAQZ0zGPffCgl9s6yT4vlvIdpu4YhBwA25wtQWZsc6GJYGWHyvSdeuh3mmUI9DSq13Fsp8C1MU3tqc04/df9LoTUXVXI5INOw/e8C7Hd+5CvbkMEFnnrUUmskEw==', 'base64');
function xorBytes(a, b) { const out = Buffer.from(a); for (let i = 0; i < out.length; i += 1) out[i] ^= b[i % b.length]; return out; }
function matrix(bytes) { return Array.from({ length: 4 }, (_v, i) => Array.from(bytes.subarray(i * 4, i * 4 + 4))); }
function flat(rows) { return Buffer.from(rows.flat()); }
function aesMix(rows) { for (let i = 0; i < 4; i += 1) { const t = rows[0][i] ^ rows[1][i] ^ rows[2][i] ^ rows[3][i]; const u = rows[0][i]; const xt = (x) => ((x << 1) ^ ((x & 128) ? 0x1b : 0)) & 255; rows[0][i] ^= t ^ xt(rows[0][i] ^ rows[1][i]); rows[1][i] ^= t ^ xt(rows[1][i] ^ rows[2][i]); rows[2][i] ^= t ^ xt(rows[2][i] ^ rows[3][i]); rows[3][i] ^= t ^ xt(rows[3][i] ^ u); } }
class AesV3 {
  constructor(key, khronos) { this.wordSize = khronos & 3; this.box = SBOX.subarray(this.wordSize * 256, (this.wordSize + 1) * 256); this.con = [[1, 0, 2, 3], [1, 3, 0, 2], [0, 1, 3, 2], [1, 0, 2, 3]][this.wordSize]; this.con2 = [[1, 0, 2, 3], [2, 0, 3, 1], [0, 1, 3, 2], [1, 0, 2, 3]][this.wordSize]; this.order = [[0, 9, 14, 11, 4, 13, 2, 7, 8, 1, 6, 15, 12, 5, 10, 3], [0, 9, 14, 15, 4, 13, 2, 7, 8, 1, 6, 3, 12, 5, 10, 11], [0, 9, 14, 7, 4, 13, 2, 11, 8, 1, 6, 3, 12, 5, 10, 15], [0, 9, 14, 11, 4, 13, 2, 7, 8, 1, 6, 15, 12, 5, 10, 3]][this.wordSize]; const init = [0xca025ddc, 0x823dc546, 0xc9420583, 0xc298225f][this.wordSize]; const initial = Buffer.alloc(16); for (let i = 0; i < 4; i += 1)initial.writeUInt32LE(init, i * 4); const mk = xorBytes(initial, key); const expanded = Buffer.concat([mk, Buffer.alloc(32)]); let rounds = 8; for (let i = 4; i < 12; i += 1) { let at = 4 * (i - 1); let a = expanded[at], b = expanded[at + 1], c = expanded[at + 2], d = expanded[at + 3]; if ((i & 3) === 0) { const t = (u32(init >> ((rounds & 24))) ^ this.box[b]) & 255; b = this.box[c]; c = this.box[d]; d = this.box[a]; a = t; } rounds += 2; expanded[at + 4] = a ^ expanded[at - 12]; expanded[at + 5] = b ^ expanded[at - 11]; expanded[at + 6] = c ^ expanded[at - 10]; expanded[at + 7] = d ^ expanded[at - 9]; } this.keys = Array.from({ length: 12 }, (_v, i) => Array.from(expanded.subarray(i * 4, i * 4 + 4))); }
  add(rows, key) { for (let i = 0; i < 4; i += 1) for (let j = 0; j < 4; j += 1) rows[i][j] ^= key[i][j]; }
  addCon(rows, keys) { for (let i = 0; i < 4; i += 1) for (let j = 0; j < 4; j += 1) rows[i][j] ^= keys[i][this.con2[j]]; }
  sub(rows) { for (let i = 0; i < 4; i += 1) for (let j = 0; j < 4; j += 1) rows[i][j] = this.box[rows[i][j]]; const old = rows.map((x) => x.slice()); for (let i = 0; i < 4; i += 1) rows[i] = old[this.con2[i]]; }
  shift(rows) { const b = flat(rows); for (let i = 0; i < 16; i += 1) rows[Math.floor(i / 4)][i % 4] = b[this.order[i]]; }
  shiftCon(rows) { const old = rows.map((x) => x.slice()); for (let i = 0; i < 4; i += 1) rows[i] = this.con2.map((x) => old[i][x]); }
  block(value) { const rows = matrix(value); this.addCon(rows, this.keys.slice(0, 4)); for (let i = 1; i < 3; i += 1) { this.sub(rows); this.shift(rows); if (i === 1) { this.shiftCon(rows); aesMix(rows); } this.addCon(rows, this.keys.slice(i * 4)); } this.add(rows, this.keys.slice(4)); return flat(rows); }
  encrypt(data, iv) { const source = Buffer.from(data); const plaintext = Buffer.alloc(32); for (let i = 0; i < 31; i += 1) { const at = i * 8; const n0 = (source[at] >> 4) & 2; const n1 = n0 | (source[at + 1] & 64); const n2 = n1 | ((source[at + 2] >> 2) & 1); const n3 = n2 | ((source[at + 3] << 3) & 128); const n4 = n3 | ((source[at + 4] >> 1) & 4); const n5 = n4 | ((source[at + 5] << 3) & 16); const n6 = n5 | ((source[at + 6] << 5) & 32); plaintext[i] = n6 | ((source[at + 7] >> 4) & 8); } plaintext[31] = 1; const blocks = []; let previous = Buffer.from(iv); for (let i = 0; i < plaintext.length; i += 16) { const value = this.block(xorBytes(plaintext.subarray(i, i + 16), previous)); blocks.push(value); previous = value; } const key = Buffer.concat(blocks); const out = Buffer.from(source); for (let i = 0; i < 31; i += 1) { const at = i * 8; const k = key[i]; out[at] &= 0xdf; out[at] |= (k << 4) & 32; out[at + 1] &= 0xbf; out[at + 1] |= k & 64; out[at + 2] &= 0xfb; out[at + 2] |= (k << 2) & 4; out[at + 3] &= 0xef; out[at + 3] |= (k >> 3) & 16; out[at + 4] &= 0xf7; out[at + 4] |= (k + k) & 8; out[at + 5] &= 0xfd; out[at + 5] |= (k >> 3) & 2; out[at + 6] &= 0xfe; out[at + 6] |= (k >> 5) & 1; out[at + 7] &= 0x7f; out[at + 7] |= (k << 4) & 128; } return Buffer.concat([key.subarray(-1), out]); }
}
function xmxor(data, key) { const encoded = Buffer.alloc(data.length); for (let i = 0; i < data.length; i += 1) { const at = (i * 4) & 28; const d0 = key[at], d1 = key[at + 1]; let d2 = ((((data[i] << 4) | (data[i] >>> 4)) & 255) + d0); d2 = (~d2) ^ d1; d2 = ((((d2 & 255) << 3) | ((d2 & 255) >>> 5)) & 255); d2 = (d2 + d1) & 255; d2 = (d2 ^ d0) & 255; encoded[data.length - i - 1] = (~d2) & 255; } let last = encoded[encoded.length - 1] ^ encoded[encoded.length - 2]; const first = encoded[0]; encoded[0] = (~last + first) & 255; encoded[1] = ((encoded[0] ^ encoded[encoded.length - 1] ^ 254) + encoded[1]) & 255; encoded[2] = (encoded[2] + ((last - first) ^ (((encoded[1] << 3) | (encoded[1] >>> 5)) & 255) ^ 2)) & 255; for (let i = 0; i < encoded.length - 4; i += 1) { const temp = (((encoded[i + 2] << 3) | (encoded[i + 2] >>> 5)) & 255) ^ encoded[i + 1] ^ (i + 3); encoded[i + 3] = (~temp + encoded[i + 3]) & 255; } encoded[encoded.length - 1] ^= encoded[encoded.length - 2]; let sum = 0; for (let i = 0; i < encoded.length - 1; i += 1)sum += encoded[i + 1]; encoded[0] = ((encoded[0] ^ encoded[1]) + sum) & 255; return encoded; }
function keyHash(signKey, random) { const input = Buffer.concat([signKey, le32(random), signKey]); const hash = sm3(input); const d1 = (random >> 16) & 255; let d2 = ((d1 << 11) | (random >>> 24)) ^ (d1 >> 5) ^ d1; d2 = (~d2) >>> 0; return [hash, le32(d2)]; }
function buildMedusa(url, body, khronos) {
  const bodyMd5 = body ? crypto.createHash('md5').update(body).digest() : Buffer.alloc(16); const querySm3 = sm3(url.split('?')[1]); const ts = le32(khronos); const queryBodyTs = hashF13(querySm3, bodyMd5, ts, khronos); const nested = proto([[1, 111, 'sint'], [2, 10, 'sint'], [3, 694367, 'sint'], [5, 586952199, 'sint']]); const messageRand = Math.floor(Math.random() * 0x100000000); const envLaunch = Math.floor(Math.random() * 21) + 100; const envPid = Math.floor(Math.random() * 2000) + 10001; const env = proto([[1, envLaunch, 'sint'], [2, 146331399, 'sint'], [3, 146331396, 'sint'], [5, 7, 'sint'], [6, 'v04.06.04.03-bugfix'], [7, envPid, 'sint'], [12, deviceProto(DEVICE.device_id, DEVICE.version_name), 'message'], [13, proto([[1, Math.floor(Date.now() / 1000), 'sint'], [2, -2, 'sint'], [4, 200, 'sint']]), 'message'], [14, DEVICE.version_name]]); const queryHash = sm3(Buffer.concat([Buffer.from(url.split('?')[1]), bodyMd5, Buffer.from('none')])); const message = proto([[1, Buffer.from('f7e85ffad7d7dc3bd62ac87057cf6118', 'hex'), 'bytes'], [2, 3, 'sint'], [3, messageRand, 'sint'], [4, '8662'], [5, DEVICE.device_id], [6, '1588093228'], [7, DEVICE.version_name], [8, 'v04.06.04-ml-android'], [9, 67503104, 'sint'], [10, Buffer.from('4001000000000000', 'hex'), 'bytes'], [12, khronos, 'sint'], [13, queryBodyTs, 'bytes'], [14, querySm3.subarray(0, 6), 'bytes'], [15, nested, 'message'], [16, 'AXYQOS6n2m60x1fVZHIrH3iol'], [17, khronos, 'sint'], [19, queryHash, 'bytes'], [20, 'none'], [21, 312, 'sint'], [23, env, 'message'], [24, '{\"cmr\":16777216,\"cmr2\":16777216,\"un_h\":1879194040,\"vpn\":0,\"kd\":0,\"fkd\":3672518972,\"pd\":-1872573247,\"dyn\":\"\",\"do\":0,\"tk\":true}']]); const random = Math.floor(Math.random() * 0x100000000); const [hash, seed] = keyHash(Buffer.from('8ebdfa3806ecc5cee79423e6029ed82540bc2218bb7eae f71cb691f7aa8aa2f5'.replace(/ /g, ''), 'hex'), random); let transformed = xmxor(message, hash); transformed = Buffer.concat([Buffer.from('4001000000000000', 'hex'), transformed]).reverse(); for (let i = 0; i < transformed.length; i += 1)transformed[i] ^= seed[(~i) & 3]; const check = ((querySm3[0] & 63) << 14) | 0x18000001 | ((queryBodyTs[0] & 63) << 8); const xmRand = Math.floor(Math.random() * 0x100000000); const packed = Buffer.concat([Buffer.from([0x35]), le32(xmRand), le32(check), transformed, Buffer.from([random >> 16, random >> 24])]); const encrypted = new AesV3(Buffer.from('f1593376766ea98d34f31b057a9d5be4', 'hex'), khronos).encrypt(packed, Buffer.from('1fe109a4125283f418de9e051a969e12', 'hex')); const version = Buffer.from('03000000f7e85ffad7d7dc3bd62ac87057cf6118', 'hex'); const prefix = Buffer.alloc(20); for (let i = 0; i < 20; i += 4) prefix.writeUInt32LE(u32(version.readUInt32LE(i) ^ khronos), i); return Buffer.concat([prefix, Buffer.from([random & 255, (random >> 8) & 255, 0, 1]), encrypted]).toString('base64');
}
function helios(khronos) {
  const random = Math.floor(Math.random() * 0x100000000); const data = Buffer.concat([le32(random), Buffer.from('8662')]); const digest = crypto.createHash('md5').update(data).digest(); const ascii = Buffer.from(digest.toString('hex'), 'ascii'); const words = [];
  for (let i = 0; i < 4; i += 1) words.push(ascii.readBigUInt64LE(i * 8)); const table = [words[0]]; let b0 = words[0]; let b8 = words[1]; words.splice(0, 2);
  for (let i = 0; i < 34; i += 1) { let x8 = BigInt.asUintN(64, ror64(b8, 8) + b0); x8 = BigInt.asUintN(64, x8 ^ BigInt(i)); words.push(x8); x8 = BigInt.asUintN(64, x8 ^ ror64(b0, 61)); table.push(x8); b0 = x8; b8 = words.shift(); }
  const text = Buffer.from(`${khronos}-1588093228-8662`); const pad = Buffer.alloc(Math.ceil((text.length + 1) / 16) * 16, 16 - (text.length % 16)); text.copy(pad); const output = [];
  for (let at = 0; at < pad.length; at += 16) { let a = pad.readBigUInt64LE(at); let b = pad.readBigUInt64LE(at + 8); for (let i = 0; i < 34; i += 1) { b = BigInt.asUintN(64, table[i] ^ (a + ror64(b, 8))); a = BigInt.asUintN(64, b ^ ror64(a, 61)); } const block = Buffer.alloc(16); block.writeBigUInt64LE(a); block.writeBigUInt64LE(b, 8); output.push(block); }
  return Buffer.concat([le32(random), ...output]).toString('base64');
}

function branchOf(url, body, khronos) { const bodyMd5 = body ? crypto.createHash('md5').update(body).digest() : Buffer.alloc(16); const q = sm3(url.split('?')[1]); const iv = getIv(getIv(getIv(0x20230928, q), bodyMd5), le32(khronos)); const low = iv & 15; return low - (((low * 171) >> 9) * 3); }
async function signedAppGet(values) {
  const khronos = Math.floor(Date.now() / 1000); const ticket = Date.now();
  const query = pythonUrlEncode({ ...values, ts: String(khronos), _rticket: String(ticket) });
  const url = `${APP_SEARCH_API}?${query}`;
  const random = Math.floor(Math.random() * 65536); const body = null;
  const headers = {
    'User-Agent': APP_UA, Accept: 'application/json; charset=utf-8,application/x-protobuf',
    'x-ss-req-ticket': String(ticket), 'x-tt-request-tag': 't=0;n=0', 'sdk-version': '2',
    'passport-sdk-version': '50561', 'x-xs-from-web': '0', 'x-khronos': String(khronos),
    'x-ladon': be32(khronos).toString('base64'), 'x-argus': le32(khronos).toString('base64'),
    'x-gorgon': xGorgon(query, body, khronos, random), 'x-helios': helios(khronos),
    'x-medusa': buildMedusa(url, body, khronos), 'x-tt-dt': '',
  };
  const resp = await localHttp(url, { headers, timeout: 20000, responseType: 'text' });
  const data = jsonBody(resp.data);
  if (resp.status !== 200 || !data || Number(data.code) !== 0) {
    const reason = data ? (data.message || data.code || resp.status) : `${resp.status} 空响应`;
    throw new Error(`App search failed: ${reason}`);
  }
  return data;
}

function videoModelUrl() { const query = new URLSearchParams({ ...DEVICE }); return `${VIDEO_API}?${query}`; }

function signedVideoRequest(payload) {
  const khronos = Math.floor(Date.now() / 1000); const body = Buffer.from(payload); const ticketBase = Date.now(); let requestTicket = ticketBase; let query = ''; let url = '';
  // branch 1 的签名变体服务端不认：抖动 _rticket 找一个可用的 branch（最多试 32 秒偏移）
  for (let offset = 0; offset < 32; offset += 1) { requestTicket = ticketBase + offset; const values = { ...DEVICE, ts: String(khronos), _rticket: String(requestTicket) }; query = pythonUrlEncode(values); url = `${VIDEO_API}?${query}`; if (branchOf(url, body, khronos) !== 1) break; }
  const random = Math.floor(Math.random() * 65536); const headers = {
    'User-Agent': VIDEO_UA, Accept: 'application/json; charset=utf-8,application/x-protobuf', 'Content-Type': 'application/json; charset=UTF-8',
    'x-xs-from-web': '0', 'x-ss-req-ticket': String(requestTicket), 'x-tt-request-tag': 't=0;n=0', 'sdk-version': '2', 'passport-sdk-version': '50561',
    'x-vc-bdturing-sdk-version': '3.7.2.cn', 'x-ss-stub': md5(body), 'x-gorgon': xGorgon(query, body, khronos, random),
    'x-khronos': String(khronos), 'x-ladon': be32(khronos).toString('base64'), 'x-argus': le32(khronos).toString('base64'),
    'x-helios': helios(khronos), 'x-medusa': buildMedusa(url, body, khronos), 'x-tt-dt': '',
  };
  return { url, headers, body };
}

async function requestVideoModel(vid) {
  const payload = JSON.stringify({
    biz_param: { detail_page_version: 0, device_level: 3, disable_digg_stat: false, need_all_video_definition: true, need_mp4_align: false, use_os_player: false, use_server_dns: false, video_platform: 1024 },
    mixed_video_id_map: { '1004': [str(vid)] },
  });
  let lastError = 'unknown';
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const signed = signedVideoRequest(payload);
    const resp = await localHttp(signed.url, { method: 'POST', data: signed.body, headers: signed.headers, timeout: 20000, responseType: 'text' });
    const data = jsonBody(resp.data);
    if (resp.status === 200 && data && Number(data.Code || data.code || 0) === 0) return data;
    lastError = data?.Message || data?.message || resp.status;
    DEVICE = { ...DEVICE, iid: randomDeviceId(), device_id: randomDeviceId() };
  }
  throw new Error(`video_model failed after device rotation: ${lastError}`);
}

function modelForVideo(data, vid) {
  const map = data?.data || {};
  const entry = map[str(vid)] || Object.values(map).find((value) => value && typeof value === 'object');
  if (!entry) throw new Error('video_model 没有对应视频');
  const model = typeof entry.video_model === 'string' ? jsonBody(entry.video_model) : entry.video_model;
  if (!model) throw new Error('video_model 内容为空');
  return model;
}

function parseFallback(value) {
  if (typeof value === 'string') { const parsed = jsonBody(value); return parsed?.fallback_api || value; }
  if (Array.isArray(value)) return str(value[0]);
  return str(value?.fallback_api);
}

function qualityNumber(value) {
  const text = str(value); const match = text.match(/(2160|1440|1080|720|576|540|480|360)/);
  if (match) return Number(match[1]);
  return ({ '1920': 1080, '1280': 720, '1024': 576, '854': 480, '640': 360 })[text] || (/^\d{3,4}$/.test(text) ? Number(text) : 0);
}
function qualityLabel(value) {
  const n = qualityNumber(value); if (n) return `${n}P`;
  const labels = { low: '流畅', smooth: '流畅', medium: '标清', normal: '高清', high: '超清', original: '原画', uhd: '原画', super_high: '原画' };
  return labels[str(value).toLowerCase()] || str(value, '自动');
}
function qualityRows(videoList) {
  const rows = [];
  if (!videoList || typeof videoList !== 'object') return rows;
  for (const [key, value] of Object.entries(videoList)) {
    const item = value && typeof value === 'object' ? value : {};
    const quality = str(item.quality_desc || item.height || item.vheight || item.quality || key);
    if (item.main_url && !rows.some((row) => row.quality === key)) rows.push({ key, quality, item });
  }
  return rows.sort((a, b) => qualityNumber(b.quality || b.key) - qualityNumber(a.quality || a.key));
}

async function fetchVideoInfo(vid) {
  const cached = videoInfoCache.get(str(vid));
  if (cached && Date.now() - cached.time < 300000) return cached.value;
  const model = modelForVideo(await requestVideoModel(vid), vid);
  const fallback = parseFallback(model.fallback_api);
  if (!fallback) throw new Error('fallback_api 为空');
  const outer = jsonBody(await getText(fallback));
  const info = outer?.video_info?.data || {};
  const value = { model, info, rows: qualityRows(info.video_list) };
  videoInfoCache.set(str(vid), { time: Date.now(), value });
  return value;
}

// ---------- spade URL 解密与 CENC 内容密钥 ----------

function deriveContentKey(value) {
  const raw = Buffer.from(str(value).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  if (raw.length < 3) throw new Error('spade_a too short');
  let v8 = raw.length - (raw[0] ^ raw[1] ^ raw[2]) + 47;
  v8 = Math.min(v8, raw.length - 1);
  if (v8 < 33) throw new Error('spade_a key length invalid');
  const work = Buffer.from(raw.subarray(1, 1 + v8)); let a = 85; let b = 246;
  for (let i = 0; i < v8; i += 1) {
    const old = work[i]; const previous = i & 1 ? a : b;
    if (i & 1) a = old; else b = old;
    const pop = i.toString(2).split('1').length - 1;
    work[i] = (-21 - pop + (previous ^ old)) & 255;
  }
  return Buffer.from(work.subarray(1, 33).toString('ascii'), 'hex');
}

function decryptSpadeUrl(value, seed) {
  const encoded = str(value); if (!encoded) return '';
  const raw = Buffer.from(encoded, 'base64');
  if (raw.length < 5) throw new Error('spade URL ciphertext too short');
  if (raw[0] !== 0xa8 || raw[2] !== 0x01 || raw[3] !== 0x00) throw new Error('spade URL header format error');
  const cipherLength = Math.floor((raw.length - 4) / 16) * 16;
  if (!cipherLength) throw new Error('spade URL ciphertext has no complete block');
  const constants = Buffer.from('4dd4c2e6b83162090e52b3c7a6733ba41cb2462b829ab58a196b39db57177524f49baf7f08e8d68d26a72e37c1a95a2f1f05a51892aef2949732b62a38aadd58', 'hex');
  const h1 = crypto.createHash('sha512').update(seed).digest(); const h2 = crypto.createHash('sha512').update(Buffer.concat([h1, constants])).digest();
  const decipher = crypto.createDecipheriv('aes-128-cbc', h2.subarray(0, 16), h2.subarray(16, 32));
  decipher.setAutoPadding(false);
  let plaintext = Buffer.concat([decipher.update(raw.subarray(4, 4 + cipherLength)), decipher.final()]);
  if (plaintext.length) {
    const padding = plaintext[plaintext.length - 1];
    if (padding >= 1 && padding <= 16 && padding <= plaintext.length) plaintext = plaintext.subarray(0, plaintext.length - padding);
  }
  while (plaintext.length && plaintext[plaintext.length - 1] === 0) plaintext = plaintext.subarray(0, plaintext.length - 1);
  return plaintext.toString('utf8');
}

// ---------- CENC(MP4) 索引解析与分段解密 ----------

function readBox(data, offset) {
  if (offset < 0 || offset + 8 > data.length) return null;
  let size = data.readUInt32BE(offset); const type = data.toString('ascii', offset + 4, offset + 8);
  let header = 8;
  if (size === 1) {
    if (offset + 16 > data.length) return null;
    const large = data.readBigUInt64BE(offset + 8); if (large > BigInt(Number.MAX_SAFE_INTEGER)) return null;
    size = Number(large); header = 16;
  } else if (size === 0) size = data.length - offset;
  if (size < header || offset + size > data.length) return null;
  return { offset, size, type, header, bodyStart: offset + header };
}

function findBox(data, type, start = 0) {
  for (let offset = Math.max(0, start); offset + 8 <= data.length; offset += 1) {
    const box = readBox(data, offset);
    if (box?.type === type) return box;
  }
  return null;
}

function boxBody(data, type, start = 0) {
  const box = findBox(data, type, start); return box ? data.subarray(box.bodyStart, box.offset + box.size) : null;
}

function readU64(data, offset) {
  const value = data.readBigUInt64BE(offset); if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('MP4 offset too large');
  return Number(value);
}

function parseTrack(moov, track) {
  const stbl = findBox(moov, 'stbl', track.bodyStart); if (!stbl) return null;
  const stsz = boxBody(moov, 'stsz', stbl.bodyStart); const stsc = boxBody(moov, 'stsc', stbl.bodyStart);
  const chunkBox = findBox(moov, 'stco', stbl.bodyStart) || findBox(moov, 'co64', stbl.bodyStart);
  const saiz = boxBody(moov, 'saiz', stbl.bodyStart); const saio = boxBody(moov, 'saio', stbl.bodyStart);
  if (!stsz || !stsc || !chunkBox || !saiz || !saio || stsz.length < 12 || stsc.length < 8 || saiz.length < 9 || saio.length < 8) return null;
  const defaultSampleSize = stsz.readUInt32BE(4); const sampleCount = stsz.readUInt32BE(8); const sizes = [];
  if (defaultSampleSize) sizes.push(...Array(sampleCount).fill(defaultSampleSize));
  else for (let i = 0; i < sampleCount && 12 + (i + 1) * 4 <= stsz.length; i += 1) sizes.push(stsz.readUInt32BE(12 + i * 4));
  if (sizes.length !== sampleCount) return null;
  const chunkCount = chunkBox.bodyStart + 8 <= chunkBox.offset + chunkBox.size ? moov.readUInt32BE(chunkBox.bodyStart + 4) : 0;
  const offsets = [];
  for (let i = 0; i < chunkCount; i += 1) {
    const at = chunkBox.bodyStart + 8 + i * (chunkBox.type === 'co64' ? 8 : 4);
    if (at + (chunkBox.type === 'co64' ? 8 : 4) > chunkBox.offset + chunkBox.size) return null;
    offsets.push(chunkBox.type === 'co64' ? readU64(moov, at) : moov.readUInt32BE(at));
  }
  const entryCount = stsc.readUInt32BE(4); const entries = [];
  for (let i = 0; i < entryCount; i += 1) {
    const at = 8 + i * 12; if (at + 8 > stsc.length) return null;
    entries.push({ firstChunk: stsc.readUInt32BE(at), samplesPerChunk: stsc.readUInt32BE(at + 4) });
  }
  const samplesPerChunk = offsets.map((_value, index) => {
    let selected = 0; for (const entry of entries) if (entry.firstChunk <= index + 1) selected = entry.samplesPerChunk; return selected;
  });
  const auxDefault = saiz[4]; const auxCount = saiz.readUInt32BE(5); const auxSizes = [];
  if (auxDefault) auxSizes.push(...Array(auxCount).fill(auxDefault));
  else for (let i = 0; i < auxCount && 9 + i < saiz.length; i += 1) auxSizes.push(saiz[9 + i]);
  if (auxSizes.length !== auxCount) return null;
  const saioVersion = saio.readUInt32BE(0) >>> 24; const offsetSize = saioVersion === 1 ? 8 : 4;
  const saioCount = saio.readUInt32BE(4); if (!saioCount || 8 + offsetSize > saio.length) return null;
  const auxOffset = offsetSize === 8 ? readU64(saio, 8) : saio.readUInt32BE(8);
  return { sizes, offsets, samplesPerChunk, auxOffset, auxSizes, sampleCount };
}

function buildSamples(data, tracks) {
  const samples = [];
  for (const track of tracks) {
    let sampleIndex = 0; let auxPos = 0;
    const auxTotal = track.auxSizes.reduce((sum, size) => sum + Math.max(size, 8), 0);
    if (track.auxOffset < 0 || track.auxOffset + auxTotal > data.length) throw new Error('MP4 auxiliary data out of range');
    const aux = data.subarray(track.auxOffset, track.auxOffset + auxTotal);
    for (let chunk = 0; chunk < track.offsets.length && sampleIndex < track.sampleCount; chunk += 1) {
      let offset = track.offsets[chunk]; const count = track.samplesPerChunk[chunk] || 0;
      for (let index = 0; index < count && sampleIndex < track.sampleCount; index += 1) {
        const size = track.sizes[sampleIndex]; const auxSize = Math.max(track.auxSizes[sampleIndex] || 8, 8);
        if (offset + size > Number.MAX_SAFE_INTEGER || auxPos + auxSize > aux.length) throw new Error('MP4 sample index out of range');
        const iv = Buffer.alloc(16); aux.copy(iv, 0, auxPos, auxPos + Math.min(8, auxSize));
        samples.push({ start: offset, end: offset + size, iv }); offset += size; sampleIndex += 1; auxPos += auxSize;
      }
    }
  }
  return samples.sort((a, b) => a.start - b.start);
}

function replaceFourcc(data, from, to) {
  let offset = 0; const source = Buffer.from(from);
  while ((offset = data.indexOf(source, offset)) >= 0) { data.write(to, offset, 'ascii'); offset += source.length; }
}

function replaceSinf(data) {
  let offset = 0;
  while ((offset = data.indexOf(Buffer.from('sinf'), offset)) >= 0) {
    if (offset < 4) { offset += 4; continue; }
    const size = data.readUInt32BE(offset - 4); const end = offset - 4 + size;
    if (size >= 8 && size < 50000 && end <= data.length) { data.write('free', offset, 'ascii'); data.fill(0, offset + 4, end); offset = end; }
    else offset += 4;
  }
}

function prepareCencHeader(data, key) {
  const ftypSize = data.readUInt32BE(0); const moov = readBox(data, ftypSize);
  if (!moov || moov.type !== 'moov') throw new Error('invalid MP4 moov');
  const moovBody = data.subarray(moov.bodyStart, moov.offset + moov.size); const tracks = [];
  let cursor = 0; while (true) { const track = findBox(moovBody, 'trak', cursor); if (!track) break; tracks.push(track); cursor = track.offset + track.size; }
  const parsed = tracks.map((track) => parseTrack(moovBody, track)).filter(Boolean);
  const samples = key ? buildSamples(data, parsed) : [];
  const header = Buffer.from(data.subarray(0, moov.offset + moov.size));
  replaceFourcc(header, 'encv', 'hvc1'); replaceFourcc(header, 'enca', 'mp4a'); replaceSinf(header);
  return { header, samples };
}

function addCounter(iv, blocks) {
  const value = (iv.readBigUInt64BE(0) << 64n) | iv.readBigUInt64BE(8); const next = (value + BigInt(blocks)) & ((1n << 128n) - 1n);
  const result = Buffer.alloc(16); result.writeBigUInt64BE(next >> 64n, 0); result.writeBigUInt64BE(next & ((1n << 64n) - 1n), 8); return result;
}

function decryptPartial(data, start, key, prepared) {
  const output = Buffer.from(data); const end = start + output.length;
  if (start < prepared.header.length) prepared.header.copy(output, 0, start, Math.min(end, prepared.header.length));
  if (!key) return output;
  let index = 0; while (index < prepared.samples.length && prepared.samples[index].end <= start) index += 1;
  for (; index < prepared.samples.length; index += 1) {
    const sample = prepared.samples[index]; if (sample.start >= end) break;
    const overlapStart = Math.max(start, sample.start); const overlapEnd = Math.min(end, sample.end); if (overlapStart >= overlapEnd) continue;
    const relative = overlapStart - sample.start; const block = Math.floor(relative / 16); const skip = relative % 16;
    const decipher = crypto.createDecipheriv('aes-128-ctr', key, addCounter(sample.iv, block));
    if (skip) decipher.update(Buffer.alloc(skip));
    const decrypted = Buffer.concat([decipher.update(output.subarray(overlapStart - start, overlapEnd - start)), decipher.final()]);
    decrypted.copy(output, overlapStart - start);
  }
  return output;
}

// ---------- 播放流解析与 Range 代理 ----------

async function resolveStream(vid, quality) {
  const cacheKey = playKey(vid, quality); const cached = streamCache.get(cacheKey); if (cached && Date.now() - cached.time < 300000) return cached.value;
  const { info, rows } = await fetchVideoInfo(vid); const wanted = str(quality, 'auto');
  const selected = rows.find((row) => row.key === wanted || qualityNumber(row.quality) === qualityNumber(wanted)) || rows[0]; if (!selected) throw new Error('没有可用清晰度');
  let url = cleanUrl(selected.item.main_url); const seed = Buffer.from(str(info.key_seed), 'base64');
  if (seed.length && url) url = decryptSpadeUrl(url, seed);
  const result = { url, quality: qualityLabel(selected.quality || selected.key), key: selected.item.spade_a ? deriveContentKey(selected.item.spade_a) : null };
  streamCache.set(cacheKey, { time: Date.now(), value: result }); return result;
}

async function remoteRange(stream, start, end) {
  try {
    return await remoteRangeOnce(stream, start, end, stream.finalUrl || stream.url);
  } catch (e) {
    // 缓存的重定向地址可能因签名失效过期，清掉后回原始 url 重新跟随一次
    if (stream.finalUrl) { stream.finalUrl = null; return await remoteRangeOnce(stream, start, end, stream.url); }
    throw e;
  }
}
async function remoteRangeOnce(stream, start, end, initialUrl) {
  const headers = { 'User-Agent': VIDEO_UA, Referer: 'https://novel.snssdk.com/', Range: `bytes=${start}-${end}` };
  let mediaUrl = initialUrl;
  let resp;
  for (let redirect = 0; redirect < 6; redirect += 1) {
    resp = await localHttp(mediaUrl, { headers, timeout: 30000, responseType: 'arraybuffer', redirect: false });
    if (![301, 302, 303, 307, 308].includes(Number(resp.status))) break;
    const location = headerValue(resp.headers, 'location');
    if (!location) break;
    mediaUrl = new URL(location, mediaUrl).href;
  }
  // 缓存重定向后的真实 CDN 地址（播放期内有效），后续 1MB 段直接命中，省掉每段重复重定向
  if (mediaUrl && mediaUrl !== stream.url) stream.finalUrl = mediaUrl;
  let data = Buffer.from(resp.data);
  const contentRange = headerValue(resp.headers, 'content-range');
  let total = Number((contentRange.match(/\/(\d+)$/) || [])[1] || 0);
  if (resp.status !== 200 && resp.status !== 206) throw new Error(`CDN Range 请求失败: HTTP ${resp.status}`);
  if (resp.status === 200 && !contentRange) {
    total = total || Number(headerValue(resp.headers, 'content-length') || data.length);
    if (data.length > end - start + 1) data = data.subarray(start, end + 1);
  }
  const expected = end - start + 1;
  if (data.length !== expected) throw new Error(`CDN Range 长度异常: ${data.length}/${expected}`);
  return { data, total };
}

// 预取 ftyp+moov 并建 CENC 样本索引（结果挂在 stream 上随 streamCache 缓存）
async function prepareHeader(stream) {
  if (stream.prepared) return stream.prepared;
  if (!stream.preparePromise) stream.preparePromise = (async () => {
    const firstEnd = 256 * 1024 - 1; const first = await remoteRange(stream, 0, firstEnd); let head = first.data;
    const total = first.total || head.length; if (head.length < 16) throw new Error('MP4 头过短');
    const ftypSize = head.readUInt32BE(0); if (ftypSize < 8 || ftypSize + 8 > head.length) throw new Error('MP4 ftyp 异常');
    if (head.toString('ascii', 4, 8) !== 'ftyp' || head.toString('ascii', ftypSize + 4, ftypSize + 8) !== 'moov') throw new Error('MP4 moov 定位失败: ' + head.subarray(0, 32).toString('hex'));
    const moovSize = head.readUInt32BE(ftypSize); const moovEnd = ftypSize + moovSize;
    if (moovSize < 8 || moovEnd > total || moovEnd > 8 * 1024 * 1024) throw new Error(`MP4 moov 异常: ${moovSize}`);
    if (moovEnd > head.length) {
      const extra = await remoteRange(stream, head.length, moovEnd - 1);
      head = Buffer.concat([head, extra.data]);
    }
    head = head.subarray(0, moovEnd);
    const p = stream.key ? prepareCencHeader(head, stream.key) : { header: head, samples: [] };
    stream.prepared = { total, header: p.header, samples: p.samples };
    return stream.prepared;
  })();
  try { return await stream.preparePromise; } finally { delete stream.preparePromise; }
}

function parseRangeHeader(value, total) {
  const match = str(value).match(/^bytes=(\d*)-(\d*)/i); if (!match) return null;
  let start; let end;
  if (!match[1]) { const length = Math.min(total, Number(match[2])); if (!length) return 'invalid'; start = total - length; end = total - 1; }
  else { start = Number(match[1]); end = match[2] ? Number(match[2]) : total - 1; }
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || start >= total || start > end) return 'invalid';
  return [start, Math.min(end, total - 1)];
}

// ---------- 秒播缓存：1MB 对齐分段 / 首段预热 / 段内预读 ----------
// 取第 segIndex 个 1MB 对齐段的明文：命中缓存直接返回，否则拉取+解密并写缓存。
// 所有预热/播放/预读都走同一套对齐段，保证预热的数据播放时 100% 命中。
async function fetchSegment(vid, quality, stream, prepared, segIndex) {
  const total = prepared.total;
  const segStart = segIndex * SEG_SIZE;
  if (segStart >= total) return null;
  const segEnd = Math.min(segStart + SEG_SIZE - 1, total - 1);
  const key = segKey(vid, quality, segIndex);
  if (segCache.has(key)) return cacheTouch(key);
  if (segPending.has(key)) return segPending.get(key);
  const p = (async () => {
    const headLen = prepared.header ? prepared.header.length : 0;
    const chunks = [];
    let cursor = segStart;
    // 落在明文 moov 头内的部分直接复用 prepareHeader 已解析的头，避免重复拉取/解密
    if (segStart < headLen) {
      const headTo = Math.min(segEnd + 1, headLen);
      chunks.push(prepared.header.subarray(segStart, headTo));
      cursor = headTo;
    }
    if (cursor <= segEnd) {
      const rr = await remoteRange(stream, cursor, segEnd);
      chunks.push(decryptPartial(rr.data, cursor, stream.key, prepared));
    }
    const row = { start: segStart, end: segEnd, total, data: Buffer.concat(chunks), at: Date.now() };
    segCache.set(key, row);
    cacheTrim();
    return row;
  })();
  segPending.set(key, p);
  try { return await p; } finally { segPending.delete(key); }
}

// 预热一集：准备 moov，并缓存足够播放器首次响应的连续启动段。
// 不再后台下载整集，防止下一集预取反过来挤占当前播放带宽。
async function warmEpisode(vid, quality) {
  vid = String(vid);
  const stream = await resolveStream(vid, quality);
  const prepared = await prepareHeader(stream);
  // 播放线路传入的通常是 video_5/video_4 这类内部 key，不能直接判断画质。
  // resolveStream 已经把它还原为 1080P/720P，必须按真实画质决定预热量，
  // 否则 1080P 只会预热 2MB，而播放器首请求需要 4MB，切集仍会现场补数据。
  const qn = qualityNumber(stream.quality || quality);
  const wanted = qn >= 1080 ? 4 : (qn >= 720 ? 3 : 2);
  const limit = Math.min(Math.ceil(prepared.total / SEG_SIZE), wanted);
  for (let idx = 0; idx < limit; idx += 1) {
    await fetchSegment(vid, quality, stream, prepared, idx);
    if (idx > 0) await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

// 冷启动最多等待 1.5 秒让启动段就绪；已预热的下一集会立即返回。
// 超时后任务继续在后台执行，不让插件调用触碰客户端时限。
async function waitStartup(vid, quality, timeoutMs = 1500) {
  const task = warmEpisode(vid, quality);
  bg(task);
  await Promise.race([
    task.catch(() => null),
    new Promise((resolve) => setTimeout(resolve, timeoutMs)),
  ]);
}

// 当前集播放时，后台向前预读接下来的 READ_AHEAD_SEGS 个 1MB 段（治播放中频繁转圈）
function scheduleReadAhead(vid, quality, stream, prepared, fromSeg) {
  for (let k = 1; k <= READ_AHEAD_SEGS; k += 1) {
    const idx = fromSeg + k;
    if (idx * SEG_SIZE >= prepared.total) break;
    const key = segKey(vid, quality, idx);
    if (segCache.has(key) || segPending.has(key)) continue;
    bg(fetchSegment(vid, quality, stream, prepared, idx));
  }
}

// 把当前集后面 PREFETCH_EPISODES 集加入串行预热队列（每集只预热首段 1MB）
function scheduleEpisodeWarm(vid, quality) {
  const nexts = episodeNext.get(String(vid)) || [];
  for (let i = 0; i < nexts.length; i += 1) {
    const nvid = String(nexts[i]);
    const key = nvid + '|' + String(quality);
    if (!episodeQueued.has(key)) { episodeQueued.add(key); episodeQueue.push({ vid: nvid, quality: String(quality) }); }
  }
  drainEpisodeQueue();
}
function drainEpisodeQueue() {
  if (episodeActive) return;
  const job = episodeQueue.shift();
  if (!job) return;
  episodeActive = true;
  const finish = () => {
    episodeQueued.delete(String(job.vid) + '|' + String(job.quality));
    episodeActive = false;
    setTimeout(drainEpisodeQueue, WARM_PAUSE_MS);
  };
  warmEpisode(job.vid, job.quality).then(finish, finish);
}

function setResult(value) { return Array.isArray(value) ? value : []; }
function log(value) { try { console.log('[好哥哥16]', value); } catch (e) { } }

// ---------- DS rule ----------

var rule = {
  title: '🍎红果·苹果·秒播优化',
  host: SITE,
  // 惯例占位：drpyS 前置 parse（searchParse/cateParse）在 searchUrl/url 缺失时直接放弃调用源方法（返回空对象）
  url: '/category',
  searchUrl: '/search/**',
  play_parse: true,
  play_json: [{ re: '*', json: {} }],
  searchable: 1,
  filterable: 1,
  quickSearch: 1,
  class_parse: async function () {
    return { class: CATEGORIES, filters: FILTERS };
  },
  推荐: async function () {
    try {
      const data = await categoryPage('sort_type=1');
      return setResult(categoryData(data).slice(0, 12).map(itemToCard));
    } catch (e) {
      log('红果果推荐出错: ' + e.message);
      return setResult([]);
    }
  },
  一级: async function (tid, pg, filter, extend) {
    const page = pageNumber(pg);
    const rawId = str(tid || 'short');
    const typeId = categoryType(rawId);
    const config = CATEGORY_CONFIG[typeId];
    const requestedFilters = filterValues(extend);
    try {
      if (config.kind === 'category' || config.kind === 'app') {
        const rows = await currentCategoryPage(typeId, page);
        if (rows.length) return setResult(rows.map(itemToCard).filter((item) => item.url && item.title));
      }
      if (config.kind === 'app') {
        let result;
        try { result = await appCategoryPage(typeId, config, requestedFilters, page); } catch (e) { result = null; }
        if (result && result.list.length) return setResult(result.list);
        const fallback = await rankPage(config.fallback, page);
        return setResult(fallback.list);
      }
      if (config.kind === 'rank') {
        return setResult(await currentRankPage(config.route, page));
      }
      const query = new URLSearchParams(config.query);
      if (rawId.includes('=') && !CATEGORY_CONFIG[rawId]) {
        const requested = new URLSearchParams(rawId.replace(/^category\?/, ''));
        for (const [key, value] of requested) query.set(key, value);
      }
      for (const [key, value] of Object.entries(requestedFilters)) query.set(key, value);
      const data = await categoryPage(query.toString(), page);
      return setResult(categoryData(data).map(itemToCard));
    } catch (e) {
      log('红果果一级出错: ' + e.message);
      return setResult([]);
    }
  },
  二级: async function () {
    const { orId } = this;
    const id = str(Array.isArray(orId) ? orId[0] : orId);
    if (!id) return { list: [] };
    try {
      const data = await routerData(`${SITE}/detail?series_id=${encodeURIComponent(id)}`);
      const series = data?.loaderData?.detail_page?.seriesDetail || {};
      const vids = (series.vid_list || []).map(str).filter(Boolean);
      if (!vids.length) return { list: [] };
      // 建立“当前集 → 后面 PREFETCH_EPISODES 集”的关系，播放时据此串行预热后10集首段
      vids.forEach((v, i) => { episodeNext.set(String(v), vids.slice(i + 1, i + 1 + PREFETCH_EPISODES).map(String)); });
      let rows = [];
      try { rows = (await fetchVideoInfo(vids[0])).rows; } catch (e) { }
      // 用户停留在详情页时提前准备默认最高画质的首集启动段。
      // 点击播放时大概率已经命中，不再把全部准备工作压到播放器首个请求。
      if (rows.length) bg(warmEpisode(vids[0], rows[0].key));
      const sources = (rows.length ? rows : [{ key: 'auto', quality: 'auto' }])
        .map((row) => ({ name: qualityLabel(row.quality || row.key), episodes: vids.map((vid, index) => `第${index + 1}集$${playKey(vid, row.key)}`).join('#') }));
      // 二级不经 setResult 转换，直接返回 vod_* 完整对象
      const categoryList = Array.isArray(series.category_list) ? series.category_list.map((v) => v?.name || v).filter(Boolean) : [];
      const tags = Array.isArray(series.tags) ? series.tags : categoryList;
      const count = Number(series.episode_cnt || series.series_episode_info?.episode_cnt || 0);
      return {
        vod_id: id,
        vod_name: str(series.series_name || series.series_title),
        vod_pic: cleanUrl(series.series_cover),
        vod_remarks: str(series.episode_right_text) || (count ? `全${count}集` : ''),
        type_name: tags.slice(0, 5).join('/'),
        vod_content: str(series.series_intro),
        vod_play_from: sources.map((source) => source.name).join('$$$'),
        vod_play_url: sources.map((source) => source.episodes).join('$$$'),
      };
    } catch (e) {
      log('红果果二级出错: ' + e.message);
      return { vod_id: id, vod_name: '详情获取失败', vod_play_from: '红果', vod_play_url: '' };
    }
  },
  搜索: async function (key, quick, pg) {
    const page = pageNumber(pg);
    const word = str(key);
    if (!word) return setResult([]);
    try {
      const app = await appSearchPage(word, 11, page, 20);
      if (app.list.length) return setResult(app.list);
    } catch (e) {
      log('红果果App搜索失败回退官网: ' + e.message);
    }
    try {
      const web = await webSearchPage(word, page);
      if (web.list.length) return setResult(web.list);
    } catch (e) {
      log('红果果官网搜索出错: ' + e.message);
    }
    return setResult([]);
  },
  lazy: async function (flag, id) {
    const [vid, quality = 'auto'] = str(id).split('|');
    if (!/^\d+$/.test(vid)) return { parse: 0, url: 'toast://播放引用无效（vid 需为数字）' };
    // 壳子只保证可达主服务：播放回流走 /proxy 门面，proxy_rule 进程内解密
    const base = runtimeProxyBase();
    if (base.indexOf('toast://') === 0) return { parse: 0, url: base };
    const playUrl = base + 'hg_action=play&vid=' + vid + '&q=' + encodeURIComponent(quality || 'auto') + '&ext=.mp4';
    // 当前集最多等待 1.5 秒完成启动段；预热命中时几乎立即返回。
    await waitStartup(vid, quality || 'auto');
    scheduleEpisodeWarm(vid, quality || 'auto');
    return { parse: 0, url: playUrl };
  },
  proxy_rule: async function (params) {
    if (params.hg_action !== 'play') return [404, 'text/plain', 'not found'];
    const vid = str(params.vid);
    const quality = str(params.q) || 'auto';
    if (!/^\d+$/.test(vid)) return [400, 'text/plain', 'bad vid'];
    try {
      const stream = await resolveStream(vid, quality);
      const prepared = await prepareHeader(stream);
      const total = prepared.total;
      // __range 由框架注入（客户端 Range 头）；无 Range 按 0 起段，全部钳制到 SEG_SIZE 防整文件 base64
      const requested = parseRangeHeader(params.__range || params.range || params.Range, total);
      if (requested === 'invalid') return [416, 'text/plain', 'range not satisfiable', { 'Content-Range': 'bytes */' + total }];
      let [start, end] = requested || [0, Math.min(total, SEG_SIZE) - 1];
      // 统一对齐到 1MB 段：本次只回包含 start 的那个对齐段，粒度与缓存/预热完全一致，命中率 100%
      const segIndex = Math.floor(start / SEG_SIZE);
      const segStart = segIndex * SEG_SIZE;
      const segEnd = Math.min(segStart + SEG_SIZE - 1, total - 1);
      end = Math.min(end, segEnd);
      const segRow = await fetchSegment(vid, quality, stream, prepared, segIndex);
      const output = segRow.data.subarray(start - segStart, end - segStart + 1);
      // 后台：当前集向前预读 N 段消除播放中转圈；首段请求时兜底触发后10集预热
      scheduleReadAhead(vid, quality, stream, prepared, segIndex);
      if (segIndex === 0) scheduleEpisodeWarm(vid, quality);
      return [206, 'video/mp4', Buffer.from(output).toString('base64'), {
        'Content-Range': `bytes ${start}-${end}/${total}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': String(output.length),
        'Cache-Control': 'no-store',
      }, 1];
    } catch (e) {
      log('红果果代理出错: ' + e.message);
      return [502, 'text/plain', '红果果解析失败: ' + e.message];
    }
  },
};


// SRC_VAR: HGAPPLE_APPLE_SRC
// ---------- 苹果客户端本地包适配层 ----------
var HGAPPLE_LOCAL = { server: null, port: 0, starting: null };

function hgappleBody(b) { return b && b.body ? b.body : (b || {}); }
function hgappleVod(item) {
  item = item || {};
  return {
    vod_id: String(item.vod_id || item.url || ''),
    vod_name: String(item.vod_name || item.title || ''),
    vod_pic: String(item.vod_pic || item.img || ''),
    vod_remarks: String(item.vod_remarks || item.desc || ''),
    vod_year: String(item.vod_year || ''),
    vod_content: String(item.vod_content || item.content || ''),
    type_name: String(item.type_name || '')
  };
}
function hgappleJson(res, code, text) {
  var data = Buffer.from(String(text || ''), 'utf8');
  res.writeHead(code, { 'Content-Type': 'text/plain; charset=utf-8', 'Content-Length': data.length, 'Access-Control-Allow-Origin': '*' });
  res.end(data);
}
async function hgappleStream(req, res) {
  try {
    var u = new URL(req.url || '/', 'http://127.0.0.1');
    if (u.pathname === '/health') return hgappleJson(res, 200, 'ok');
    if (u.pathname !== '/hgapple.mp4') return hgappleJson(res, 404, 'not found');
    var vid = u.searchParams.get('vid') || '';
    var quality = u.searchParams.get('q') || 'auto';
    var code = 500, mime = 'text/plain', headers = { 'Access-Control-Allow-Origin': '*' }, body = null;
    try {
      // 【优化】直接走二进制 + 复用 1MB 对齐段缓存，不再经 proxy_rule 的 base64 回吐
      if (!/^\d+$/.test(vid)) { code = 400; body = Buffer.from('bad vid', 'utf8'); }
      else {
        var stream = await resolveStream(vid, quality);
        var prepared = await prepareHeader(stream);
        var total = prepared.total;
        var requested = parseRangeHeader(req.headers.range || '', total);
        if (requested === 'invalid') { code = 416; body = Buffer.from('range not satisfiable', 'utf8'); headers['Content-Range'] = 'bytes */' + total; }
        else {
          var st = 0, en = total - 1;
          if (requested) { st = requested[0]; en = Math.min(requested[1], st + MAX_REPLY_BYTES - 1); }
          else { en = Math.min(total, MAX_REPLY_BYTES) - 1; }
          en = Math.min(en, total - 1);
          var si0 = Math.floor(st / SEG_SIZE);
          var si1 = Math.floor(en / SEG_SIZE);
          var __t0 = Date.now();
          var __hit = segCache.has(segKey(vid, quality, si0)) ? 1 : 0;
          // 【v20】按播放器请求的范围拼接多个 1MB 段一起返回（封顶 8MB）。
          // 之前一次只回 1MB，MPV 读完就以为没有更多数据而停住（AVPlayer 按小块要才看不出来）。
          var __parts = [];
          var __miss = 0;
          var __si;
          for (__si = si0; __si <= si1; __si += 1) {
            if (!segCache.has(segKey(vid, quality, __si))) __miss += 1;
            var __row = await fetchSegment(vid, quality, stream, prepared, __si);
            if (!__row || !__row.data) break;
            __parts.push(__row.data);
          }
          var __t1 = Date.now();
          if (!__parts.length) throw new Error('取段失败');
          var __joined = Buffer.concat(__parts);
          var __from = st - si0 * SEG_SIZE;
          if (__from < 0) __from = 0;
          var __need = en - st + 1;
          if (__from + __need > __joined.length) __need = __joined.length - __from;
          if (__need <= 0) throw new Error('取段范围异常');
          body = Buffer.from(__joined.subarray(__from, __from + __need));
          code = 206;
          headers['Content-Range'] = 'bytes ' + st + '-' + (st + body.length - 1) + '/' + total;
          headers['Accept-Ranges'] = 'bytes';
          // 允许播放器短时间复用已返回的 Range，减少切回/探测时重复请求。
          headers['Cache-Control'] = 'private, max-age=120';
          try {
            var __bg = bgTasks.length;
            __beacon('req', 'seg=' + si0 + '-' + si1 + ' hit=' + __hit + ' miss=' + __miss + ' ms=' + (__t1 - __t0) + ' bgq=' + __bg + ' byte=' + body.length);
          } catch (e) {}
          scheduleReadAhead(vid, quality, stream, prepared, si1);
        }
      }
    } catch (e) {
      code = 502; body = Buffer.from('本地解密失败: ' + (e && e.message || e), 'utf8');
    }
    mime = (code === 206) ? 'video/mp4' : 'text/plain; charset=utf-8';
    if (!body) body = Buffer.from('', 'utf8');
    headers['Content-Type'] = mime;
    headers['Content-Length'] = String(body.length);
    if (typeof hgappleJson === 'function' && code !== 206) { /* 统一走下面的 writeHead */ }
    res.writeHead(code, headers);
    if (req.method === 'HEAD') return res.end();
    res.end(body);
  } catch (e) { hgappleJson(res, 502, '本地解密失败: ' + (e && e.message || e)); }
}
function hgappleStart() {
  if (HGAPPLE_LOCAL.port) return Promise.resolve(HGAPPLE_LOCAL.port);
  if (HGAPPLE_LOCAL.starting) return HGAPPLE_LOCAL.starting;
  HGAPPLE_LOCAL.starting = new Promise(function (resolve, reject) {
    var port = 18780;
    function tryPort() {
      var srv;
      try { srv = require('http').createServer(function (req, res) { hgappleStream(req, res); }); }
      catch (e) { return reject(e); }
      srv.once('error', function (e) {
        try { srv.close(); } catch (x) { }
        if (e && e.code === 'EADDRINUSE' && port < 18790) { port += 1; return tryPort(); }
        reject(e);
      });
      srv.listen(port, '127.0.0.1', function () {
        HGAPPLE_LOCAL.server = srv;
        HGAPPLE_LOCAL.port = port;
        resolve(port);
      });
    }
    tryPort();
  });
  return HGAPPLE_LOCAL.starting;
}

var HGAPPLE_APPLE_SRC = {
  meta: { key: '🍎红果·苹果秒播', name: '🍎红果·苹果秒播', type: 3, searchable: 1, quickSearch: 1, filterable: 1 },
  init: async function () {
    try { await hgappleStart(); return {}; } catch (e) { log('本地流服务启动失败: ' + e.message); return {}; }
  },
  home: async function () {
    try {
      var h = await rule.class_parse();
      var list = await rule['推荐']();
      return { class: h.class || [], filters: h.filters || {}, list: (list || []).map(hgappleVod) };
    } catch (e) { log('首页失败: ' + e.message); return { class: [], filters: {}, list: [] }; }
  },
  category: async function (b) {
    var x = hgappleBody(b), page = pageNumber(x.page || x.pg || 1), ext = x.extend || x.filters || x.ext || {};
    try {
      var list = await rule['一级'](x.id || x.tid || x.type_id || 'short', page, true, ext);
      var rows = (list || []).map(hgappleVod);
      return { page: page, pagecount: rows.length ? page + 1 : page, limit: PAGE_SIZE, total: rows.length ? (page + 1) * PAGE_SIZE : page * PAGE_SIZE, list: rows };
    } catch (e) { log('分类失败: ' + e.message); return { page: page, pagecount: page, limit: PAGE_SIZE, total: 0, list: [] }; }
  },
  detail: async function (b) {
    var x = hgappleBody(b), id = x.ids || x.id || x.vod_id || '';
    if (Array.isArray(id)) id = id[0];
    try { var vod = await rule['二级'].call({ orId: [id] }); return { list: vod && vod.vod_id ? [vod] : [] }; }
    catch (e) { log('详情失败: ' + e.message); return { list: [] }; }
  },
  search: async function (b) {
    var x = hgappleBody(b), wd = x.wd || x.word || x.keyword || '', page = pageNumber(x.page || x.pg || 1);
    if (!wd) return { list: [] };
    try { var list = await rule['搜索'](wd, false, page); return { page: page, list: (list || []).map(hgappleVod) }; }
    catch (e) { log('搜索失败: ' + e.message); return { list: [] }; }
  },
  play: async function (b) {
    var x = hgappleBody(b), id = x.id || x.play || '';
    if (Array.isArray(id)) id = id[0];
    var parts = String(id).split('|'), vid = parts[0], quality = parts[1] || 'auto';
    if (!/^\d+$/.test(vid)) return { parse: 0, url: 'toast://播放引用无效' };
    try {
      var port = await hgappleStart();
      // 冷启动最多等 1.5 秒；后续集若已预热会立即完成。
      await waitStartup(vid, quality);
      scheduleEpisodeWarm(vid, quality);
      return { parse: 0, url: 'http://127.0.0.1:' + port + '/hgapple.mp4?vid=' + encodeURIComponent(vid) + '&q=' + encodeURIComponent(quality), header: {} };
    } catch (e) { return { parse: 0, url: 'toast://苹果本地解密服务启动失败' }; }
  }
};

// ----- 滴源 Node 插件入口（兼容 {meta, api}）-----
// 手机端访问此插件运行时的 HTTP 服务，不使用 127.0.0.1 本地回环地址。
function hgNodePublicBase(request) {
  var h = request.headers || {};
  var forwardedHost = String(h['x-forwarded-host'] || '').split(',')[0].trim();
  var host = forwardedHost || String(h.host || '').trim();
  if (!/^[a-z0-9.\[\]:-]+$/i.test(host)) throw new Error('无法确定可访问的插件域名');
  var proto = String(h['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
  if (proto !== 'https' && proto !== 'http') proto = request.protocol === 'https' ? 'https' : 'http';
  return proto + '://' + host;
}

module.exports = {
  meta: {
    key: 'hongguo_node',
    name: '红果秒播 Node版',
    type: 3,
    searchable: 1,
    quickSearch: 1,
    filterable: 1
  },
  api: async function (fastify) {
    fastify.post('/init', async function () { return {}; });
    fastify.post('/home', async function () { return HGAPPLE_APPLE_SRC.home(); });
    fastify.post('/category', async function (request) {
      return HGAPPLE_APPLE_SRC.category(request.body || {});
    });
    fastify.post('/detail', async function (request) {
      return HGAPPLE_APPLE_SRC.detail(request.body || {});
    });
    fastify.post('/search', async function (request) {
      return HGAPPLE_APPLE_SRC.search(request.body || {});
    });
    fastify.post('/play', async function (request) {
      var body = request.body || {};
      var id = Array.isArray(body.id) ? body.id[0] : (body.id || body.play || '');
      var parts = String(id).split('|');
      var vid = parts[0];
      var quality = parts[1] || 'auto';
      if (!/^\d+$/.test(vid)) return { parse: 0, url: 'toast://无效剧集ID' };
      // 必须返回服务端可访问的地址，不能用手机上的 localhost。
      var base = hgNodePublicBase(request);
      await waitStartup(vid, quality);
      scheduleEpisodeWarm(vid, quality);
      // 该路径相对于插件根路径；Fastify 注册时如配置 prefix，会自动加上前缀。
      var prefix = String(request.routeOptions?.url || request.routerPath || '').replace(/\/play\/?$/, '');
      return {
        parse: 0,
        url: base + prefix + '/hgapple.mp4?vid=' + encodeURIComponent(vid) + '&q=' + encodeURIComponent(quality),
        header: {}
      };
    });
    fastify.get('/hgapple.mp4', async function (request, reply) {
      reply.hijack();
      var originalUrl = request.raw.url;
      try {
        request.raw.url = '/hgapple.mp4?' + new URL(originalUrl, 'http://localhost').searchParams.toString();
        await hgappleStream(request.raw, reply.raw);
      } catch (error) {
        if (!reply.raw.headersSent) hgappleJson(reply.raw, 502, String(error.message || error));
        else reply.raw.destroy(error);
      } finally {
        request.raw.url = originalUrl;
      }
    });
  }
};

