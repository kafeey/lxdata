/*!
 * @name LX 搜索
 * @description kw/kg/mg/tx 含 MD5/SHA1 签名；wy 暂用公开接口。
 * @version v2.0.0
 */
const { EVENT_NAMES, request, on, send } = globalThis.lx;

const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36";

// ==================== 纯 JS crypto（洛雪用 Node crypto，这里内联） ====================

const MD5_S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
const MD5_K = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
  0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
  0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
  0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
  0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
  0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391];

const rotl = (x, c) => ((x << c) | (x >>> (32 - c))) | 0;

const utf8Bytes = (str) => {
  const out = [];
  const s = String(str == null ? "" : str);
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) { out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f)); }
    else if (c < 0xd800 || c >= 0xe000) {
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    } else {
      i++;
      const c2 = 0x10000 + (((c & 0x3ff) << 10) | (s.charCodeAt(i) & 0x3ff));
      out.push(0xf0 | (c2 >> 18), 0x80 | ((c2 >> 12) & 0x3f), 0x80 | ((c2 >> 6) & 0x3f), 0x80 | (c2 & 0x3f));
    }
  }
  return out;
};

const bytesToHex = (bytes) => {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += ("0" + (bytes[i] & 0xff).toString(16)).slice(-2);
  return s;
};

const base64Encode = (bytes) => {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] & 0xff;
    const has1 = i + 1 < bytes.length;
    const has2 = i + 2 < bytes.length;
    const b1 = has1 ? bytes[i + 1] & 0xff : 0;
    const b2 = has2 ? bytes[i + 2] & 0xff : 0;
    out += chars[b0 >> 2];
    out += chars[((b0 & 3) << 4) | (b1 >> 4)];
    out += has1 ? chars[((b1 & 15) << 2) | (b2 >> 6)] : "=";
    out += has2 ? chars[b2 & 63] : "=";
  }
  return out;
};

const md5 = (str) => {
  const bytes = utf8Bytes(str);
  const len = bytes.length;
  const bitLenLo = (len * 8) >>> 0;
  const bitLenHi = Math.floor(len / 0x20000000) >>> 0;
  bytes.push(0x80);
  while (bytes.length % 64 !== 56) bytes.push(0);
  bytes.push(bitLenLo & 0xff, (bitLenLo >>> 8) & 0xff, (bitLenLo >>> 16) & 0xff, (bitLenLo >>> 24) & 0xff);
  bytes.push(bitLenHi & 0xff, (bitLenHi >>> 8) & 0xff, (bitLenHi >>> 16) & 0xff, (bitLenHi >>> 24) & 0xff);

  let a0 = 0x67452301 | 0, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476 | 0;
  for (let off = 0; off < bytes.length; off += 64) {
    const M = [];
    for (let i = 0; i < 16; i++) {
      const p = off + i * 4;
      M.push((bytes[p] | (bytes[p + 1] << 8) | (bytes[p + 2] << 16) | (bytes[p + 3] << 24)) | 0);
    }
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      const tmp = D;
      D = C; C = B;
      B = (B + rotl((A + F + MD5_K[i] + M[g]) | 0, MD5_S[i])) | 0;
      A = tmp;
    }
    a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
  }
  const out = [];
  [a0, b0, c0, d0].forEach((v) => { for (let i = 0; i < 4; i++) out.push((v >>> (i * 8)) & 0xff); });
  return bytesToHex(out);
};

const sha1 = (str) => {
  const bytes = utf8Bytes(str);
  const len = bytes.length;
  const bitLenHi = Math.floor(len / 0x20000000) >>> 0;
  const bitLenLo = (len * 8) >>> 0;
  bytes.push(0x80);
  while (bytes.length % 64 !== 56) bytes.push(0);
  bytes.push((bitLenHi >>> 24) & 0xff, (bitLenHi >>> 16) & 0xff, (bitLenHi >>> 8) & 0xff, bitLenHi & 0xff);
  bytes.push((bitLenLo >>> 24) & 0xff, (bitLenLo >>> 16) & 0xff, (bitLenLo >>> 8) & 0xff, bitLenLo & 0xff);

  let h0 = 0x67452301 | 0, h1 = 0xefcdab89 | 0, h2 = 0x98badcfe | 0, h3 = 0x10325476 | 0, h4 = 0xc3d2e1f0 | 0;
  for (let off = 0; off < bytes.length; off += 64) {
    const w = [];
    for (let i = 0; i < 16; i++) {
      const p = off + i * 4;
      w.push(((bytes[p] << 24) | (bytes[p + 1] << 16) | (bytes[p + 2] << 8) | bytes[p + 3]) | 0);
    }
    for (let i = 16; i < 80; i++) {
      const v = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
      w.push(((v << 1) | (v >>> 31)) | 0);
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4;
    for (let i = 0; i < 80; i++) {
      let f, k;
      if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
      else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
      else { f = b ^ c ^ d; k = 0xca62c1d6; }
      const temp = (rotl(a, 5) + f + e + k + w[i]) | 0;
      e = d; d = c; c = rotl(b, 30); b = a; a = temp;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
  }
  const out = [];
  [h0, h1, h2, h3, h4].forEach((v) => {
    out.push((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
  });
  return bytesToHex(out);
};

// ---------- AES-128-ECB（wy eapi 请求加密用；洛雪用 Node createCipheriv） ----------

const AES_SBOX = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16];
const AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

const aesGmul = (a, b) => {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p;
};

const aesExpandKey = (key) => {
  const w = [];
  for (let i = 0; i < 4; i++) w.push([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
  for (let i = 4; i < 44; i++) {
    let t = w[i - 1].slice();
    if (i % 4 === 0) {
      t = [t[1], t[2], t[3], t[0]];
      t = [AES_SBOX[t[0]], AES_SBOX[t[1]], AES_SBOX[t[2]], AES_SBOX[t[3]]];
      t[0] ^= AES_RCON[(i / 4) - 1];
    }
    const prev = w[i - 4];
    w.push([prev[0] ^ t[0], prev[1] ^ t[1], prev[2] ^ t[2], prev[3] ^ t[3]]);
  }
  return w;
};

const aesEncryptBlock = (block, w) => {
  const s = block.slice();
  for (let c = 0; c < 4; c++)
    for (let r = 0; r < 4; r++) s[r + 4 * c] ^= w[c][r];

  for (let round = 1; round <= 10; round++) {
    for (let i = 0; i < 16; i++) s[i] = AES_SBOX[s[i]];

    const t = s.slice();
    for (let r = 0; r < 4; r++)
      for (let c = 0; c < 4; c++) s[r + 4 * c] = t[r + 4 * ((c + r) % 4)];

    if (round < 10) {
      for (let c = 0; c < 4; c++) {
        const i = 4 * c;
        const a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
        s[i] = aesGmul(a0, 2) ^ aesGmul(a1, 3) ^ a2 ^ a3;
        s[i + 1] = a0 ^ aesGmul(a1, 2) ^ aesGmul(a2, 3) ^ a3;
        s[i + 2] = a0 ^ a1 ^ aesGmul(a2, 2) ^ aesGmul(a3, 3);
        s[i + 3] = aesGmul(a0, 3) ^ a1 ^ a2 ^ aesGmul(a3, 2);
      }
    }

    for (let c = 0; c < 4; c++)
      for (let r = 0; r < 4; r++) s[r + 4 * c] ^= w[round * 4 + c][r];
  }
  return s;
};

// PKCS7 填充 + ECB 加密, 输出大写 HEX(洛雪 eapi 的格式)
const aes128ecbEncryptHex = (text, keyStr) => {
  const key = utf8Bytes(keyStr);
  const w = aesExpandKey(key);
  const data = utf8Bytes(text);
  const pad = 16 - (data.length % 16);
  for (let i = 0; i < pad; i++) data.push(pad);

  const out = [];
  for (let off = 0; off < data.length; off += 16) {
    const enc = aesEncryptBlock(data.slice(off, off + 16), w);
    for (let i = 0; i < 16; i++) out.push(enc[i]);
  }
  return bytesToHex(out).toUpperCase();
};

// ==================== 通用工具 ====================

const httpFetch = (url, options = { method: "GET" }) =>
  new Promise((resolve, reject) => {
    request(url, options, (error, response) => {
      if (error) return reject(error);
      resolve(response);
    });
  });

const bodyOf = (resp) => {
  let b = resp && resp.body !== undefined ? resp.body : resp;
  if (typeof b === "string") {
    try { b = JSON.parse(b); } catch (e) { throw new Error("响应不是有效 JSON: " + e.message); }
  }
  return b;
};

const dec = (v) => String(v == null ? "" : v)
  .replace(/&nbsp;/g, " ").replace(/&amp;/g, "&")
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&#39;/g, "'").trim();

const pad2 = (n) => (n < 10 ? "0" : "") + n;
const pad5 = (n) => { let s = String(n); while (s.length < 5) s = "0" + s; return s; };

const fmtTime = (sec) => {
  const s = Number(sec) > 0 ? Math.floor(Number(sec)) : 0;
  return pad2(Math.floor(s / 60)) + ":" + pad2(s % 60);
};

const singers = (arr) => Array.isArray(arr)
  ? arr.map((x) => dec(typeof x === "string" ? x : (x && x.name))).filter(Boolean).join("、")
  : "";

// 统一歌曲结构：id/songmid/hash/meta 填齐，供解析脚本使用
const song = (plat, name, singer, album, id, interval, img, hash) => {
  const sid = String(id == null ? "" : id);
  const h = hash ? String(hash) : sid;
  return {
    name: dec(name), singer: dec(singer), albumName: dec(album), source: plat,
    id: sid, songmid: sid, hash: h,
    interval: fmtTime(interval),
    img: img ? String(img) : "",
    meta: { picture: img ? String(img) : "", [plat]: { id: sid, hash: h } },
  };
};

// 从上游多个候选字段中取第一个合法的总数(0=上游未给, 由调用方按"未知"处理)
const pickTotal = function () {
  for (let i = 0; i < arguments.length; i++) {
    const n = Number(arguments[i]);
    if (isFinite(n) && n >= 0) return Math.floor(n);
  }
  return 0;
};

// ==================== 酷我（洛雪 kw，无签名） ====================

const searchKw = async (keyword, limit, page) => {
  const url = "http://search.kuwo.cn/r.s?client=kt&all=" + encodeURIComponent(keyword)
    + "&pn=" + ((page - 1) * limit) + "&rn=" + limit
    + "&uid=794762570&ver=kwplayer_ar_9.2.2.1&vipver=1&show_copyright_off=1&newver=1"
    + "&ft=music&cluster=0&strategy=2012&encoding=utf8&rformat=json&vermerge=1&mobi=1&issubtitle=1";
  const body = bodyOf(await httpFetch(url, { method: "GET", headers: { "User-Agent": UA } }));
  const list = body && Array.isArray(body.abslist) ? body.abslist : [];
  const out = [];
  for (const item of list) {
    const rid = String(item.MUSICRID || item.MP3RID || "").replace(/^MUSIC_/i, "").replace(/^MP3_/i, "");
    if (!rid) continue;
    out.push(song("kw", item.SONGNAME || item.NAME, item.ARTIST || item.AARTIST,
      item.ALBUM, rid, item.DURATION, null, rid));
    if (out.length >= limit) break;
  }
  if (!out.length) throw new Error("酷我未找到相关歌曲");
  return { list: out, total: pickTotal(body && body.TOTAL, body && body.total) };
};

// ==================== 酷狗（洛雪 kg，无签名） ====================

const searchKg = async (keyword, limit, page) => {
  const url = "http://songsearch.kugou.com/song_search_v2?platform=AndroidFilter&iscorrection=1&keyword="
    + encodeURIComponent(keyword) + "&hifiquality=0&pagesize=" + limit + "&PrivilegeFilter=0&page=" + page;
  const body = bodyOf(await httpFetch(url, { method: "GET", headers: { "User-Agent": UA } }));
  if (!body || Number(body.error_code) !== 0) throw new Error("酷狗搜索失败");
  const lists = body.data && Array.isArray(body.data.lists) ? body.data.lists : [];
  const out = [];
  const seen = new Set();
  const pushOne = (d) => {
    const hash = String(d.FileHash || "");
    const key = String(d.Audioid || "") + hash;
    if (!hash || seen.has(key)) return;
    seen.add(key);
    out.push(song("kg", d.OriSongName || d.SongName, singers(d.Singers || d.singer),
      d.AlbumName, d.Audioid || hash, d.Duration, null, hash));
  };
  for (const d of lists) {
    pushOne(d);
    for (const child of (Array.isArray(d.Grp) ? d.Grp : [])) pushOne(child);
    if (out.length >= limit) break;
  }
  if (!out.length) throw new Error("酷狗未找到相关歌曲");
  return { list: out, total: pickTotal(body.data && body.data.total) };
};

// ==================== 咪咕（洛雪 mg v3，MD5 签名） ====================

const MG_DEVICE_ID = "963B7AA0D21511ED807EE5846EC87D20";
const MG_SIGNATURE_MD5 = "6cdc72a439cef99a3418d2a78aa28c73";
const MG_SALT = "yyapp2d16148780a1dcc7408e06336b98cfd50";

const searchMg = async (keyword, limit, page) => {
  const time = String(Date.now());
  const sign = md5(keyword + MG_SIGNATURE_MD5 + MG_SALT + MG_DEVICE_ID + time);
  const sw = "%7B%22song%22%3A1%2C%22album%22%3A0%2C%22singer%22%3A0%2C%22tagSong%22%3A1"
    + "%2C%22mvSong%22%3A0%2C%22bestShow%22%3A1%2C%22songlist%22%3A0%2C%22lyricSong%22%3A0%7D";
  const url = "https://jadeite.migu.cn/music_search/v3/search/searchAll?isCorrect=0&isCopyright=1"
    + "&searchSwitch=" + sw + "&pageSize=" + limit + "&text=" + encodeURIComponent(keyword)
    + "&pageNo=" + page + "&sort=0&sid=USS";
  const body = bodyOf(await httpFetch(url, {
    method: "GET",
    headers: {
      uiVersion: "A_music_3.6.1",
      deviceId: MG_DEVICE_ID,
      timestamp: time,
      sign: sign,
      channel: "0146921",
      "User-Agent": "Mozilla/5.0 (Linux; U; Android 11.0.0; zh-cn; MI 11 Build/OPR1.170623.032) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30",
    },
  }));
  if (!body || String(body.code) !== "000000") throw new Error((body && body.info) || "咪咕搜索失败");
  const resultList = body.songResultData && Array.isArray(body.songResultData.resultList)
    ? body.songResultData.resultList : [];
  const out = [];
  const seen = new Set();
  resultList.forEach((group) => {
    (Array.isArray(group) ? group : []).forEach((d) => {
      if (!d.songId || !d.copyrightId || seen.has(d.copyrightId)) return;
      seen.add(d.copyrightId);
      out.push(song("mg", d.name, singers(d.singerList), d.album, d.songId, d.duration,
        d.img3 || d.img2 || d.img1, d.songId));
    });
  });
  if (!out.length) throw new Error("咪咕未找到相关歌曲");
  return { list: out.slice(0, limit), total: pickTotal(body.songResultData && body.songResultData.totalCount) };
};

// ==================== QQ音乐（洛雪 tx，zzcSign=SHA1+base64） ====================

const zzcSign = (text) => {
  const hash = sha1(text);
  const PART1 = [23, 14, 6, 36, 16, 40, 7, 19];
  const PART2 = [16, 1, 32, 12, 19, 27, 8, 5];
  const SCRAMBLE = [89, 39, 179, 150, 218, 82, 58, 252, 177, 52, 186, 123, 120, 64, 242, 133, 143, 161, 121, 179];
  const part1 = PART1.map((i) => hash[i]).join("");
  const part2 = PART2.map((i) => hash[i]).join("");
  const part3 = SCRAMBLE.map((v, i) => v ^ parseInt(hash.slice(i * 2, i * 2 + 2), 16));
  const b64 = base64Encode(part3).replace(/[\\/+=]/g, "");
  return ("zzc" + part1 + b64 + part2).toLowerCase();
};

const txSearchId = () => {
  let guid = "";
  for (let i = 0; i < 32; i++) guid += Math.floor(Math.random() * 16).toString(16);
  return guid.toUpperCase() + pad5(Math.floor(Math.random() * 100000));
};

const searchTx = async (keyword, limit, page) => {
  const data = {
    comm: {
      _channelid: "0", _os_version: "6.2.9200-2", ct: "19", cv: "2151",
      guid: "1F70E520B2EAA7D25E11760783C53CA9", patch: "118",
      psrf_access_token_expiresAt: 0, psrf_qqaccess_token: "", psrf_qqopenid: "",
      psrf_qqunionid: "", tmeAppID: "qqmusic", tmeLoginType: 0, uin: "0",
      wid: "7223299733393904640",
    },
    "music.search.SearchCgiService": {
      module: "music.search.SearchCgiService",
      method: "DoSearchForQQMusicDesktop",
      param: {
        grp: 1, num_per_page: limit, page_num: page, query: keyword,
        remoteplace: "txt.newclient.top", search_type: 0, searchid: txSearchId(),
      },
    },
  };
  const sign = zzcSign(JSON.stringify(data));
  const url = "https://u.y.qq.com/cgi-bin/musics.fcg?sign=" + sign;
  const body = bodyOf(await httpFetch(url, {
    method: "POST",
    headers: { "User-Agent": "QQMusic 14090508(android 12)" },
    body: data,
  }));
  const req = body && (body["music.search.SearchCgiService"] || body.req);
  if (!req || Number(body.code) !== 0 || Number(req.code) !== 0) throw new Error("QQ音乐搜索失败");
  const d = req.data || {};
  const list = (d.body && d.body.song && Array.isArray(d.body.song.list)) ? d.body.song.list : [];
  const out = [];
  list.forEach((item) => {
    if (!item.file || !item.file.media_mid) return;
    const albumMid = item.album ? item.album.mid : "";
    out.push(song("tx", item.title, singers(item.singer), item.album ? item.album.name : "",
      item.mid, item.interval,
      albumMid ? ("https://y.gtimg.cn/music/photo_new/T002R500x500M000" + albumMid + ".jpg") : "",
      item.mid));
  });
  if (!out.length) throw new Error("QQ音乐未找到相关歌曲");
  return { list: out.slice(0, limit), total: pickTotal(d.meta && d.meta.sum, d.total, d.sum) };
};

// ==================== 网易云（洛雪 wy：eapi = MD5 + AES-128-ECB） ====================

const WY_EAPI_KEY = "e82ckenh8dichen8";
const WY_SALT = "36cd479b6b5";

const wyEapiForm = (path, obj) => {
  const text = JSON.stringify(obj);
  const message = "nobody" + path + "use" + text + "md5forencrypt";
  const digest = md5(message);
  const data = path + "-" + WY_SALT + "-" + text + "-" + WY_SALT + "-" + digest;
  return { params: aes128ecbEncryptHex(data, WY_EAPI_KEY) };
};

const searchWyEapi = async (keyword, limit, page) => {
  const path = "/api/search/song/list/page";
  const body = bodyOf(await httpFetch("http://interface.music.163.com/eapi/batch", {
    method: "POST",
    headers: {
      "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36",
      origin: "https://music.163.com",
    },
    form: wyEapiForm(path, {
      keyword: keyword, needCorrect: "1", channel: "typing",
      offset: (page - 1) * limit, scene: "normal", total: true, limit: limit,
    }),
  }));
  if (!body || Number(body.code) !== 200) throw new Error("网易云 eapi 搜索失败");
  const resources = (body.data && Array.isArray(body.data.resources)) ? body.data.resources : [];
  const out = [];
  resources.forEach((item) => {
    const d = item && item.baseInfo && item.baseInfo.simpleSongData;
    if (!d) return;
    out.push(song("wy", d.name, singers(d.ar), d.al && d.al.name, d.id,
      (Number(d.dt) || 0) / 1000, d.al && d.al.picUrl, d.id));
  });
  if (!out.length) throw new Error("网易云未找到相关歌曲");
  return {
    list: out.slice(0, limit),
    total: pickTotal(body.data && body.data.totalCount, body.data && body.data.resourceCount),
  };
};

// eapi 不可用(网络/协议变化)时回退公开搜索接口, 保证 wy 仍可搜
const searchWyPublic = async (keyword, limit, page) => {
  const url = "https://music.163.com/api/search/get/web?s=" + encodeURIComponent(keyword)
    + "&type=1&offset=" + ((page - 1) * limit) + "&limit=" + limit;
  const body = bodyOf(await httpFetch(url, {
    method: "GET",
    headers: { "User-Agent": UA, "Referer": "https://music.163.com/" },
  }));
  const list = body && body.result && Array.isArray(body.result.songs) ? body.result.songs : [];
  const out = [];
  for (const d of list) {
    const id = String(d.id || "");
    if (!id) continue;
    const arts = Array.isArray(d.artists) ? d.artists : (Array.isArray(d.ar) ? d.ar : []);
    const al = d.album || d.al || {};
    out.push(song("wy", d.name, singers(arts), al.name, id,
      (Number(d.duration) || Number(d.dt) || 0) / 1000, al.picUrl, id));
    if (out.length >= limit) break;
  }
  if (!out.length) throw new Error("网易云未找到相关歌曲");
  return {
    list: out,
    total: pickTotal(body.result && body.result.songCount, body.result && body.result.songcount),
  };
};

const searchWy = async (keyword, limit, page) => {
  try {
    return await searchWyEapi(keyword, limit, page);
  } catch (e) {
    return await searchWyPublic(keyword, limit, page);
  }
};

// ==================== 注册 ====================

const SEARCH = { kw: searchKw, kg: searchKg, mg: searchMg, tx: searchTx, wy: searchWy };
const QUALITYS = {
  kw: ["128k", "320k", "flac", "flac24bit"],
  kg: ["128k", "320k", "flac", "flac24bit"],
  mg: ["128k", "320k", "flac", "flac24bit"],
  tx: ["128k", "320k", "flac", "flac24bit"],
  wy: ["128k", "320k", "flac", "flac24bit"],
};

on(EVENT_NAMES.request, ({ action, source, info }) => {
  if (action !== "search") return Promise.reject(new Error("action not supported: " + action));
  const fn = SEARCH[String(source || "").toLowerCase()];
  if (!fn) return Promise.reject(new Error("source " + source + " 不支持搜索"));
  const keyword = info && info.keyword ? String(info.keyword).trim() : "";
  if (!keyword) return Promise.reject(new Error("需要搜索关键词"));
  const limit = Math.min(Number(info && info.limit) || 20, 30);
  const page = Math.max(1, Number(info && info.page) || 1);
  return Promise.resolve(fn(keyword, limit, page)).then((r) => {
    const list = (r && Array.isArray(r.list)) ? r.list : (Array.isArray(r) ? r : []);
    const total = (r && !Array.isArray(r)) ? pickTotal(r.total) : 0;
    const allPage = total > 0 ? Math.ceil(total / limit) : 0;
    return { list: list.slice(0, limit), total: total, allPage: allPage, limit: limit };
  });
});

const sources = {};
Object.keys(SEARCH).forEach((p) => {
  sources[p] = { name: p, type: "music", actions: ["search"], qualitys: QUALITYS[p] };
});
send(EVENT_NAMES.inited, { status: true, openDevTools: false, sources });
