/*!
 * @name 纯搜索源
 */
const { EVENT_NAMES, request, on, send, env, version } = globalThis.lx;

const KW_SEARCH_API = "https://search.kuwo.cn/r.s";
const MG_SEARCH_API = "http://pd.musicapp.migu.cn/MIGUM2.0/v1.0/content/search_all.do";
const MG_SEARCH_SWITCH = '{"song":1,"album":0,"singer":0,"tagSong":0,"mvSong":0,"songlist":0,"bestShow":1}';
const MG_MOBILE_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13B143 Safari/601.1";
const TX_SEARCH_API = "https://shc.y.qq.com/soso/fcgi-bin/search_for_qq_cp";
const TX_REFERER = "http://y.qq.com/";
const QS_SEARCH_API = "https://api-vehicle.volcengine.com/v2/search/type";
const KG_SEARCH_API = "http://mobilecdn.kugou.com/api/v3/search/song";

const httpFetch = (url, options = { method: "GET" }) =>
  new Promise((resolve, reject) => {
    request(url, options, (error, response) => {
      if (error) return reject(error);
      resolve(response);
    });
  });
const parseResponseBody = (body) => {
  if (typeof body !== "string") return body;
  try { return JSON.parse(body); }
  catch (error) { throw new Error("响应不是有效 JSON: " + error.message); }
};
const formatSeconds = (value) => {
  const sec = Number(value) || 0;
  if (sec <= 0) return "00:00";
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return `${m < 10 ? "0" : ""}${m}:${s < 10 ? "0" : ""}${s}`;
};
const dec = (v) => String(v == null ? "" : v).replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").trim();

// 从上游多个候选字段中取第一个合法的总数(0=上游未给, 由调用方按"未知"处理)
const pickTotal = function () {
  for (let i = 0; i < arguments.length; i++) {
    const n = Number(arguments[i]);
    if (isFinite(n) && n >= 0) return Math.floor(n);
  }
  return 0;
};

const parseKuwoLiteral = (text) => {
  let s = String(text || "").trim();
  s = s.replace(/\\'/g, "\u0001").replace(/'/g, '"').replace(/\u0001/g, "'");
  return JSON.parse(s);
};

const handleSearchKuwo = async (keyword, limit, page) => {
  const url = `${KW_SEARCH_API}?all=${encodeURIComponent(keyword)}&ft=music&itemset=web_2013&client=kt&pn=${(page - 1) * limit}&rn=${limit}&rformat=json&encoding=utf8`;
  const response = await httpFetch(url, {
    method: "GET",
    headers: { "User-Agent": "Mozilla/5.0", Referer: "https://www.kuwo.cn/" },
    timeout: 8000,
  });
  const body = parseKuwoLiteral(response?.body);
  const list = Array.isArray(body?.abslist) ? body.abslist : [];
  if (!list.length) throw new Error("未找到相关歌曲");
  return {
    list: list.slice(0, limit).map((item) => {
      const musicRid = String(item.MUSICRID || item.MP3RID || "");
      const numericId = musicRid.replace(/^MUSIC_/, "").replace(/^MP3_/, "");
      return {
        name: dec(item.NAME || item.SONGNAME),
        singer: dec(item.ARTIST || item.AARTIST),
        albumName: dec(item.ALBUM),
        id: numericId,
        songmid: numericId,
        hash: numericId,
        source: "kw",
        interval: formatSeconds(item.DURATION),
        meta: { kw: { id: numericId, rid: musicRid } },
      };
    }),
    total: pickTotal(body?.TOTAL, body?.total),
  };
};

const handleSearchMigu = async (keyword, limit, page) => {
  const pageSize = Math.min(Math.max(limit, 1), 30);
  const url = `${MG_SEARCH_API}?ua=Android_migu&version=5.0.1&text=${encodeURIComponent(keyword)}&pageNo=${page}&pageSize=${pageSize}&searchSwitch=${encodeURIComponent(MG_SEARCH_SWITCH)}`;
  const response = await httpFetch(url, {
    method: "GET",
    headers: { "User-Agent": MG_MOBILE_UA, Referer: "http://music.migu.cn/" },
    timeout: 8000,
  });
  const body = parseResponseBody(response?.body);
  if (String(body?.code) !== "000000") throw new Error(body?.info || "咪咕搜索失败");
  const list = body?.songResultData?.result;
  if (!Array.isArray(list) || !list.length) throw new Error("未找到相关歌曲");
  const pickCover = (item) => {
    const imgs = Array.isArray(item?.imgItems) ? item.imgItems : [];
    let best = "", bestSize = -1;
    imgs.forEach((x) => {
      const t = Number(x?.imgSizeType) || 0;
      if (x?.img && t > bestSize) { bestSize = t; best = x.img; }
    });
    return best || (imgs.length ? imgs[0].img : "");
  };
  const pickSinger = (item) => {
    const s = item?.singers || item?.singerList || item?.artists;
    if (Array.isArray(s) && s.length) return s.map((x) => x.name).filter(Boolean).join(" / ");
    return String(item?.singer || "");
  };
  return {
    list: list.slice(0, limit).map((item) => {
      const contentId = String(item.contentId || item.id || "");
      return {
        name: dec(item.name || item.songName || ""),
        singer: dec(pickSinger(item)),
        albumName: dec(item.albums && item.albums[0] ? item.albums[0].name : ""),
        id: contentId,
        songmid: contentId,
        hash: contentId,
        source: "mg",
        meta: { picture: pickCover(item), mg: { id: contentId, copyrightId: String(item.copyrightId || "") } },
      };
    }),
    total: pickTotal(body?.songResultData?.totalCount, body?.data?.total),
  };
};

const handleSearchTencent = async (keyword, limit, page) => {
  const url = `${TX_SEARCH_API}?g_tk=1037878909&uin=1804681355&format=json&inCharset=utf-8&outCharset=utf-8&platform=h5&needNewCode=1&catZhida=1&t=0&perpage=${limit}&n=${limit}&w=${encodeURIComponent(keyword)}&p=${page}`;
  const response = await httpFetch(url, {
    method: "GET", headers: { Referer: TX_REFERER, "User-Agent": "Mozilla/5.0" }, timeout: 8000,
  });
  const body = parseResponseBody(response?.body);
  if (Number(body?.code) !== 0) throw new Error(body?.message || "QQ音乐搜索失败");
  const list = body?.data?.song?.list;
  if (!Array.isArray(list) || !list.length) throw new Error("未找到相关歌曲");
  return {
    list: list.slice(0, limit).map((item) => {
      const songmid = String(item.songmid || item.mid || "");
      const singers = Array.isArray(item.singer) ? item.singer.map((s) => s.name).filter(Boolean) : [];
      return {
        name: dec(item.songname || item.name),
        singer: dec(singers.join(" / ")),
        albumName: dec(item.albumname),
        id: songmid,
        songmid,
        hash: songmid,
        source: "tx",
        interval: formatSeconds(item.interval),
        meta: { picture: item.albummid ? `https://y.qq.com/music/photo_new/T002R300x300M000${item.albummid}.jpg` : "", tx: { id: songmid, mid: songmid } },
      };
    }),
    total: pickTotal(body?.data?.total),
  };
};

const handleSearchQishui = async (keyword, limit, page) => {
  const url = `${QS_SEARCH_API}?keyword=${encodeURIComponent(keyword)}&search_type=music&limit=${limit}&real_offset=${(page - 1) * limit}&search_source=qishui`;
  const response = await httpFetch(url, {
    method: "GET", headers: { "User-Agent": "Mozilla/5.0" }, timeout: 8000,
  });
  const body = parseResponseBody(response?.body);
  if (Number(body?.errno) !== 0) throw new Error(body?.msg || "汽水音乐搜索失败");
  const list = body?.data?.list;
  if (!Array.isArray(list) || !list.length) throw new Error("未找到相关歌曲");
  return {
    list: list.slice(0, limit).map((item) => {
      const itemId = String(item.item_id || "");
      return {
        name: dec(item.title),
        singer: dec(item.author_info?.name),
        albumName: "",
        id: itemId,
        songmid: itemId,
        hash: itemId,
        source: "qs",
        interval: formatSeconds(item.duration),
        meta: { picture: dec(item.cover_url), qs: { id: itemId } },
      };
    }),
    total: pickTotal(body?.data?.total, body?.data?.total_count, body?.data?.totalCount),
  };
};

const handleSearchKugou = async (keyword, limit, page) => {
  const url = `${KG_SEARCH_API}?keyword=${encodeURIComponent(keyword)}&page=${page}&pagesize=${limit}&showtype=1`;
  const response = await httpFetch(url, {
    method: "GET", headers: { "User-Agent": "Mozilla/5.0" }, timeout: 8000,
  });
  const body = parseResponseBody(response?.body);
  if (Number(body?.status) !== 1 || Number(body?.errcode) !== 0) throw new Error(body?.error || "酷狗搜索失败");
  const list = body?.data?.info;
  if (!Array.isArray(list) || !list.length) throw new Error("未找到相关歌曲");
  const coverOf = (item) => String(item?.trans_param?.union_cover || "").replace("{size}", "300");
  return {
    list: list.slice(0, limit).map((item) => {
      const hash = String(item.hash || "");
      return {
        name: dec(item.songname || item.songname_original),
        singer: dec(item.singername),
        albumName: dec(item.album_name),
        id: hash,
        songmid: hash,
        hash,
        source: "kg",
        interval: formatSeconds(item.duration),
        meta: { picture: dec(coverOf(item)), kg: { id: hash, hash } },
      };
    }),
    total: pickTotal(body?.data?.total),
  };
};

const SEARCH = {
  kw: handleSearchKuwo, mg: handleSearchMigu, tx: handleSearchTencent,
  qs: handleSearchQishui, kg: handleSearchKugou,
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
  sources[p] = {
    name: p, type: "music", actions: ["search"],
    qualitys: ["128k", "320k", "flac", "flac24bit"],
  };
});
send(EVENT_NAMES.inited, { status: true, openDevTools: false, sources });
