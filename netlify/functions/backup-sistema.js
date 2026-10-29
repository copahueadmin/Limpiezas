// (Tanda 511) Función serverless PROGRAMADA de Netlify: COPIA DE SEGURIDAD DIARIA de todo el sistema (la base principal "limpiezas-e3e75").
// Corre sola todas las noches a las 23:59 hs de Argentina (ver el schedule en netlify.toml: "59 2 * * *", UTC-3 todo el año),
// aunque no haya nadie con la app abierta, y manda un ZIP por mail a copahueadmin@gmail.com.
// Los ROOMINGS no están acá: viven en otra base (proyecto "roomings-hotelcopahue") y los respalda backup-roomings.js.
//
// QUÉ GUARDA: cada documento de la colección «estado» de Firestore (habitaciones, usuarios, mucamas, cocheras, caja, cuentas corrientes,
// personal, historial, plano, etc.: todo lo que la app sincroniza entre dispositivos). Un archivo JSON por documento, dentro de «datos/».
// NO incluye los videos de incidencias (vid_*) ni los PDF de currículums (cvf_*), que son pesados y harían rebotar el mail
// (con la variable SISTEMA_BACKUP_INCLUIR_ARCHIVOS=1 se incluyen igual).
// PARA RECUPERAR: en la app, Admin → «Copias de seguridad» → subir este mismo ZIP (o los archivos ya descomprimidos).
//
// Variables de entorno (Netlify → Site settings → Environment variables). Las 3 primeras YA existen (las usan los mails de cumpleaños):
//   RESEND_API_KEY, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY
//   SISTEMA_BACKUP_TO                  (opcional) destinatario(s), por defecto copahueadmin@gmail.com
//   SISTEMA_BACKUP_KEY                 (opcional) clave para dispararla a mano: https://TU-SITIO/.netlify/functions/backup-sistema?run=1&key=LA_CLAVE
//   SISTEMA_BACKUP_INCLUIR_ARCHIVOS    (opcional) "1" = incluir también los videos y PDF de currículums.
// Abrir la URL de la función en el navegador (sin parámetros) muestra un diagnóstico (cuántos documentos ve) sin mandar nada.
// Si la copia falla (no puede leer la base, etc.) manda igual un mail de aviso con el motivo, para que no pase desapercibido.

const crypto = require("crypto");
const zlib = require("zlib");

const PROJECT = process.env.FIREBASE_PROJECT_ID || "limpiezas-e3e75";
const COLL = "estado";
const TO = process.env.SISTEMA_BACKUP_TO || "copahueadmin@gmail.com";
const FROM = "Hotel Copahue <informes@hotelcopahue.com>";
const PART_BYTES = 14 * 1024 * 1024; // datos sin comprimir por mail (el zip comprime mucho; el adjunto viaja en base64: +33%)
const FORMATO = "hotel-copahue-estado";
const BASE = `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents`;

// ───────── Firestore (REST) ─────────
function b64u(x) { return Buffer.from(x).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
// Normaliza la clave privada de la cuenta de servicio (variable de Netlify) para que OpenSSL 3 la pueda leer.
// Acepta: PEM con saltos reales, con "\n" literales, entre comillas, con \r, en una sola línea con espacios,
// el JSON completo de la cuenta de servicio, o el PEM codificado en base64.
function normalizePrivateKey(raw) {
  let s = String(raw == null ? "" : raw).trim();
  if (!s) return "";
  if (s[0] === "{") { try { const j = JSON.parse(s); if (j && j.private_key) s = String(j.private_key); } catch (e) {} }
  s = s.trim().replace(/^["'`]+|["'`,;]+$/g, "").trim();
  if (!/-----BEGIN/.test(s)) {
    try { const d = Buffer.from(s, "base64").toString("utf8"); if (/-----BEGIN/.test(d)) s = d; } catch (e) {}
  }
  s = s.replace(/\\r/g, "").replace(/\\n/g, "\n").replace(/\r/g, "");
  const m = s.match(/-----BEGIN ([A-Z ]+)-----([\s\S]*?)-----END \1-----/);
  if (m) {
    const body = m[2].replace(/[^A-Za-z0-9+\/=]/g, "");
    s = "-----BEGIN " + m[1] + "-----\n" + (body.match(/.{1,64}/g) || []).join("\n") + "\n-----END " + m[1] + "-----\n";
  }
  return s;
}
function loadPrivateKey(raw, nombreVar) {
  const pem = normalizePrivateKey(raw);
  try { return crypto.createPrivateKey(pem); }
  catch (e) { throw new Error("La clave privada de " + (nombreVar || "FIREBASE_PRIVATE_KEY") + " en Netlify no es válida (" + e.message + "). Volvé a pegar el valor de \"private_key\" del .json de la cuenta de servicio, completo, desde -----BEGIN PRIVATE KEY----- hasta -----END PRIVATE KEY-----."); }
}
async function accessToken() {
  const ce = process.env.FIREBASE_CLIENT_EMAIL, pk = process.env.FIREBASE_PRIVATE_KEY;
  if (!ce || !pk) return null;
  const key = loadPrivateKey(pk, "FIREBASE_PRIVATE_KEY"), now = Math.floor(Date.now() / 1000);
  const un = b64u(JSON.stringify({ alg: "RS256", typ: "JWT" })) + "." + b64u(JSON.stringify({ iss: ce, scope: "https://www.googleapis.com/auth/datastore", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 }));
  const s = crypto.createSign("RSA-SHA256"); s.update(un); s.end();
  const jwt = un + "." + s.sign(key).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const r = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "grant_type=" + encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer") + "&assertion=" + encodeURIComponent(jwt) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) throw new Error("token de Google: " + JSON.stringify(j));
  return j.access_token;
}
function dec(v) {
  if (v == null) return null;
  if ("stringValue" in v) return v.stringValue;
  if ("integerValue" in v) return Number(v.integerValue);
  if ("doubleValue" in v) return v.doubleValue;
  if ("booleanValue" in v) return v.booleanValue;
  if ("nullValue" in v) return null;
  if ("timestampValue" in v) return { __ts: v.timestampValue };
  if ("mapValue" in v) { const o = {}; const f = v.mapValue.fields || {}; Object.keys(f).forEach((k) => { o[k] = dec(f[k]); }); return o; }
  if ("arrayValue" in v) return (v.arrayValue.values || []).map(dec);
  if ("geoPointValue" in v) return v.geoPointValue;
  if ("referenceValue" in v) return v.referenceValue;
  return null;
}
function argNow() { return new Date(Date.now() - 3 * 3600 * 1000); } // «reloj» de Argentina leído con getUTC*
function z(n) { return (n < 10 ? "0" : "") + n; }
function ymd(d) { return d.getUTCFullYear() + "-" + z(d.getUTCMonth() + 1) + "-" + z(d.getUTCDate()); }
function dmy(ms) { if (!ms) return ""; const d = new Date(ms - 3 * 3600 * 1000); return z(d.getUTCDate()) + "/" + z(d.getUTCMonth() + 1) + "/" + d.getUTCFullYear(); }
const CRC = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
function crc32(buf) { let c = 0xffffffff; for (let i = 0; i < buf.length; i++) c = CRC[(c ^ buf[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
// (Tanda 519) Clave opcional: si existe la variable de entorno BACKUP_ZIP_PASSWORD en Netlify, el ZIP sale cifrado con AES-256 (formato WinZip AE-2:
// se abre con 7-Zip, WinRAR, Keka, The Unarchiver, etc.). Sin esa variable el ZIP sale sin clave, como antes.
const ZIP_PWD = () => String(process.env.BACKUP_ZIP_PASSWORD || "").trim();
function aesCtrLE(key, data) { // AES-CTR con contador little-endian que arranca en 1 (así lo pide WinZip AES)
  const nb = Math.ceil(data.length / 16), ctr = Buffer.alloc(nb * 16);
  for (let i = 0; i < nb; i++) { const c = i + 1; ctr.writeUInt32LE(c >>> 0, i * 16); ctr.writeUInt32LE(Math.floor(c / 4294967296) >>> 0, i * 16 + 4); }
  const ci = crypto.createCipheriv("aes-256-ecb", key, null); ci.setAutoPadding(false);
  const ks = Buffer.concat([ci.update(ctr), ci.final()]), out = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ ks[i];
  return out;
}
function aesWrap(raw, pwd) { // → Buffer: sal(16) + verificación(2) + datos cifrados + autenticación(10)
  const salt = crypto.randomBytes(16), dk = crypto.pbkdf2Sync(Buffer.from(pwd, "utf8"), salt, 1000, 66, "sha1");
  const enc = aesCtrLE(dk.subarray(0, 32), raw), mac = crypto.createHmac("sha1", dk.subarray(32, 64)).update(enc).digest().subarray(0, 10);
  return Buffer.concat([salt, dk.subarray(64, 66), enc, mac]);
}
function buildZip(files, pwd) { // files: [{name, data:Buffer}]; pwd opcional (cifra con AES-256)
  pwd = pwd === undefined ? ZIP_PWD() : String(pwd || "");
  const locals = [], central = []; let off = 0; const now = argNow();
  const dt = ((now.getUTCHours() << 11) | (now.getUTCMinutes() << 5) | (now.getUTCSeconds() >> 1)) & 0xffff, dd = (((now.getUTCFullYear() - 1980) << 9) | ((now.getUTCMonth() + 1) << 5) | now.getUTCDate()) & 0xffff;
  files.forEach((f) => {
    const nm = Buffer.from(f.name, "utf8"), raw = f.data, def = zlib.deflateRawSync(raw, { level: 6 }), useDef = def.length < raw.length;
    let body = useDef ? def : raw, crc = crc32(raw), method = useDef ? 8 : 0, flag = 0x0800, ver = 20, extra = Buffer.alloc(0);
    if (pwd) { // AE-2: método 99, CRC = 0, campo extra 0x9901
      body = aesWrap(body, pwd); extra = Buffer.alloc(11); extra.writeUInt16LE(0x9901, 0); extra.writeUInt16LE(7, 2); extra.writeUInt16LE(2, 4); extra.write("AE", 6, "latin1"); extra.writeUInt8(3, 8); extra.writeUInt16LE(method, 9);
      method = 99; flag |= 1; ver = 51; crc = 0;
    }
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(ver, 4); lh.writeUInt16LE(flag, 6); lh.writeUInt16LE(method, 8); lh.writeUInt16LE(dt, 10); lh.writeUInt16LE(dd, 12); lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(body.length, 18); lh.writeUInt32LE(raw.length, 22); lh.writeUInt16LE(nm.length, 26); lh.writeUInt16LE(extra.length, 28);
    locals.push(lh, nm, extra, body);
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(ver, 4); ch.writeUInt16LE(ver, 6); ch.writeUInt16LE(flag, 8); ch.writeUInt16LE(method, 10); ch.writeUInt16LE(dt, 12); ch.writeUInt16LE(dd, 14); ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(body.length, 20); ch.writeUInt32LE(raw.length, 24); ch.writeUInt16LE(nm.length, 28); ch.writeUInt16LE(extra.length, 30); ch.writeUInt32LE(off, 42);
    central.push(ch, nm, extra); off += 30 + nm.length + extra.length + body.length;
  });
  const cd = Buffer.concat(central), end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, end]);
}
function claveTxt() { return ZIP_PWD() ? "\n\nEste ZIP está protegido con CLAVE (cifrado AES-256). Para abrirlo usá 7-Zip, WinRAR, Keka o The Unarchiver: el explorador de archivos común de Windows / Mac no soporta este tipo de clave. Para restaurar en la app: descomprimilo con la clave y subí los archivos (carpeta «datos»)." : "\n\n(Este ZIP NO tiene clave. Para protegerlo: en Netlify → Site configuration → Environment variables → agregar BACKUP_ZIP_PASSWORD con la clave que quieras.)"; }
async function sendMail(key, subject, text, attachments) {
  const r = await fetch("https://api.resend.com/emails", { method: "POST", headers: { Authorization: "Bearer " + key, "Content-Type": "application/json" },
    body: JSON.stringify({ from: FROM, to: TO.split(",").map((s) => s.trim()).filter(Boolean), subject, text, attachments: attachments.map((a) => ({ filename: a.filename, content: a.data.toString("base64") })) }) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error("Resend rechazó el envío (" + r.status + "): " + JSON.stringify(j).slice(0, 300));
  return j.id || true;
}


// Lista los ids (y nada más: máscara vacía) para poder saltear los documentos pesados sin descargarlos.
async function listIds(tok) {
  const out = []; let pageToken = "";
  for (let g = 0; g < 100; g++) {
    const url = `${BASE}/${COLL}?pageSize=300&mask.fieldPaths=t` + (pageToken ? "&pageToken=" + encodeURIComponent(pageToken) : "");
    const r = await fetch(url, tok ? { headers: { Authorization: "Bearer " + tok } } : {});
    const j = await r.json().catch(() => null);
    if (!r.ok || !j) throw new Error("No se pudo leer Firestore (" + r.status + "): " + JSON.stringify(j).slice(0, 300) + (tok ? "" : " — faltan FIREBASE_CLIENT_EMAIL / FIREBASE_PRIVATE_KEY en Netlify."));
    (j.documents || []).forEach((d) => out.push(d.name.split("/").pop()));
    if (!j.nextPageToken) return out;
    pageToken = j.nextPageToken;
  }
  throw new Error("Demasiadas páginas al leer Firestore.");
}
async function getDocs(ids, tok) {
  const out = [];
  for (let i = 0; i < ids.length; i += 40) {
    const lote = ids.slice(i, i + 40);
    const r = await fetch(`${BASE}:batchGet`, { method: "POST", headers: Object.assign({ "Content-Type": "application/json" }, tok ? { Authorization: "Bearer " + tok } : {}),
      body: JSON.stringify({ documents: lote.map((id) => `projects/${PROJECT}/databases/(default)/documents/${COLL}/${id}`) }) });
    const j = await r.json().catch(() => null);
    if (!r.ok || !Array.isArray(j)) throw new Error("No se pudieron leer los documentos (" + r.status + "): " + JSON.stringify(j).slice(0, 300));
    j.forEach((x) => {
      if (!x.found) return;
      const campos = {}, f = x.found.fields || {}; Object.keys(f).forEach((k) => { campos[k] = dec(f[k]); });
      out.push({ id: x.found.name.split("/").pop(), campos });
    });
  }
  return out;
}
function esPesado(id) { return /^(vid_|cvf_)/.test(id); }
function jsonSafe(o) { return JSON.parse(JSON.stringify(o, (k, v) => (v && v.__ts ? v.__ts : v))); }
function fmtBytes(n) { return n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1024)) + " KB"; }

// ───────── proceso ─────────
async function run(opts) {
  opts = opts || {};
  const tok = await accessToken(), todos = await listIds(tok), incluirTodo = process.env.SISTEMA_BACKUP_INCLUIR_ARCHIVOS === "1";
  const ids = todos.filter((id) => incluirTodo || !esPesado(id)), omitidos = todos.length - ids.length;
  const res = { documentosEnLaBase: todos.length, aRespaldar: ids.length, omitidosPorPeso: omitidos, enviados: 0, errores: [] };
  if (opts.dry) return res;
  const key = process.env.RESEND_API_KEY; if (!key) throw new Error("Falta RESEND_API_KEY en las variables de entorno de Netlify.");
  if (!ids.length) { res.aviso = "No hay documentos para respaldar."; return res; }
  const docs = await getDocs(ids, tok), today = dmy(Date.now()), folder = "Copia_sistema_" + ymd(argNow());
  res.leidos = docs.length;
  docs.sort((a, b) => a.id.localeCompare(b.id));
  const items = docs.map((d) => {
    const json = Buffer.from(JSON.stringify({ copia: FORMATO, proyecto: PROJECT, id: d.id, campos: jsonSafe(d.campos) }, null, 1), "utf8");
    return { id: d.id, json, t: d.campos && d.campos.t };
  });
  const parts = []; let cur = [], size = 0;
  items.forEach((it) => { if (cur.length && size + it.json.length > PART_BYTES) { parts.push(cur); cur = []; size = 0; } cur.push(it); size += it.json.length; });
  if (cur.length) parts.push(cur);
  const leeme = "COPIA DE SEGURIDAD DEL SISTEMA — Hotel Copahue Junín\r\n"
    + "Generada el " + today + " a las 23:59 hs (hora de Argentina). Base: " + PROJECT + ", colección «" + COLL + "».\r\n\r\n"
    + "Cada archivo de la carpeta «datos» es un documento de la base (habitaciones, usuarios, cocheras, caja, personal, plano, etc.).\r\n"
    + "NO los edites a mano.\r\n\r\n"
    + "PARA RECUPERAR UNA VERSIÓN ANTERIOR: entrá a la app como Admin → «Copias de seguridad» → «Elegir el ZIP» (o «Elegir archivos / carpeta» si ya lo descomprimiste)."
    + "\r\nLa app muestra qué contiene la copia, te deja elegir qué recuperar y antes de pisar nada descarga una copia de lo que hay hoy.\r\n"
    + (parts.length > 1 ? "\r\nEsta copia viene en " + parts.length + " mails (partes). Para recuperar todo, subí TODAS las partes juntas.\r\n" : "")
    + (omitidos ? "\r\nNo incluye " + omitidos + " documentos pesados (videos de incidencias y PDF de currículums).\r\n" : "")
    + "\r\nLos roomings se respaldan aparte (otro mail, «Copia de seguridad de roomings»).\r\n"
    + "ATENCIÓN: esta copia contiene todos los datos del sistema, incluidas las claves de los usuarios. Mantené protegida la casilla que la recibe.\r\n";
  for (let i = 0; i < parts.length; i++) {
    const files = [{ name: folder + "/LEEME.txt", data: Buffer.from(leeme, "utf8") }];
    const idx = [];
    parts[i].forEach((it) => {
      files.push({ name: folder + "/datos/" + encodeURIComponent(it.id) + ".json", data: it.json });
      idx.push(it.id + "  (" + fmtBytes(it.json.length) + (it.t ? ", último cambio " + dmy(Number(it.t)) : "") + ")");
    });
    files.push({ name: folder + "/INDICE.txt", data: Buffer.from("Documentos de esta copia" + (parts.length > 1 ? " (parte " + (i + 1) + " de " + parts.length + ")" : "") + " — " + today + "\r\n\r\n" + idx.join("\r\n") + "\r\n", "utf8") });
    const zip = buildZip(files), fname = folder + (parts.length > 1 ? "_parte" + (i + 1) + "de" + parts.length : "") + ".zip";
    try {
      await sendMail(key, "Copia de seguridad del sistema — " + today + (parts.length > 1 ? " (" + (i + 1) + "/" + parts.length + ")" : ""),
        "Copia de seguridad automática del sistema del Hotel Copahue (" + parts[i].length + " documentos en este envío).\n\nAdjunto: " + fname + " (" + fmtBytes(zip.length) + ")\n\nPara recuperar una versión anterior: en la app, Admin → «Copias de seguridad» → subir este ZIP.\n"
        + (parts.length > 1 ? "Esta copia viene en " + parts.length + " partes: para recuperar todo hay que subir todas juntas.\n" : "")
        + "\nGenerada el " + today + " a las 23:59 hs (hora de Argentina). Los roomings se respaldan aparte." + claveTxt(),
        [{ filename: fname, data: zip }]);
      res.enviados++;
    } catch (er) { res.errores.push("ZIP " + (i + 1) + ": " + er.message); }
  }
  return res;
}
async function avisoFalla(msg) {
  try {
    const key = process.env.RESEND_API_KEY; if (!key) return;
    await sendMail(key, "⚠ FALLÓ la copia de seguridad del sistema — " + dmy(Date.now()),
      "La copia de seguridad automática de esta noche NO se pudo generar.\n\nMotivo: " + msg + "\n\nSi el motivo no es claro, abrí https://TU-SITIO/.netlify/functions/backup-sistema en el navegador para ver el diagnóstico.", []);
  } catch (e) { console.error("No se pudo mandar el aviso de falla:", e); }
}

exports.handler = async (event) => {
  event = event || {};
  const method = event.httpMethod || "POST", q = event.queryStringParameters || {}, ua = String((event.headers && (event.headers["user-agent"] || event.headers["User-Agent"])) || "");
  const keyOk = process.env.SISTEMA_BACKUP_KEY && q.key === process.env.SISTEMA_BACKUP_KEY;
  const scheduled = (method === "POST" && (/Netlify/i.test(ua) || /next_run/.test(String(event.body || "")))) || !event.httpMethod;
  const manual = method === "GET" && q.run === "1" && keyOk;
  try {
    const res = await run({ dry: !(scheduled || manual) });
    console.log("backup-sistema:", JSON.stringify(res));
    if (res.errores && res.errores.length) await avisoFalla(res.errores.join(" | "));
    return { statusCode: 200, headers: { "Content-Type": "application/json; charset=utf-8" }, body: JSON.stringify(Object.assign({ modo: scheduled || manual ? "ejecutado" : "diagnóstico (no manda nada)" }, res), null, 2) };
  } catch (er) {
    console.error("backup-sistema falló:", er);
    if (scheduled || manual) await avisoFalla(String(er && er.message || er));
    return { statusCode: 500, body: JSON.stringify({ error: String(er && er.message || er) }) };
  }
};
exports._t = { buildZip, aesWrap, run, crc32, esPesado };
