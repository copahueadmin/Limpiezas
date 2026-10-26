// (Tanda 510) Función serverless PROGRAMADA de Netlify: COPIA DE SEGURIDAD de los roomings y archivo a los 6 meses.
// Corre sola todas las noches (ver el schedule en netlify.toml: "59 2 * * *" = 23:59 hs de Argentina, que es UTC-3 todo el año),
// sin que nadie tenga la app abierta. Sin librerías externas (solo `crypto`, `zlib` y `fetch`).
//
// QUÉ HACE, EN ORDEN:
//  1) Lee TODOS los roomings de la base de Roomings (Firestore, proyecto "roomings-hotelcopahue", colección "roomings_history").
//     Ignora los documentos de prueba (id que empieza con "zz_" o nombre "Delegacion Falsa …").
//  2) Arma un ZIP con: una carpeta «PDF» (un PDF por rooming, listo para abrir/imprimir), una carpeta «Datos_para_restaurar»
//     (el JSON completo de cada rooming: sirve para volver a cargarlo en la base si algún día se pierde) y un INDICE.txt.
//     Lo manda por mail a copahuerecepcion@gmail.com (si pesa mucho, en varias partes).
//  3) Solo si ese mail salió bien: a los roomings con 6 MESES cumplidos y estadía ya terminada les manda un mail propio
//     con su PDF (+ su JSON) y recién después los borra de la base. Máx. 10 por noche. Si cualquier envío falla, NO se borra nada.
//
// Variables de entorno (Netlify → Site settings → Environment variables):
//   RESEND_API_KEY            la misma que ya usa send-email.js (obligatoria).
//   ROOMINGS_BACKUP_TO        (opcional) destinatario(s), por defecto copahuerecepcion@gmail.com.
//   ROOMINGS_NO_DELETE        (opcional) "1" = nunca borra nada (solo manda la copia de seguridad).
//   ROOMINGS_BACKUP_KEY       (opcional) clave para disparar a mano: https://TU-SITIO/.netlify/functions/backup-roomings?run=1&key=LA_CLAVE
//   ROOMINGS_FIREBASE_CLIENT_EMAIL / ROOMINGS_FIREBASE_PRIVATE_KEY   (opcionales) cuenta de servicio del proyecto de Roomings:
//             hacen falta SOLO si algún día se cierran las reglas de Firestore (hoy están abiertas y no se necesitan).
// Abrir la URL de la función en el navegador (sin parámetros) muestra un diagnóstico (cuántos roomings ve) sin mandar ni borrar nada.

const crypto = require("crypto");
const zlib = require("zlib");

const PROJECT = process.env.ROOMINGS_PROJECT_ID || "roomings-hotelcopahue";
const COLL = "roomings_history";
const TO = process.env.ROOMINGS_BACKUP_TO || "copahuerecepcion@gmail.com";
const FROM = "Hotel Copahue <informes@hotelcopahue.com>";
const MAX_DEL = 10;
const PART_BYTES = 18 * 1024 * 1024; // tope por mail (el adjunto viaja en base64: +33%)

// ───────── Firestore (REST) ─────────
function b64u(x) { return Buffer.from(x).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
async function accessToken() {
  const ce = process.env.ROOMINGS_FIREBASE_CLIENT_EMAIL, pk = process.env.ROOMINGS_FIREBASE_PRIVATE_KEY;
  if (!ce || !pk) return null;
  const key = String(pk).includes("\\n") ? pk.replace(/\\n/g, "\n") : pk, now = Math.floor(Date.now() / 1000);
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
async function listAll(tok) {
  const out = []; let pageToken = "";
  for (let g = 0; g < 50; g++) {
    const url = `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/${COLL}?pageSize=200` + (pageToken ? "&pageToken=" + encodeURIComponent(pageToken) : "");
    const r = await fetch(url, tok ? { headers: { Authorization: "Bearer " + tok } } : {});
    const j = await r.json().catch(() => null);
    if (!r.ok || !j) throw new Error("No se pudo leer Firestore (" + r.status + "): " + JSON.stringify(j).slice(0, 300));
    (j.documents || []).forEach((d) => {
      const data = {}; const f = d.fields || {}; Object.keys(f).forEach((k) => { data[k] = dec(f[k]); });
      out.push({ id: d.name.split("/").pop(), data, saved: data.savedAt && data.savedAt.__ts ? Date.parse(data.savedAt.__ts) : 0 });
    });
    if (!j.nextPageToken) return out;
    pageToken = j.nextPageToken;
  }
  throw new Error("Demasiadas páginas al leer Firestore.");
}
async function delDoc(id, tok) {
  const r = await fetch(`https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/${COLL}/${encodeURIComponent(id)}`, { method: "DELETE", headers: tok ? { Authorization: "Bearer " + tok } : {} });
  return r.ok;
}
function isJunk(e) { return /^zz_/i.test(e.id) || /^Delegacion Falsa/i.test(String((e.data && e.data.contingentName) || "")); }
function jsonSafe(o) { return JSON.parse(JSON.stringify(o, (k, v) => (v && v.__ts ? v.__ts : v))); }

// ───────── fechas ─────────
const MES = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"];
function argNow() { return new Date(Date.now() - 3 * 3600 * 1000); } // «reloj» de Argentina leído con getUTC*
function z(n) { return (n < 10 ? "0" : "") + n; }
function ymd(d) { return d.getUTCFullYear() + "-" + z(d.getUTCMonth() + 1) + "-" + z(d.getUTCDate()); }
function dmy(ms) { if (!ms) return ""; const d = new Date(ms - 3 * 3600 * 1000); return z(d.getUTCDate()) + "/" + z(d.getUTCMonth() + 1) + "/" + d.getUTCFullYear(); }
function isoDmy(s) { const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(s || "")); return m ? m[3] + "/" + m[2] + "/" + m[1] : String(s || ""); }
function baseMs(e) { const c = e.data.createdAt; const n = typeof c === "number" ? c : (c && c.__ts ? Date.parse(c.__ts) : 0); return n || e.saved || 0; }
function isDue(e, now) {
  const base = baseMs(e); if (!base) return false;
  const lim = new Date(base); lim.setUTCMonth(lim.getUTCMonth() + 6);
  if (now < lim.getTime()) return false;
  const s = e.data.stay || {}, last = s.out || s["in"]; // no se archiva un rooming cuya estadía todavía no terminó
  if (last && /^\d{4}-\d{2}-\d{2}$/.test(last) && Date.parse(last + "T23:59:00-03:00") > now) return false;
  return true;
}

// ───────── PDF (sin librerías: Helvetica estándar, A4) ─────────
const W = { R: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 278, 333, 556, 556, 556, 556, 260, 556, 333, 737, 370, 556, 584, 333, 737, 333, 400, 584, 333, 333, 333, 556, 537, 278, 333, 333, 365, 556, 834, 834, 834, 611, 667, 667, 667, 667, 667, 667, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278, 722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722, 722, 667, 667, 611, 556, 556, 556, 556, 556, 556, 889, 500, 556, 556, 556, 556, 278, 278, 278, 278, 556, 556, 556, 556, 556, 556, 556, 584, 611, 556, 556, 556, 556, 500, 556, 500], B: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 278, 333, 556, 556, 556, 556, 280, 556, 333, 737, 370, 556, 584, 333, 737, 333, 400, 584, 333, 333, 333, 611, 556, 278, 333, 333, 365, 556, 834, 834, 834, 611, 722, 722, 722, 722, 722, 722, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278, 722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722, 722, 667, 667, 611, 556, 556, 556, 556, 556, 556, 889, 556, 556, 556, 556, 556, 278, 278, 278, 278, 611, 611, 611, 611, 611, 611, 611, 584, 611, 611, 611, 611, 611, 556, 611, 556] };
function toWin(s) { // Unicode → bytes WinAnsi (lo que no existe se reemplaza por "?")
  const map = { "–": 150, "—": 151, "‘": 145, "’": 146, "“": 147, "”": 148, "•": 149, "…": 133, "€": 128 };
  const o = []; for (const ch of String(s == null ? "" : s)) { const c = ch.codePointAt(0); if (map[ch]) o.push(map[ch]); else if (c >= 32 && c < 256) o.push(c); else if (c === 9 || c === 10 || c === 13) o.push(32); else o.push(63); }
  return o;
}
function tw(s, size, bold) { const t = bold ? W.B : W.R; let w = 0; toWin(s).forEach((c) => { w += (t[c] || 500); }); return w * size / 1000; }
function wrap(s, size, bold, maxW) {
  const words = String(s == null ? "" : s).split(/\s+/).filter(Boolean), lines = []; let cur = "";
  words.forEach((w) => {
    let t = cur ? cur + " " + w : w;
    if (tw(t, size, bold) <= maxW) { cur = t; return; }
    if (cur) lines.push(cur);
    while (tw(w, size, bold) > maxW && w.length > 1) { let k = w.length - 1; while (k > 1 && tw(w.slice(0, k), size, bold) > maxW) k--; lines.push(w.slice(0, k)); w = w.slice(k); }
    cur = w;
  });
  if (cur) lines.push(cur); return lines.length ? lines : [""];
}
function pdfEsc(bytes) { let s = ""; bytes.forEach((c) => { s += (c === 40 || c === 41 || c === 92) ? "\\" + String.fromCharCode(c) : String.fromCharCode(c); }); return s; }
function roomNum(a, b) { const x = parseInt(a, 10), y = parseInt(b, 10); if (isFinite(x) && isFinite(y) && x !== y) return x - y; return String(a).localeCompare(String(b)); }
function guestLine(g) { if (typeof g === "string") return g.trim(); const a = String((g && g.apellido) || "").trim(), n = String((g && g.nombre) || "").trim(); return (a + (a && n ? ", " : "") + n).trim(); }

function buildPdf(d, meta) {
  const PW = 595.28, PH = 841.89, M = 40, pages = []; let ops = null, y = 0, pageNo = 0;
  const cols = [{ x: M, w: 42, t: "Hab." }, { x: M + 42, w: 120, t: "Camas" }, { x: M + 162, w: 108, t: "Etiqueta" }, { x: M + 270, w: PW - M - (M + 270), t: "Huéspedes" }];
  const text = (x, yy, s, size, bold, rgb) => { ops.push((rgb ? rgb.join(" ") + " rg " : "0 g ") + "BT /" + (bold ? "F2" : "F1") + " " + size + " Tf " + x.toFixed(2) + " " + yy.toFixed(2) + " Td (" + pdfEsc(toWin(s)) + ") Tj ET"); };
  const rect = (x, yy, w, h, rgb) => ops.push(rgb.join(" ") + " rg " + x.toFixed(2) + " " + yy.toFixed(2) + " " + w.toFixed(2) + " " + h.toFixed(2) + " re f");
  const line = (x1, y1, x2, y2, g) => ops.push(g + " G 0.5 w " + x1.toFixed(2) + " " + y1.toFixed(2) + " m " + x2.toFixed(2) + " " + y2.toFixed(2) + " l S");
  const newPage = (first) => {
    ops = []; pages.push(ops); pageNo++; y = PH - M;
    if (first) {
      rect(0, PH - 70, PW, 70, [0.059, 0.298, 0.361]);
      const title = String(d.contingentName || "Rooming");
      wrap(title, 20, true, PW - 2 * M).slice(0, 2).forEach((l, i) => text(M, PH - 34 - i * 22, l, 20, true, [1, 1, 1]));
      text(M, PH - 62, "Rooming · Hotel Copahue Junín", 9.5, false, [0.85, 0.93, 0.95]);
      y = PH - 92;
      const st = d.stay || {}, bits = [];
      if (d.date) bits.push("Fecha: " + d.date);
      if (st["in"] || st.out) bits.push("Ingreso: " + (isoDmy(st["in"]) || "—") + "   Egreso: " + (isoDmy(st.out) || "—") + (st.days ? "   (" + st.days + " días)" : ""));
      bits.push("Habitaciones: " + meta.nRooms + "   Huéspedes: " + meta.nGuests);
      bits.forEach((b) => { text(M, y, b, 10.5, false, [0.15, 0.15, 0.15]); y -= 15; });
      text(M, y, "Guardado en el sistema: " + (meta.saved || "—") + (meta.created ? "   ·   Creado: " + meta.created : ""), 8.5, false, [0.45, 0.45, 0.45]); y -= 22;
    }
    rect(M, y - 4, PW - 2 * M, 16, [0.059, 0.298, 0.361]);
    cols.forEach((c) => text(c.x + 4, y, c.t, 9.5, true, [1, 1, 1])); y -= 20;
  };
  newPage(true);
  const rooms = d.rooms || {}, nums = Object.keys(rooms).sort(roomNum);
  nums.forEach((n, i) => {
    const r = rooms[n] || {}, gl = (r.guests || []).map(guestLine).filter(Boolean), extra = [];
    const tag = String(r.tag || ""), bed = String(r.bed || "") + (r.spa ? "  · Sala de masajes" : "");
    const gLines = []; gl.forEach((g) => wrap(g, 9.5, false, cols[3].w - 8).forEach((l, k) => gLines.push(k ? "   " + l : l)));
    const obs = String(r.obs || r.comentario || ""); if (obs) wrap("Obs.: " + obs, 8.5, false, cols[3].w - 8).forEach((l) => extra.push(l));
    const bLines = wrap(bed, 9.5, false, cols[1].w - 8), tLines = wrap(tag, 9.5, false, cols[2].w - 8);
    const nl = Math.max(1, gLines.length + extra.length, bLines.length, tLines.length), h = nl * 12.5 + 7;
    if (y - h < M + 22) newPage(false);
    if (i % 2 === 0) rect(M, y - h + 9, PW - 2 * M, h, [0.955, 0.965, 0.97]);
    text(cols[0].x + 4, y, n, 10, true);
    bLines.forEach((l, k) => text(cols[1].x + 4, y - k * 12.5, l, 9.5, false));
    tLines.forEach((l, k) => text(cols[2].x + 4, y - k * 12.5, l, 9.5, false));
    gLines.forEach((l, k) => text(cols[3].x + 4, y - k * 12.5, l, 9.5, false));
    extra.forEach((l, k) => text(cols[3].x + 4, y - (gLines.length + k) * 12.5, l, 8.5, false, [0.4, 0.4, 0.4]));
    y -= h; line(M, y + 9, PW - M, y + 9, 0.85);
  });
  if (!nums.length) text(M + 4, y, "Este rooming no tiene habitaciones cargadas.", 10, false, [0.4, 0.4, 0.4]);
  // pie de página
  pages.forEach((p, i) => { ops = p; text(M, 22, "Hotel Copahue Junín S.R.L. · copia de seguridad del " + meta.today, 7.5, false, [0.5, 0.5, 0.5]); text(PW - M - 40, 22, "Pág. " + (i + 1) + "/" + pages.length, 7.5, false, [0.5, 0.5, 0.5]); });
  // ensamblado
  const objs = []; const add = (s) => { objs.push(s); return objs.length; };
  add("<< /Type /Catalog /Pages 2 0 R >>"); add(""); // 1 catálogo, 2 páginas (se completa abajo)
  add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"); // 3
  add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"); // 4
  const kids = [];
  pages.forEach((p) => {
    const content = p.join("\n"), cid = add("<< /Length " + Buffer.byteLength(content, "latin1") + " >>\nstream\n" + content + "\nendstream");
    const pid = add("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 " + PW + " " + PH + "] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents " + cid + " 0 R >>"); kids.push(pid + " 0 R");
  });
  objs[1] = "<< /Type /Pages /Kids [" + kids.join(" ") + "] /Count " + kids.length + " >>";
  const infoId = add("<< /Title <FEFF" + Buffer.from(String(d.contingentName || "Rooming"), "utf16le").swap16().toString("hex").toUpperCase() + "> /Producer (Hotel Copahue) >>");
  let out = "%PDF-1.4\n"; const offs = [];
  objs.forEach((o, i) => { offs.push(Buffer.byteLength(out, "latin1")); out += (i + 1) + " 0 obj\n" + o + "\nendobj\n"; });
  const xr = Buffer.byteLength(out, "latin1");
  out += "xref\n0 " + (objs.length + 1) + "\n0000000000 65535 f \n" + offs.map((o) => String(o).padStart(10, "0") + " 00000 n \n").join("") + "trailer\n<< /Size " + (objs.length + 1) + " /Root 1 0 R /Info " + infoId + " 0 R >>\nstartxref\n" + xr + "\n%%EOF\n";
  return Buffer.from(out, "latin1");
}

// ───────── ZIP (store/deflate, UTF-8) ─────────
const CRC = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
function crc32(buf) { let c = 0xffffffff; for (let i = 0; i < buf.length; i++) c = CRC[(c ^ buf[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
function buildZip(files) { // files: [{name, data:Buffer}]
  const locals = [], central = []; let off = 0; const now = argNow();
  const dt = ((now.getUTCHours() << 11) | (now.getUTCMinutes() << 5) | (now.getUTCSeconds() >> 1)) & 0xffff, dd = (((now.getUTCFullYear() - 1980) << 9) | ((now.getUTCMonth() + 1) << 5) | now.getUTCDate()) & 0xffff;
  files.forEach((f) => {
    const nm = Buffer.from(f.name, "utf8"), raw = f.data, def = zlib.deflateRawSync(raw, { level: 6 }), useDef = def.length < raw.length, body = useDef ? def : raw, crc = crc32(raw);
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0x0800, 6); lh.writeUInt16LE(useDef ? 8 : 0, 8); lh.writeUInt16LE(dt, 10); lh.writeUInt16LE(dd, 12); lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(body.length, 18); lh.writeUInt32LE(raw.length, 22); lh.writeUInt16LE(nm.length, 26); lh.writeUInt16LE(0, 28);
    locals.push(lh, nm, body);
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0x0800, 8); ch.writeUInt16LE(useDef ? 8 : 0, 10); ch.writeUInt16LE(dt, 12); ch.writeUInt16LE(dd, 14); ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(body.length, 20); ch.writeUInt32LE(raw.length, 24); ch.writeUInt16LE(nm.length, 28); ch.writeUInt32LE(off, 42);
    central.push(ch, nm); off += 30 + nm.length + body.length;
  });
  const cd = Buffer.concat(central), end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, end]);
}
function safeName(s) { return String(s || "Rooming").replace(/[\\/:*?"<>|\u0000-\u001f]+/g, " ").replace(/\s+/g, " ").trim().slice(0, 60) || "Rooming"; }

// ───────── mail (Resend) ─────────
async function sendMail(key, subject, text, attachments) {
  const r = await fetch("https://api.resend.com/emails", { method: "POST", headers: { Authorization: "Bearer " + key, "Content-Type": "application/json" },
    body: JSON.stringify({ from: FROM, to: TO.split(",").map((s) => s.trim()).filter(Boolean), subject, text, attachments: attachments.map((a) => ({ filename: a.filename, content: a.data.toString("base64") })) }) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error("Resend rechazó el envío (" + r.status + "): " + JSON.stringify(j).slice(0, 300));
  return j.id || true;
}

// ───────── proceso ─────────
function prepare(e, today) {
  const d = jsonSafe(e.data), rooms = d.rooms || {}; let ng = 0;
  Object.keys(rooms).forEach((k) => { ng += ((rooms[k] && rooms[k].guests) || []).filter((g) => guestLine(g)).length; });
  const meta = { nRooms: Object.keys(rooms).length, nGuests: ng, saved: dmy(e.saved), created: dmy(baseMs(e) === e.saved ? 0 : baseMs(e)), today };
  const pdf = buildPdf(d, meta);
  const st = d.stay || {}, stamp = (st["in"] || "").slice(0, 10) || (e.saved ? ymd(new Date(e.saved - 3 * 3600 * 1000)) : "sin-fecha");
  const base = "Rooming - " + safeName(d.contingentName) + " - " + stamp + " [" + e.id.slice(0, 6) + "]";
  const json = Buffer.from(JSON.stringify({ id: e.id, coleccion: COLL, proyecto: PROJECT, guardado: e.saved ? new Date(e.saved).toISOString() : null, datos: d }, null, 1), "utf8");
  return { e, d, meta, pdf, json, base };
}
async function run(opts) {
  opts = opts || {};
  const tok = await accessToken(), all = await listAll(tok), list = all.filter((e) => !isJunk(e)), junk = all.length - list.length;
  const now = Date.now(), today = dmy(now), res = { total: all.length, reales: list.length, ignoradasPrueba: junk, enviados: 0, borrados: [], errores: [] };
  if (opts.dry) { res.vencidos = list.filter((e) => isDue(e, now)).length; return res; }
  const key = process.env.RESEND_API_KEY; if (!key) throw new Error("Falta RESEND_API_KEY en las variables de entorno de Netlify.");
  if (!list.length) { res.aviso = "No hay roomings para respaldar (no se manda nada, no se borra nada)."; return res; }
  const prep = []; list.forEach((e) => { try { prep.push(prepare(e, today)); } catch (er) { res.errores.push("PDF de " + e.id + ": " + er.message); } });
  prep.sort((a, b) => (b.e.saved || 0) - (a.e.saved || 0));
  // 1) ZIP(s) de la noche
  const parts = []; let cur = [], size = 0;
  prep.forEach((p) => { const sz = p.pdf.length + p.json.length; if (cur.length && size + sz > PART_BYTES) { parts.push(cur); cur = []; size = 0; } cur.push(p); size += sz; });
  if (cur.length) parts.push(cur);
  const folder = "Roomings_respaldo_" + ymd(argNow());
  let allOk = true;
  for (let i = 0; i < parts.length; i++) {
    const files = [], idx = [];
    parts[i].forEach((p) => {
      files.push({ name: folder + "/PDF/" + p.base + ".pdf", data: p.pdf }); files.push({ name: folder + "/Datos_para_restaurar/" + p.base + ".json", data: p.json });
      idx.push("• " + (p.d.contingentName || "(sin nombre)") + " — " + p.meta.nRooms + " hab., " + p.meta.nGuests + " huéspedes — guardado " + (p.meta.saved || "—") + (p.d.stay && p.d.stay["in"] ? " — estadía " + isoDmy(p.d.stay["in"]) + " al " + isoDmy(p.d.stay.out) : ""));
    });
    files.push({ name: folder + "/INDICE.txt", data: Buffer.from("Copia de seguridad de Roomings — " + today + (parts.length > 1 ? " (parte " + (i + 1) + " de " + parts.length + ")" : "") + "\r\n\r\n" + idx.join("\r\n") + "\r\n\r\nPDF/ : un PDF por rooming, para abrir o imprimir.\r\nDatos_para_restaurar/ : el contenido completo de cada rooming (JSON), para volver a cargarlo en la base si hiciera falta.\r\n", "utf8") });
    const zip = buildZip(files), fname = folder + (parts.length > 1 ? "_parte" + (i + 1) + "de" + parts.length : "") + ".zip";
    try {
      await sendMail(key, "Copia de seguridad de roomings — " + today + (parts.length > 1 ? " (" + (i + 1) + "/" + parts.length + ")" : ""),
        "Copia de seguridad automática de todos los roomings del sistema (" + parts[i].length + " en este envío).\n\nAdjunto: " + fname + "\nAl descomprimirlo vas a encontrar la carpeta «PDF» con un PDF por rooming (para abrir o imprimir) y la carpeta «Datos_para_restaurar» con el contenido completo de cada uno.\n\nSe generó el " + today + " a las 23:59 hs (hora de Argentina).\nSe ignoran los documentos de prueba (id «zz_…»)." + (junk ? " Ignorados hoy: " + junk + "." : ""),
        [{ filename: fname, data: zip }]);
      res.enviados++;
    } catch (er) { allOk = false; res.errores.push("ZIP " + (i + 1) + ": " + er.message); }
  }
  // 2) Archivo a los 6 meses: primero el mail con el PDF, recién después se borra
  const due = prep.filter((p) => isDue(p.e, now)).slice(0, MAX_DEL); res.vencidos = due.length;
  if (due.length && !allOk) res.aviso = "No se borró nada: la copia de seguridad de la noche no salió bien.";
  else if (due.length && process.env.ROOMINGS_NO_DELETE === "1") res.aviso = "Hay " + due.length + " roomings con 6 meses, pero ROOMINGS_NO_DELETE=1: no se borra nada.";
  else if (due.length) {
    for (const p of due) {
      try {
        const nm = p.d.contingentName || "Rooming";
        await sendMail(key, "Rooming archivado (6 meses): " + nm,
          "El rooming «" + nm + "» cumplió 6 meses (guardado " + (p.meta.saved || "—") + (p.d.stay && p.d.stay["in"] ? "; estadía " + isoDmy(p.d.stay["in"]) + " al " + isoDmy(p.d.stay.out) : "") + ") y se elimina de la base del sistema para ahorrar almacenamiento.\n\nEste mail es su copia: se adjunta el PDF y el archivo de datos (por si alguna vez hay que volver a cargarlo).",
          [{ filename: p.base + ".pdf", data: p.pdf }, { filename: p.base + ".json", data: p.json }]);
        if (await delDoc(p.e.id, tok)) res.borrados.push(nm); else res.errores.push("No se pudo borrar " + nm + " (el mail ya salió).");
      } catch (er) { res.errores.push("Archivo de " + p.d.contingentName + ": " + er.message + " (no se borró)"); }
    }
  }
  return res;
}

exports.handler = async (event) => {
  event = event || {};
  const method = event.httpMethod || "POST", q = event.queryStringParameters || {}, ua = String((event.headers && (event.headers["user-agent"] || event.headers["User-Agent"])) || "");
  const keyOk = process.env.ROOMINGS_BACKUP_KEY && q.key === process.env.ROOMINGS_BACKUP_KEY;
  const scheduled = (method === "POST" && (/Netlify/i.test(ua) || /next_run/.test(String(event.body || "")))) || !event.httpMethod;
  const manual = method === "GET" && q.run === "1" && keyOk;
  try {
    const res = await run({ dry: !(scheduled || manual) });
    console.log("backup-roomings:", JSON.stringify(res));
    return { statusCode: 200, headers: { "Content-Type": "application/json; charset=utf-8" }, body: JSON.stringify(Object.assign({ modo: scheduled || manual ? "ejecutado" : "diagnóstico (no manda ni borra nada)" }, res), null, 2) };
  } catch (er) {
    console.error("backup-roomings falló:", er);
    return { statusCode: 500, body: JSON.stringify({ error: String(er && er.message || er) }) };
  }
};
exports._t = { buildPdf, buildZip, run, isDue, isJunk, crc32 };
