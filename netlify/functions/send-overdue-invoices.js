// (Tanda 619) Función serverless PROGRAMADA de Netlify (ver el schedule en netlify.toml): avisa por mail cuando una factura de
// Cuentas corrientes lleva MÁS DE 60 DÍAS IMPAGA desde su fecha de emisión. Corre sola, sin que nadie tenga la app abierta.
// - Impaga = estado "Pendiente" (con importe mayor a 0 y sin nota de crédito TOTAL que la anule).
// - Destinatarios: todos los usuarios de Gerencia y de Administración, al correo laboral de su registro del personal
//   (ch_personalfichas[id].email; si no tiene, el correo cargado en Gestión de usuarios).
// - Manda UN mail por factura (con todos los datos) a todos los destinatarios y lo recuerda en el documento propio
//   ch_ccvencenviado, así no se repite. Si la factura se paga (deja de estar Pendiente) ya no se avisa más.
// - Para no pasarse del límite de envíos de Resend, manda como máximo 20 mails por corrida (el resto sale en la corrida siguiente).
// Usa las MISMAS 3 variables de entorno que send-probation-alerts.js (FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY, RESEND_API_KEY).

const crypto = require("crypto");

function base64url(input) {
  return Buffer.from(input).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

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
function unescapePrivateKey(raw) {
  return normalizePrivateKey(raw);
}

async function getAccessToken(clientEmail, privateKeyPem) {
  const header = { alg: "RS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const claim = {
    iss: clientEmail,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };
  const unsigned = base64url(JSON.stringify(header)) + "." + base64url(JSON.stringify(claim));
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(unsigned);
  signer.end();
  const signature = signer
    .sign(privateKeyPem)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const jwt = unsigned + "." + signature;

  const resp = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body:
      "grant_type=" +
      encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer") +
      "&assertion=" +
      encodeURIComponent(jwt),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok || !data.access_token) {
    throw new Error("No se pudo obtener el token de acceso de Google: " + JSON.stringify(data));
  }
  return data.access_token;
}

async function readEstadoKey(projectId, accessToken, key, fallback) {
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/estado/${key}`;
  const resp = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (resp.status === 404) return fallback;
  const data = await resp.json().catch(() => null);
  if (!resp.ok || !data) return fallback;
  const raw = data.fields && data.fields.v && data.fields.v.stringValue;
  if (typeof raw !== "string") return fallback;
  try {
    return JSON.parse(raw);
  } catch (e) {
    return fallback;
  }
}

// Escribe (reemplazando entero) el documento de control ch_probationemailenviado -- propio de esta
// función, evita mandar 2 veces el mismo mail a la misma persona (reintentos, corridas de más de un
// día seguidas sin que nadie haya actuado, etc.).
async function writeEnviados(projectId, accessToken, enviados) {
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/estado/ch_probationemailenviado`;
  const body = { fields: { v: { stringValue: JSON.stringify(enviados) }, t: { integerValue: String(Date.now()) } } };
  const resp = await fetch(url, {
    method: "PATCH",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    const data = await resp.json().catch(() => ({}));
    console.warn("No se pudo guardar ch_probationemailenviado (no es grave, en el peor caso se reintenta el mail):", data);
  }
}

async function writeEnviados(projectId, accessToken, enviados) {
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/estado/ch_ccvencenviado`;
  const body = { fields: { v: { stringValue: JSON.stringify(enviados) }, t: { integerValue: String(Date.now()) } } };
  const resp = await fetch(url, {
    method: "PATCH",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    const data = await resp.json().catch(() => ({}));
    console.warn("No se pudo guardar ch_ccvencenviado (en el peor caso se reintenta el mail):", data);
  }
}

const PLAZO = 60;
const EMAIL_OK = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function escapeHtml(s) {
  return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function money(v) {
  const n = Math.abs(Number(v) || 0);
  const [ent, dec] = n.toFixed(2).split(".");
  return (Number(v) < 0 ? "-" : "") + "$" + ent.replace(/\B(?=(\d{3})+(?!\d))/g, ".") + "," + dec;
}
function fechaLarga(iso) {
  const p = String(iso || "").split("-");
  return p.length === 3 ? p[2] + "/" + p[1] + "/" + p[0] : "";
}
function sumarDias(iso, dias) {
  const d = new Date(iso + "T00:00:00Z");
  d.setUTCDate(d.getUTCDate() + dias);
  return d.toISOString().slice(0, 10);
}
const MESES = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"];
function mesLbl(m) {
  const p = String(m || "").split("-");
  return p.length === 2 ? (MESES[parseInt(p[1], 10) - 1] || "") + " " + p[0] : "";
}

// Facturas impagas con más de 60 días (mismo criterio que ccVencDias() del HTML).
function facturasVencidas(cc, hoyISO) {
  const ch = (cc && Array.isArray(cc.ch)) ? cc.ch : [];
  const hoy = Date.UTC(+hoyISO.slice(0, 4), +hoyISO.slice(5, 7) - 1, +hoyISO.slice(8, 10));
  const nc = {};
  ch.forEach((n) => { if (n && n.est === "Nota Crédito" && n.nc && n.nc.ref) (nc[n.nc.ref] = nc[n.nc.ref] || []).push(n); });
  const out = [];
  ch.forEach((c) => {
    if (!c || c.est !== "Pendiente" || !(Number(c.imp) > 0) || !/^\d{4}-\d{2}-\d{2}$/.test(c.f || "")) return;
    const notas = nc[c.id] || [];
    if (notas.some((n) => n.nc && n.nc.tipo === "total")) return;
    const dias = Math.round((hoy - Date.UTC(+c.f.slice(0, 4), +c.f.slice(5, 7) - 1, +c.f.slice(8, 10))) / 86400000);
    if (dias <= PLAZO) return;
    const parciales = notas.filter((n) => n.nc && n.nc.tipo === "parcial" && typeof n.imp === "number");
    const anulado = parciales.reduce((t, n) => t + Math.abs(n.imp), 0);
    out.push({ c, dias, parciales, saldo: parciales.length ? Math.round((c.imp - anulado) * 100) / 100 : null });
  });
  return out.sort((a, b) => b.dias - a.dias);
}

async function sendOverdueEmail(resendKey, to, v) {
  const c = v.c;
  const vence = sumarDias(c.f, PLAZO);
  const filas = [
    ["Nº de factura", c.fac || "(sin número)"],
    ["Razón social", c.razon || ""],
    ["Reserva", c.rva || ""],
    ["Fecha de emisión", fechaLarga(c.f)],
    ["Plazo máximo vencido el", fechaLarga(vence) + " (" + PLAZO + " días)"],
    ["Días desde la emisión", v.dias + " días"],
    ["Importe", money(c.imp)],
  ];
  if (v.saldo != null) {
    filas.push(["Notas de crédito parciales", v.parciales.map((n) => (n.fac || "s/n") + " (" + money(n.imp) + ")").join(", ")]);
    filas.push(["Saldo pendiente", money(v.saldo)]);
  }
  filas.push(["Período en Cuentas corrientes", mesLbl(c.m)]);
  filas.push(["Estado", "Pendiente (impaga)"]);
  if (c.cm) filas.push(["Comentario", c.cm]);
  const titulo = "La factura " + (c.fac || "s/n") + " excedió el plazo máximo de " + PLAZO + " días y continúa impaga";
  const trs = filas.filter((f) => String(f[1]).trim()).map((f) =>
    `<tr><td style="padding:7px 10px;color:#6b7280;font-size:13px;border-bottom:1px solid #f1e3e3;white-space:nowrap">${escapeHtml(f[0])}</td><td style="padding:7px 10px;font-size:14px;font-weight:700;color:#1f2937;border-bottom:1px solid #f1e3e3">${escapeHtml(f[1])}</td></tr>`).join("");
  const html = `<div style="font-family:Helvetica,Arial,sans-serif;background:#fdf6ec;padding:32px 16px">
  <div style="max-width:560px;margin:0 auto;background:#ffffff;border-radius:18px;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,.08)">
    <div style="background:#9b1c1c;padding:24px;text-align:center">
      <div style="font-size:32px;line-height:1">⚠️</div>
      <div style="color:#fff;font-weight:800;font-size:18px;margin-top:8px">Factura impaga: plazo de ${PLAZO} días excedido</div>
    </div>
    <div style="padding:22px 24px;color:#1f2937;font-size:15px;line-height:1.55">
      <p style="margin:0 0 14px">${escapeHtml(titulo)}.</p>
      <table style="width:100%;border-collapse:collapse">${trs}</table>
      <p style="margin:16px 0 0;color:#4b5563;font-size:13px">Podés verla en el sistema: Finanzas &gt; Cuentas corrientes (aparece resaltada en rojo).</p>
    </div>
    <div style="background:#f4f1ea;padding:14px 24px;text-align:center;font-size:11px;color:#9ca3af">Hotel Copahue Junín S.R.L. -- aviso automático, no respondas este correo</div>
  </div>
</div>`;
  const text = "Hotel Copahue · Cuentas corrientes\n\n" + titulo + ".\n\n" + filas.filter((f) => String(f[1]).trim()).map((f) => f[0] + ": " + f[1]).join("\n") + "\n\nPodés verla en el sistema: Finanzas > Cuentas corrientes.";
  const resp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${resendKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: "Hotel Copahue <informes@hotelcopahue.com>",
      to,
      subject: `⚠️ Factura ${c.fac || "s/n"} impaga: superó los ${PLAZO} días (${c.razon || "sin razón social"})`,
      text,
      html,
    }),
  });
  return resp.ok;
}

exports.handler = async () => {
  try {
    const projectId = process.env.FIREBASE_PROJECT_ID || "limpiezas-e3e75";
    const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
    const privateKey = unescapePrivateKey(process.env.FIREBASE_PRIVATE_KEY);
    const resendKey = process.env.RESEND_API_KEY;
    if (!clientEmail || !privateKey) return { statusCode: 200, body: "sin configurar (faltan credenciales de Firebase)" };
    if (!resendKey) return { statusCode: 200, body: "sin configurar (falta RESEND_API_KEY)" };

    const accessToken = await getAccessToken(clientEmail, privateKey);
    const [cc, users, fichas, enviados] = await Promise.all([
      readEstadoKey(projectId, accessToken, "ch_cuentascte", null),
      readEstadoKey(projectId, accessToken, "ch_users", []),
      readEstadoKey(projectId, accessToken, "ch_personalfichas", {}),
      readEstadoKey(projectId, accessToken, "ch_ccvencenviado", {}),
    ]);
    if (!cc) return { statusCode: 200, body: JSON.stringify({ ok: true, nota: "todavía no hay cuentas corrientes guardadas en la nube" }) };

    // Fecha de hoy en Argentina (UTC-3 fijo)
    const hoyISO = new Date(Date.now() - 3 * 3600 * 1000).toISOString().slice(0, 10);

    const seen = {};
    const destinatarios = [];
    (users || []).filter((u) => u && (u.area === "ger" || u.area === "admin")).forEach((u) => {
      const f = (fichas && fichas[u.id]) || {};
      const em = String(f.email || u.email || "").trim();
      if (!EMAIL_OK.test(em) || seen[em.toLowerCase()]) return;
      seen[em.toLowerCase()] = 1;
      destinatarios.push(em);
    });

    const vencidas = facturasVencidas(cc, hoyISO);
    const nuevo = { ...enviados };
    const resultados = [];
    if (destinatarios.length) {
      let n = 0;
      for (const v of vencidas) {
        if (nuevo[v.c.id]) continue;
        if (n >= 20) break; // el resto sale en la próxima corrida
        n++;
        const ok = await sendOverdueEmail(resendKey, destinatarios, v);
        resultados.push({ id: v.c.id, fac: v.c.fac, enviado: ok });
        if (ok) nuevo[v.c.id] = { ts: Date.now(), fac: v.c.fac || "", f: v.c.f };
        await new Promise((r) => setTimeout(r, 700)); // Resend admite ~2 envíos por segundo
      }
    }
    if (resultados.some((r) => r.enviado)) await writeEnviados(projectId, accessToken, nuevo);

    return {
      statusCode: 200,
      body: JSON.stringify({ ok: true, vencidas: vencidas.length, destinatarios: destinatarios.length, mailsEnviados: resultados.filter((r) => r.enviado).length, resultados }),
    };
  } catch (err) {
    console.error("send-overdue-invoices error:", err);
    return { statusCode: 500, body: JSON.stringify({ error: String((err && err.message) || err) }) };
  }
};
