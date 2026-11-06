// (Tanda 116 / ítem 2) Función serverless PROGRAMADA de Netlify: corre sola, sin que nadie tenga la
// app abierta (ver el schedule en netlify.toml). Revisa, leyendo el personal directo de Firestore
// (misma fuente de verdad que ya sincroniza sola entre todos los dispositivos, igual que
// send-birthday-emails.js), a quién le pasaron ya 136 días desde su fecha de ingreso -- es decir, a
// quién le queda 1 mes y medio para terminar su período de prueba -- y le manda un mail con asunto
// "importante" a cada usuario de Gerencia, a su email registrado en la Ficha de personal
// (D.personalFichas[id].email, el mismo campo que ya edita "Ficha de personal" dentro de la app).
// Es la contraparte por mail del aviso fijo que aparece en el "Inicio" de Gerencia dentro de la propia
// app (ver probationNotifHtml() en sistema_de_limpiezas.html) -- misma condición de disparo (136 días),
// pero el mail tiene SU PROPIO control de "ya se mandó" (ch_probationemailenviado, un doc propio de
// esta función, no lo lee ni lo necesita el navegador), independiente de si Gerencia ya descartó a
// mano el aviso dentro de la app: descartar el aviso en pantalla no debería poder cancelar en
// silencio un mail importante que todavía no salió.
//
// A diferencia del cumpleaños (que se dispara "hoy es tu día" y deja de aplicar al día siguiente), el
// umbral de 136 días es un evento de una sola vez por persona -- por eso acá "ya enviado" es
// simplemente `true`/ausente (no hace falta guardar ningún año como en
// ch_cumpleemailenviado), y por lo mismo esta función no necesita correr cada 15 minutos como esa: no
// hay un día exacto que se pueda "perder" -- una vez que se cruzan los 136 días el aviso sigue
// aplicando indefinidamente hasta mandarse, así que alcanza con revisarlo una vez por día. Ver el
// comentario grande al principio de send-birthday-emails.js para el detalle de por qué esta función
// necesita sus propias credenciales de Firebase (FIREBASE_CLIENT_EMAIL/FIREBASE_PRIVATE_KEY) además
// de RESEND_API_KEY -- son EXACTAMENTE las mismas 3 variables de entorno, ya configuradas en Netlify
// desde que se agregó send-birthday-emails.js: esta función nueva no necesita ninguna variable nueva.
//
// Igual que send-birthday-emails.js: sin librerías externas (solo `crypto` + `fetch`), autoconstruye
// el JWT firmado de la cuenta de servicio y llama directo a la API REST de Firestore.

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

function escapeHtml(s) {
  return String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

const MESES_FULL = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"];

// (Identificación pedida por el usuario: "Nombre completo + mes de ingreso" -- nunca apodo.)
async function sendProbationEmail(resendKey, to, nombreCompleto, mesLbl, anio) {
  const nombreSeguro = escapeHtml(nombreCompleto);
  const html = `<div style="font-family:Helvetica,Arial,sans-serif;background:#fdf6ec;padding:32px 16px">
  <div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:18px;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,.08)">
    <div style="background:linear-gradient(135deg,#0f4c5c,#146575);padding:28px 24px;text-align:center">
      <div style="font-size:36px;line-height:1">⚠️⏳</div>
      <div style="color:#fff;font-weight:800;font-size:20px;margin-top:8px">Período de prueba por finalizar</div>
    </div>
    <div style="padding:26px 24px;color:#1f2937;font-size:15px;line-height:1.55">
      <p style="margin:0 0 14px"><strong>${nombreSeguro}</strong> (ingresó en ${mesLbl} de ${anio}) está a 1 mes y medio de finalizar su período de prueba.</p>
      <p style="margin:0;color:#4b5563;font-size:13px">Este aviso también queda fijo en "Inicio" dentro del sistema, en la sesión de Gerencia, hasta que se descarte a mano.</p>
    </div>
    <div style="background:#f4f1ea;padding:14px 24px;text-align:center;font-size:11px;color:#9ca3af">Hotel Copahue Junín S.R.L. -- Sistema de limpiezas</div>
  </div>
</div>`;
  const text = `IMPORTANTE: ${nombreCompleto} (ingresó en ${mesLbl} de ${anio}) está a 1 mes y medio de finalizar su período de prueba.`;
  const resp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${resendKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: "Hotel Copahue <informes@hotelcopahue.com>",
      to: [to],
      subject: `⚠️ IMPORTANTE: período de prueba de ${nombreCompleto} está por finalizar`,
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

    if (!clientEmail || !privateKey) {
      console.warn("send-probation-alerts: faltan FIREBASE_CLIENT_EMAIL/FIREBASE_PRIVATE_KEY -- ver instrucciones al principio de send-birthday-emails.js (son las mismas variables).");
      return { statusCode: 200, body: "sin configurar (faltan credenciales de Firebase)" };
    }
    if (!resendKey) {
      console.warn("send-probation-alerts: falta RESEND_API_KEY.");
      return { statusCode: 200, body: "sin configurar (falta RESEND_API_KEY)" };
    }

    const accessToken = await getAccessToken(clientEmail, privateKey);
    const [users, mu, fichas, enviados] = await Promise.all([
      readEstadoKey(projectId, accessToken, "ch_users", []),
      readEstadoKey(projectId, accessToken, "ch_mu", []),
      readEstadoKey(projectId, accessToken, "ch_personalfichas", {}),
      readEstadoKey(projectId, accessToken, "ch_probationemailenviado", {}),
    ]);

    // Hora de Argentina (UTC-3 fijo) para calcular "hace cuántos días" ingresó cada persona.
    const nowArgMs = Date.now() - 3 * 60 * 60 * 1000;

    // Personal de las 6 áreas (mismo criterio que personalFichaPersonalList() en el HTML): mucamas +
    // el resto de los roles. `nombre` siempre es el nombre completo -- nunca se usa `apodo` acá,
    // porque el usuario pidió explícitamente "Nombre completo + mes de ingreso", nunca apodo.
    const personal = [
      ...(mu || []).map((m) => ({ id: m.id, nombre: m.nombre, ingreso: m.ingreso })),
      ...(users || []).filter((u) => ["rec", "mant", "ger", "admin", "coord"].includes(u.area)).map((u) => ({ id: u.id, nombre: u.nombre, ingreso: u.ingreso })),
    ];

    // Destinatarios: todos los usuarios de Gerencia que tengan email cargado en su Ficha de personal.
    const gerenciaIds = (users || []).filter((u) => u.area === "ger").map((u) => u.id);
    const destinatarios = gerenciaIds.map((id) => fichas && fichas[id] && fichas[id].email).filter((email) => email && String(email).trim());

    const enviadosNuevo = { ...enviados };
    const resultados = [];
    if (destinatarios.length) {
      for (const p of personal) {
        if (!p.ingreso) continue;
        if (enviadosNuevo[p.id]) continue; // ya se mandó este mail para esta persona (evento único, no anual)
        const partes = String(p.ingreso).split("-");
        if (partes.length !== 3) continue;
        const ingresoMs = new Date(p.ingreso + "T00:00:00Z").getTime() - 3 * 60 * 60 * 1000;
        if (!ingresoMs) continue;
        const dias = (nowArgMs - ingresoMs) / 86400000;
        if (dias < 136) continue;
        const mIdx = parseInt(partes[1], 10) - 1;
        const mesLbl = MESES_FULL[mIdx] || "";
        const anio = partes[0];
        let algunOk = false;
        for (const to of destinatarios) {
          const ok = await sendProbationEmail(resendKey, to, p.nombre || "Un empleado", mesLbl, anio);
          resultados.push({ id: p.id, to, enviado: ok });
          if (ok) algunOk = true;
        }
        if (algunOk) enviadosNuevo[p.id] = true;
      }
    }

    if (resultados.some((r) => r.enviado)) {
      await writeEnviados(projectId, accessToken, enviadosNuevo);
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ ok: true, personalRevisado: personal.length, destinatarios: destinatarios.length, mailsEnviados: resultados.filter((r) => r.enviado).length, resultados }),
    };
  } catch (err) {
    console.error("send-probation-alerts error:", err);
    return { statusCode: 500, body: JSON.stringify({ error: String(err && err.message || err) }) };
  }
};
