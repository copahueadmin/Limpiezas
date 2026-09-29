// (Tanda 105 / ítem 3, parte 3) Función serverless PROGRAMADA de Netlify: corre sola, sin que nadie
// tenga la app abierta (ver el schedule en netlify.toml). Revisa quién cumple años hoy (leyendo el
// personal directo de Firestore, que es la fuente de verdad que ya sincroniza sola entre todos los
// dispositivos) y le manda un mail de cumpleaños con estética prolija vía Resend, igual que ya se
// pidió que hiciera el efecto de globos + el mensaje atrasado dentro de la propia app (ver
// birthdayCheckOnLogin() en sistema_de_limpiezas.html) -- este archivo es la única pieza de esos 3
// puntos que necesitaba correr en un servidor en vez de en el navegador de quien inicia sesión.
// (Tanda 108 / ítem 2) El schedule en netlify.toml pasó de "una vez por día a las 00:01hs Argentina en
// punto" a "cada 15 minutos, todo el día" -- el scheduler de Netlify no garantiza el minuto exacto de
// disparo, así que un horario único corría el riesgo de atrasarse bastante (o directamente no
// disparar) sin que nadie lo notara. La función en sí NO cambió su lógica para esto: el chequeo de
// abajo (`enviadosNuevo[p.id] >= yToday`) ya evitaba mandar el mail 2 veces si se la llegaba a llamar
// más de una vez el mismo día -- eso es justamente lo que ahora se aprovecha para que, sin importar
// cuál de las corridas del día sea la que efectivamente ande bien, el mail salga una sola vez y lo más
// cerca posible de las 00:01hs.
//
// A DIFERENCIA de send-email.js (Tanda 26), esta función no la llama el sitio -- la dispara sola el
// scheduler de Netlify -- así que necesita SUS PROPIAS credenciales para poder leer Firestore (el
// navegador ya puede leerlo/escribirlo porque carga el SDK de Firebase con las reglas de seguridad
// del proyecto, pero un servidor no tiene ese contexto -- necesita autenticarse como una cuenta de
// servicio de Firebase, que si tiene permiso para leer/escribir sin pasar por esas reglas).
//
// PARA QUE FUNCIONE, además de RESEND_API_KEY (que ya tiene que estar configurada desde la Tanda 26),
// quien administre el hotel tiene que, UNA SOLA VEZ:
//   1. Ir a la consola de Firebase (https://console.firebase.google.com/) → abrir el proyecto
//      "limpiezas-e3e75" (el mismo que ya usa la app) → ⚙️ Configuración del proyecto → pestaña
//      "Cuentas de servicio" → botón "Generar nueva clave privada". Se descarga un archivo .json.
//   2. De ese archivo .json, copiar 2 valores a Netlify (Site settings → Environment variables):
//        FIREBASE_CLIENT_EMAIL = el valor del campo "client_email" del .json (tal cual, sin comillas)
//        FIREBASE_PRIVATE_KEY  = el valor del campo "private_key" del .json (el bloque que empieza con
//                                 "-----BEGIN PRIVATE KEY-----" -- Netlify permite pegar saltos de
//                                 línea reales en el valor de la variable; si el editor de Netlify no
//                                 los deja pegar así, se puede pegar todo en una sola línea reemplazando
//                                 cada salto de línea por la secuencia de 2 caracteres \n -- este
//                                 archivo ya contempla ambos casos, ver unescapePrivateKey() abajo).
//      NUNCA subir ese .json al repositorio de GitHub -- las claves van solo en Netlify.
//   3. (Opcional) Si en algún momento se migrara a otro proyecto de Firebase, cargar también
//      FIREBASE_PROJECT_ID con el nuevo project id -- mientras se siga usando "limpiezas-e3e75" (el
//      de siempre) no hace falta, ya queda como valor por defecto.
// Mientras falte alguna de estas variables, la función no rompe nada -- se guarda un aviso en los
// logs de Netlify (Functions → send-birthday-emails → registros) y no manda ningún mail, exactamente
// el mismo criterio ya usado en send-email.js cuando falta RESEND_API_KEY.
//
// No usa NINGUNA librería externa (ni firebase-admin, ni googleapis) -- solo `crypto` (viene con
// Node) y `fetch` (disponible desde Node 18, que es el runtime que usa Netlify Functions por
// default) -- así no hace falta ningún package.json ni paso de `npm install` para que esto se
// despliegue: arma a mano el JWT firmado de la cuenta de servicio, lo cambia por un token de acceso
// de Google, y llama directo a la API REST de Firestore.

const crypto = require("crypto");

function base64url(input) {
  return Buffer.from(input).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unescapePrivateKey(raw) {
  // Admite tanto una clave pegada con saltos de línea reales como una pegada en una sola línea con
  // "\n" literales (2 caracteres) -- ver el punto 2 de las instrucciones de arriba.
  return String(raw || "").includes("\\n") ? raw.replace(/\\n/g, "\n") : raw;
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

// Lee un documento de la colección "estado" (la misma que usa el navegador vía
// fsDB.collection("estado").doc(key)) por su REST API, y devuelve el JSON ya parseado que había en
// el campo `v` (el mismo shape que graba cloudPush() en el HTML: {v: rawJSON, t: timestamp}).
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

// Escribe (reemplazando entero) el documento de control ch_cumpleemailenviado -- es un documento
// propio de esta función, no lo lee ni lo necesita el navegador, así que no hace falta darlo de alta
// en K/D del HTML: solo evita mandar 2 veces el mismo mail si la función se llega a disparar más de
// una vez en el mismo día (reintentos, disparo manual de prueba, etc.).
async function writeEnviados(projectId, accessToken, enviados) {
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/estado/ch_cumpleemailenviado`;
  const body = { fields: { v: { stringValue: JSON.stringify(enviados) }, t: { integerValue: String(Date.now()) } } };
  const resp = await fetch(url, {
    method: "PATCH",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    const data = await resp.json().catch(() => ({}));
    console.warn("No se pudo guardar ch_cumpleemailenviado (no es grave, en el peor caso se reintenta el mail):", data);
  }
}

function escapeHtml(s) {
  return String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Mismo remitente y misma cuenta de Resend que ya usa send-email.js (Tanda 26) -- acá se llama
// directo (sin pasar por ese archivo) porque esta función no recibe pedidos HTTP de nadie, la
// dispara sola el scheduler.
async function sendBirthdayEmail(resendKey, to, nombreCorto, edad) {
  const nombreSeguro = escapeHtml(nombreCorto);
  const edadHtml =
    edad && edad > 0
      ? `Hoy cumplís <strong>${edad} años</strong> -- ¡y en Hotel Copahue lo festejamos con vos!`
      : "¡Que tengas un día espectacular!";
  const html = `<div style="font-family:Helvetica,Arial,sans-serif;background:#fdf6ec;padding:32px 16px">
  <div style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:18px;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,.08)">
    <div style="background:linear-gradient(135deg,#0f766e,#134e4a);padding:28px 24px;text-align:center">
      <div style="font-size:40px;line-height:1">🎉🎂🎈</div>
      <div style="color:#fff;font-weight:800;font-size:22px;margin-top:6px">¡Feliz cumpleaños, ${nombreSeguro}!</div>
    </div>
    <div style="padding:26px 24px;color:#1f2937;font-size:15px;line-height:1.55">
      <p style="margin:0 0 14px">${edadHtml}</p>
      <p style="margin:0 0 14px">De parte de todo el equipo de <strong>Hotel Copahue</strong>, esperamos que pases un día muy lindo junto a quienes más querés.</p>
      <p style="margin:0;font-weight:700;color:#0f766e">¡Feliz día! 🎁</p>
    </div>
    <div style="background:#f4f1ea;padding:14px 24px;text-align:center;font-size:11px;color:#9ca3af">Hotel Copahue Junín S.R.L.</div>
  </div>
</div>`;
  const text = `¡Feliz cumpleaños, ${nombreCorto}! ${edad && edad > 0 ? `Hoy cumplís ${edad} años. ` : ""}De parte de todo el equipo de Hotel Copahue, ¡que la pases muy lindo!`;
  const resp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${resendKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: "Hotel Copahue <informes@hotelcopahue.com>",
      to: [to],
      subject: `🎉 ¡Feliz cumpleaños, ${nombreCorto}!`,
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
      console.warn("send-birthday-emails: faltan FIREBASE_CLIENT_EMAIL/FIREBASE_PRIVATE_KEY -- ver instrucciones al principio de este archivo.");
      return { statusCode: 200, body: "sin configurar (faltan credenciales de Firebase)" };
    }
    if (!resendKey) {
      console.warn("send-birthday-emails: falta RESEND_API_KEY.");
      return { statusCode: 200, body: "sin configurar (falta RESEND_API_KEY)" };
    }

    const accessToken = await getAccessToken(clientEmail, privateKey);
    const [users, mu, fichas, enviados] = await Promise.all([
      readEstadoKey(projectId, accessToken, "ch_users", []),
      readEstadoKey(projectId, accessToken, "ch_mu", []),
      readEstadoKey(projectId, accessToken, "ch_personalfichas", {}),
      readEstadoKey(projectId, accessToken, "ch_cumpleemailenviado", {}),
    ]);

    // Hora de Argentina (UTC-3 fijo, sin horario de verano) para decidir qué día es "hoy" -- el
    // servidor de Netlify corre en UTC.
    const nowArg = new Date(Date.now() - 3 * 60 * 60 * 1000);
    const yToday = nowArg.getUTCFullYear(), mToday = nowArg.getUTCMonth() + 1, dToday = nowArg.getUTCDate();

    // (Tanda 109) Se suma "apodo" acá -- antes esta función ni lo leía, así que el mail siempre saludaba
    // por la primera palabra del nombre completo. Ver el comentario junto a nombreCorto más abajo.
    const personal = [...(mu || []).map((m) => ({ id: m.id, nombre: m.nombre, apodo: m.apodo || "" })), ...(users || []).map((u) => ({ id: u.id, nombre: u.nombre, apodo: u.apodo || "" }))];

    const enviadosNuevo = { ...enviados };
    const resultados = [];
    for (const p of personal) {
      const ficha = fichas && fichas[p.id];
      if (!ficha || !ficha.nacimiento || !ficha.email) continue;
      const partes = String(ficha.nacimiento).split("-");
      if (partes.length !== 3) continue;
      const bYear = parseInt(partes[0], 10), bMonth = parseInt(partes[1], 10), bDay = parseInt(partes[2], 10);
      if (!bYear || !bMonth || !bDay) continue;
      if (bMonth !== mToday || bDay !== dToday) continue;
      if ((enviadosNuevo[p.id] || 0) >= yToday) continue; // ya se le mandó el mail este año
      const edad = yToday - bYear;
      // (Tanda 109) El mail ahora saluda por el APODO si la persona tiene uno cargado (igual que el
      // saludo/efecto de globos dentro de la propia app, ver birthdayCheckOnLogin() en
      // sistema_de_limpiezas.html) -- se usa tal cual, sin partirlo por espacio (un apodo compuesto
      // como "El Colo" no debería quedar truncado a "El"). Sin apodo, se sigue usando la primera
      // palabra del nombre completo, como ya se hacía.
      const apodo = (p.apodo || "").trim();
      const nombreCorto = apodo || (p.nombre || "").trim().split(" ")[0] || p.nombre || "";
      const ok = await sendBirthdayEmail(resendKey, ficha.email, nombreCorto, edad > 0 ? edad : null);
      resultados.push({ id: p.id, email: ficha.email, enviado: ok });
      if (ok) enviadosNuevo[p.id] = yToday;
    }

    if (resultados.some((r) => r.enviado)) {
      await writeEnviados(projectId, accessToken, enviadosNuevo);
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ ok: true, personalRevisado: personal.length, mailsEnviados: resultados.filter((r) => r.enviado).length, resultados }),
    };
  } catch (err) {
    console.error("send-birthday-emails error:", err);
    return { statusCode: 500, body: JSON.stringify({ error: String(err && err.message || err) }) };
  }
};
