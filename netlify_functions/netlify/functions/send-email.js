// (Tanda 26) Función serverless de Netlify: es el único lugar donde vive la clave de Resend
// (RESEND_API_KEY, configurada como variable de entorno en Netlify -- Site settings → Environment
// variables -- NUNCA en el HTML ni en el repositorio de GitHub). El sitio (sistema_de_limpiezas.html)
// llama a esta función vía fetch("/.netlify/functions/send-email", {...}) en vez de llamar a Resend
// directamente desde el navegador, para no exponer la API key en el código del cliente.
//
// Espera un POST con body JSON: { to, subject, text, pdfBase64, pdfFilename }
//   - to: string con uno o varios destinatarios separados por coma (ej: "a@x.com, b@x.com")
//   - subject: asunto del mail
//   - text: cuerpo del mail en texto plano (resumen corto -- el detalle va en el PDF)
//   - pdfBase64: contenido del PDF ya codificado en base64 (sin el prefijo "data:...;base64,")
//   - pdfFilename: nombre de archivo del adjunto (ej: "informe-2026-09-11.pdf")
//
// Remitente fijo: informes@hotelcopahue.com (dominio verificado en Resend vía DNS en Donweb).
//
// Requiere en Netlify (Site settings → Environment variables):
//   RESEND_API_KEY = re_xxxxxxxx...   (se obtiene en resend.com, después de verificar el dominio)

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    return {
      statusCode: 500,
      body: JSON.stringify({
        error: "Falta configurar RESEND_API_KEY en las variables de entorno de Netlify.",
      }),
    };
  }

  let payload;
  try {
    payload = JSON.parse(event.body || "{}");
  } catch (e) {
    return { statusCode: 400, body: JSON.stringify({ error: "Body inválido (JSON esperado)." }) };
  }

  const { to, subject, text, pdfBase64, pdfFilename } = payload;
  if (!to || !subject) {
    return { statusCode: 400, body: JSON.stringify({ error: "Faltan campos requeridos (to, subject)." }) };
  }

  // Resend acepta "to" como string o array -- partimos por coma y limpiamos espacios para admitir
  // el mismo formato "a@x.com, b@x.com" que ya se usaba en el resto de la app.
  const toList = String(to)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  const body = {
    from: "Hotel Copahue <informes@hotelcopahue.com>",
    to: toList,
    subject,
    text: text || "",
  };

  if (pdfBase64 && pdfFilename) {
    body.attachments = [{ filename: pdfFilename, content: pdfBase64 }];
  }

  try {
    const resp = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });

    const data = await resp.json().catch(() => ({}));

    if (!resp.ok) {
      return {
        statusCode: resp.status,
        body: JSON.stringify({ error: "Resend rechazó el envío.", detail: data }),
      };
    }

    return { statusCode: 200, body: JSON.stringify({ ok: true, id: data.id }) };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "No se pudo contactar a Resend.", detail: String(err) }),
    };
  }
};
