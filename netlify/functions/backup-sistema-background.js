// (Tanda 586) Función «en segundo plano» de Netlify (el sufijo -background hace que responda enseguida y siga trabajando hasta 15 min):
// la dispara el botón «Enviar una copia por mail ahora» de Admin → «Copias de seguridad». Genera la misma copia que la de las 23:59
// y la manda por mail al destinatario configurado (SISTEMA_BACKUP_TO, por defecto copahueadmin@gmail.com).
// Si falla, manda un mail de aviso con el motivo (igual que la copia nocturna).
// Usa las mismas variables de entorno que backup-sistema.js (RESEND_API_KEY, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY).
// Para que no se pueda abusar, ignora pedidos que lleguen a menos de 3 minutos del anterior (misma instancia) y solo acepta POST con {"manual":true}.
const bk = require("./backup-sistema");
let ultimo = 0;
exports.handler = async (event) => {
  event = event || {};
  if ((event.httpMethod || "POST") !== "POST") return { statusCode: 405, body: "Método no permitido" };
  let body = {}; try { body = JSON.parse(event.body || "{}"); } catch (e) {}
  if (body.manual !== true) return { statusCode: 400, body: "Pedido inválido" };
  const ahora = Date.now();
  if (ahora - ultimo < 3 * 60 * 1000) { console.log("backup manual ignorado (pedido repetido)"); return { statusCode: 202 }; }
  ultimo = ahora;
  try {
    const res = await bk._t.run({ manual: true });
    console.log("backup-sistema (manual):", JSON.stringify(res));
    if (res.errores && res.errores.length) await bk._t.avisoFalla(res.errores.join(" | "));
  } catch (er) {
    console.error("backup-sistema (manual) falló:", er);
    await bk._t.avisoFalla(String((er && er.message) || er));
  }
  return { statusCode: 202 };
};
