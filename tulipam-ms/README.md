# 🌷💜 Tulipam MS v5 — Morada estilo Discord

Chat mundial + amigos + DMs + llamadas, con **base de datos real SQLite**.

## 💜 Qué incluye (todo lo que pediste)

### 1. Base de datos `tulipam.db` (SQLite)
- **Tabla `users`:** guarda todos los usuarios (nombre, email, clave cifrada)
- **Tabla `sessions`:** guarda cada inicio de sesión (dispositivo, IP, fecha). Entrar y salir sin problema, incluso en varios celulares/PC a la vez
- **Tabla `logins`:** historial de entradas/salidas (quién entró, cuándo, desde dónde)
- Los datos **quedan guardados** aunque cierres o reinicies el servidor
- Si tenías `db.json` vieja, se migra sola a SQLite

Ver tus sesiones: entra → botón **🔐** (al lado de salir) → ves dónde entraste + historial + **Salir de todos**.

### 2. Todo morado 💜
- Fondo morado oscuro, botones morados `#8B5CF6`, degradado morado en login
- Estilo Discord pero morado

### 3. Chat entre usuarios como Discord
- **Canales:** `#mundo` 🌍 (todos los países), `#general`, `#ayuda`, `#internacional` + privados 🔒 con contraseña
- **Amigos:** pestaña Amigos → Agregar por **email o nombre** → Solicitud → Aceptar
- **DMs:** clic en un amigo → 💌 → chat privado 1-a-1 (como Discord)
- **Llamadas 1-a-1:** abre el DM → 📞 (voz) o 🎥 (video). Al otro le llega **“Llamada entrante”** con Aceptar
- **Llamadas grupales:** 🔊 voz-general / voz-gaming
- **Bots, perfiles con foto/video, stickers, traductor 🌍, archivos**

## 🚀 Ponerla en internet (para hablar con otros países)

1. Sube `tulipam-ms` a GitHub
2. https://render.com → New → Web Service → conecta repo
   - Build: `npm install` · Start: `npm start`
   - Env: `JWT_SECRET`=clave larga · `NODE_ENV`=production
3. Deploy → te da `https://tulipam-ms.onrender.com`
4. Comparte el link. Todos se registran y aparecen en Gente.

> En Render el archivo `.db` se borra si haces redeploy gratis. Para producción seria usa disco persistente o Postgres. Para empezar/empezar con amigos está perfecto.

## 💻 Probar en tu PC

```
cd tulipam-ms
npm install
npm start
# http://localhost:3000
# Crea 2 cuentas en 2 navegadores → Agrega amigo → DM → 📞 llamar
```

## 📁 Archivos
- `server.js` → backend + SQLite
- `tulipam.db` → se crea sola al iniciar (usuarios + sesiones)
- `public/index.html` → app morada
- `uploads/` → fotos/videos
