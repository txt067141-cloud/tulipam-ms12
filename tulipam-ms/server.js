/**
 * 🌷 TULIPAM MS v5 — Backend real con BASE DE DATOS SQLite
 * - Usuarios + sesiones + historial de inicios guardados en tulipam.db
 * - Entrar / salir sin problema, multi-dispositivo
 * - Chat mundial + DMs + llamadas 1-a-1 WebRTC + canales privados
 * Ejecutar: npm install && npm start
 */
require('dotenv').config();
const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const multer = require('multer');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'tulipam-dev-cambia-esto-en-produccion-1234567890';
const CLIENT_URL = process.env.CLIENT_URL || true;
if (!process.env.JWT_SECRET) console.warn('⚠️  Usa JWT_SECRET largo en .env para producción.');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: CLIENT_URL === true ? true : CLIENT_URL, credentials: true } });

app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.socket.io"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:", "https:"],
      mediaSrc: ["'self'", "blob:", "data:"],
      connectSrc: ["'self'", "wss:", "ws:", "https:"],
    }
  },
  crossOriginEmbedderPolicy: false,
}));
app.use(cors({ origin: CLIENT_URL === true ? true : CLIENT_URL, credentials: true }));
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 200 });
app.use('/api/', apiLimiter);

// ================= BASE DE DATOS SQLite =================
const DB_PATH = path.join(__dirname, 'tulipam.db');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, name TEXT, email TEXT UNIQUE, hash TEXT, tfa TEXT, tfa_pending TEXT, created INTEGER);
CREATE TABLE IF NOT EXISTS profiles(user_id TEXT PRIMARY KEY, bio TEXT DEFAULT '', color TEXT DEFAULT '#8B5CF6', emoji TEXT DEFAULT '💜', status TEXT DEFAULT '🟣 en línea', avatarUrl TEXT DEFAULT '', bannerUrl TEXT DEFAULT '', videoUrl TEXT DEFAULT '', stickers TEXT DEFAULT '[]');
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, user_id TEXT, created INTEGER, expires INTEGER, ip TEXT, agent TEXT, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS logins(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, email TEXT, event TEXT, ip TEXT, time INTEGER);
CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY, room TEXT, user_id TEXT, uname TEXT, text TEXT, t TEXT, ts INTEGER);
CREATE TABLE IF NOT EXISTS dms(id TEXT PRIMARY KEY, conv TEXT, from_id TEXT, fromName TEXT, text TEXT, t TEXT, ts INTEGER);
CREATE TABLE IF NOT EXISTS friends(user_id TEXT, friend_id TEXT, PRIMARY KEY(user_id, friend_id));
CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY AUTOINCREMENT, from_id TEXT, to_id TEXT, t INTEGER, UNIQUE(from_id, to_id));
CREATE TABLE IF NOT EXISTS channels(id TEXT PRIMARY KEY, name TEXT, passHash TEXT, owner TEXT, owner_id TEXT, members TEXT DEFAULT '[]');
CREATE TABLE IF NOT EXISTS bots(id TEXT PRIMARY KEY, name TEXT, emoji TEXT, reply TEXT, owner TEXT);
CREATE INDEX IF NOT EXISTS idx_msg_room ON messages(room, ts);
CREATE INDEX IF NOT EXISTS idx_dm_conv ON dms(conv, ts);
`);

const q = {
  getUserByEmail: db.prepare('SELECT * FROM users WHERE email=?'),
  getUserById: db.prepare('SELECT * FROM users WHERE id=?'),
  addUser: db.prepare('INSERT INTO users(id,name,email,hash,created) VALUES(?,?,?,?,?)'),
  addProfile: db.prepare('INSERT OR IGNORE INTO profiles(user_id) VALUES(?)'),
  getProfile: db.prepare('SELECT * FROM profiles WHERE user_id=?'),
  addSession: db.prepare('INSERT INTO sessions(id,user_id,created,expires,ip,agent,active) VALUES(?,?,?,?,?,?,1)'),
  getSession: db.prepare('SELECT * FROM sessions WHERE id=?'),
  killSession: db.prepare('UPDATE sessions SET active=0 WHERE id=?'),
  killUserSessions: db.prepare('UPDATE sessions SET active=0 WHERE user_id=?'),
  userSessions: db.prepare('SELECT id,created,expires,ip,agent,active FROM sessions WHERE user_id=? ORDER BY created DESC LIMIT 20'),
  addLogin: db.prepare('INSERT INTO logins(user_id,email,event,ip,time) VALUES(?,?,?,?,?)'),
  userLogins: db.prepare('SELECT event,ip,time FROM logins WHERE user_id=? ORDER BY time DESC LIMIT 30'),
};

const esc = (s) => String(s ?? '').replace(/[&<>"'`=\/]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#x60;', '=': '&#x3D;', '/': '&#x2F;' }[c]));
const uid = () => crypto.randomUUID();
const nowT = () => new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
function logEvent(user_id, email, event, ip) {
  try { q.addLogin.run(user_id, email, event, String(ip || '').slice(0, 60), Date.now()); } catch {}
}

// ---- importar db.json vieja si existe (migración automática) ----
(function migrateOld() {
  const old = path.join(__dirname, 'db.json');
  if (!fs.existsSync(old)) return;
  try {
    const count = db.prepare('SELECT COUNT(*) c FROM users').get().c;
    if (count > 0) return;
    const O = JSON.parse(fs.readFileSync(old, 'utf8'));
    for (const u of (O.users || [])) {
      try {
        q.addUser.run(u.id, u.u, u.e, u.hash, u.created || Date.now());
        q.addProfile.run(u.id);
        if (u.tfa) db.prepare('UPDATE users SET tfa=? WHERE id=?').run(u.tfa, u.id);
        const p = (O.profiles || {})[u.id];
        if (p) db.prepare('UPDATE profiles SET bio=?,color=?,emoji=?,status=?,avatarUrl=?,bannerUrl=?,videoUrl=?,stickers=? WHERE user_id=?')
          .run(p.bio || '', p.color || '#8B5CF6', p.emoji || '💜', p.status || '🟣 en línea', p.avatarUrl || '', p.bannerUrl || '', p.videoUrl || '', JSON.stringify(p.stickers || []), u.id);
      } catch {}
    }
    console.log('📦 Migrados usuarios de db.json a tulipam.db');
  } catch (e) { console.log('Migración omitida:', e.message); }
})();

// ================= AUTH + SESIONES =================
function signToken(user, sid) {
  return jwt.sign({ id: user.id, u: user.name, e: user.email, sid }, JWT_SECRET, { expiresIn: '30d' });
}
function setCookie(res, token) {
  res.cookie('tulipam_token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 30 * 24 * 3600 * 1000 });
}
function authHTTP(req, res, next) {
  const token = req.cookies.tulipam_token || req.cookies.pliacs_token || (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No autenticado. Entra de nuevo.' });
  try {
    const d = jwt.verify(token, JWT_SECRET);
    if (d.sid) {
      const s = q.getSession.get(d.sid);
      if (!s || !s.active) return res.status(401).json({ error: 'Sesión cerrada. Entra de nuevo.' });
    }
    req.user = d; next();
  } catch { return res.status(401).json({ error: 'Sesión expirada. Entra de nuevo.' }); }
}

// Registro
app.post('/api/register', body('u').trim().isLength({ min: 2, max: 20 }), body('e').trim().isEmail(), body('p').isLength({ min: 4, max: 72 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'Revisa: usuario min 2 letras, email válido, clave min 4.' });
    let { u, e, p } = req.body;
    e = String(e).toLowerCase().trim(); u = String(u).trim().slice(0, 20);
    if (q.getUserByEmail.get(e)) return res.status(409).json({ error: 'Ese correo ya tiene cuenta. Pulsa Entrar.' });
    const hash = await bcrypt.hash(String(p), 10);
    const id = uid();
    q.addUser.run(id, esc(u), e, hash, Date.now());
    q.addProfile.run(id);
    const sid = uid();
    q.addSession.run(sid, id, Date.now(), Date.now() + 30 * 864e5, req.ip, String(req.headers['user-agent'] || '').slice(0, 120));
    logEvent(id, e, 'registro', req.ip);
    const user = { id, name: esc(u), email: e };
    const token = signToken({ id, name: esc(u), email: e }, sid);
    setCookie(res, token);
    res.json({ ok: true, msg: '¡Cuenta creada! Entrando...', token, user: { u: esc(u), e } });
  });

// Login — crea sesión en DB
app.post('/api/login', loginLimiter, async (req, res) => {
  const { e, p, tfaCode } = req.body;
  const email = String(e || '').toLowerCase().trim();
  const user = q.getUserByEmail.get(email);
  if (!user) { logEvent('-', email, 'login-fallido', req.ip); return res.status(401).json({ error: 'Credenciales inválidas.' }); }
  const ok = await bcrypt.compare(String(p || ''), user.hash);
  if (!ok) { logEvent(user.id, email, 'login-fallido', req.ip); return res.status(401).json({ error: 'Credenciales inválidas.' }); }
  if (user.tfa) {
    if (!tfaCode) return res.status(206).json({ need2FA: true, msg: 'Introduce tu código 2FA.' });
    const verified = speakeasy.totp.verify({ secret: user.tfa, encoding: 'base32', token: String(tfaCode), window: 1 });
    if (!verified) return res.status(401).json({ error: 'Código 2FA inválido.' });
  }
  const sid = uid();
  q.addSession.run(sid, user.id, Date.now(), Date.now() + 30 * 864e5, req.ip, String(req.headers['user-agent'] || '').slice(0, 120));
  logEvent(user.id, email, 'login', req.ip);
  const token = signToken({ id: user.id, name: user.name, email: user.email }, sid);
  setCookie(res, token);
  res.json({ ok: true, token, user: { u: user.name, e: user.email, tfa: !!user.tfa } });
});

// Logout — cierra SOLO esta sesión (las otras siguen abiertas)
app.post('/api/logout', (req, res) => {
  try {
    const token = req.cookies.tulipam_token || (req.headers.authorization || '').replace('Bearer ', '');
    if (token) { const d = jwt.verify(token, JWT_SECRET); if (d.sid) q.killSession.run(d.sid); logEvent(d.id, d.e, 'logout', req.ip); }
  } catch {}
  res.clearCookie('tulipam_token'); res.json({ ok: true });
});
// Cerrar todas las sesiones (todos los dispositivos)
app.post('/api/logout-all', authHTTP, (req, res) => {
  q.killUserSessions.run(req.user.id); logEvent(req.user.id, req.user.e, 'logout-all', req.ip);
  res.clearCookie('tulipam_token'); res.json({ ok: true });
});
// Mis sesiones + historial — para ver dónde entré
app.get('/api/sessions', authHTTP, (req, res) => {
  res.json({ sessions: q.userSessions.all(req.user.id), history: q.userLogins.all(req.user.id) });
});

// 2FA
app.post('/api/2fa/setup', authHTTP, async (req, res) => {
  const user = q.getUserById.get(req.user.id);
  const secret = speakeasy.generateSecret({ name: 'TulipamMS:' + user.email, length: 20 });
  db.prepare('UPDATE users SET tfa_pending=? WHERE id=?').run(secret.base32, user.id);
  const qr = await QRCode.toDataURL(secret.otpauth_url);
  res.json({ secret: secret.base32, qr });
});
app.post('/api/2fa/verify', authHTTP, (req, res) => {
  const user = q.getUserById.get(req.user.id);
  const ok = speakeasy.totp.verify({ secret: user.tfa_pending, encoding: 'base32', token: String(req.body.code), window: 1 });
  if (!ok) return res.status(400).json({ error: 'Código inválido.' });
  db.prepare('UPDATE users SET tfa=tfa_pending, tfa_pending=NULL WHERE id=?').run(user.id);
  res.json({ ok: true });
});
app.post('/api/2fa/disable', authHTTP, (req, res) => {
  db.prepare('UPDATE users SET tfa=NULL WHERE id=?').run(req.user.id); res.json({ ok: true });
});

app.get('/api/me', authHTTP, (req, res) => {
  const user = q.getUserById.get(req.user.id);
  if (!user) return res.status(404).json({ error: 'No existe' });
  res.json({ u: user.name, e: user.email, tfa: !!user.tfa });
});
app.post('/api/change-password', authHTTP, async (req, res) => {
  const { oldP, newP } = req.body;
  if (String(newP || '').length < 4) return res.status(400).json({ error: 'Nueva clave min 4.' });
  const user = q.getUserById.get(req.user.id);
  if (!(await bcrypt.compare(String(oldP || ''), user.hash))) return res.status(401).json({ error: 'Clave actual incorrecta.' });
  db.prepare('UPDATE users SET hash=? WHERE id=?').run(await bcrypt.hash(String(newP), 12), user.id);
  logEvent(user.id, user.email, 'cambio-clave', req.ip);
  res.json({ ok: true });
});

// Historial de sala
app.get('/api/history/:room', authHTTP, (req, res) => {
  const room = String(req.params.room).slice(0, 60);
  const rows = db.prepare('SELECT uname u, text, t FROM messages WHERE room=? ORDER BY ts DESC LIMIT 100').all(room).reverse();
  res.json(rows);
});

// Traductor gratis (para hablar entre países)
app.get('/api/translate', async (req, res) => {
  try {
    const t = String(req.query.q || '').slice(0, 500);
    const to = String(req.query.to || 'es').slice(0, 8);
    if (!t) return res.status(400).json({ error: 'Sin texto' });
    const r = await fetch('https://api.mymemory.translated.net/get?q=' + encodeURIComponent(t) + '&langpair=auto|' + encodeURIComponent(to), { signal: AbortSignal.timeout(8000) });
    const j = await r.json();
    res.json({ text: j?.responseData?.translatedText || t });
  } catch { res.status(500).json({ error: 'No se pudo traducir' }); }
});
app.get('/api/health', (req, res) => {
  const users = db.prepare('SELECT COUNT(*) c FROM users').get().c;
  res.json({ ok: true, app: 'Tulipam MS', users, online: online.size, db: 'sqlite' });
});

// Subidas
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
const upload = multer({
  dest: 'uploads/', limits: { fileSize: (Number(process.env.MAX_FILE_MB) || 5) * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    const ok = /^(image\/(png|jpeg|gif|webp)|audio\/(mpeg|ogg|wav)|video\/(mp4|webm)|application\/pdf|text\/plain)$/.test(file.mimetype);
    cb(ok ? null : new Error('Tipo no permitido'), ok);
  }
});
app.post('/api/upload', authHTTP, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Sin archivo' });
  logEvent(req.user.id, req.user.e, 'upload', req.ip);
  res.json({ url: '/uploads/' + req.file.filename, name: esc(req.file.originalname), size: req.file.size });
});

// ================= SOCKET.IO =================
function socketAuth(socket, next) {
  try {
    const m = socket.handshake.headers.cookie?.match(/(?:tulipam_token|pliacs_token)=([^;]+)/);
    const token = socket.handshake.auth?.token || (m && m[1]);
    if (!token) return next(new Error('No auth'));
    const d = jwt.verify(decodeURIComponent(token), JWT_SECRET);
    if (d.sid) { const s = q.getSession.get(d.sid); if (!s || !s.active) return next(new Error('Sesión cerrada')); }
    socket.user = d; next();
  } catch { next(new Error('Auth inválida')); }
}
io.use(socketAuth);
const online = new Map();
const voiceRooms = new Map();

io.on('connection', (socket) => {
  online.set(socket.id, { u: socket.user.u, e: socket.user.e, id: socket.user.id });
  socket.join('u:' + socket.user.id);
  io.emit('presence', [...online.values()].map(o => o.u));
  let lastMsg = 0;
  socket.on('message', ({ room, text }) => {
    room = String(room || socket.data.room || '0:mundo').slice(0, 60);
    text = String(text || '').slice(0, 500).trim(); if (!text) return;
    if (Date.now() - lastMsg < 700) return; lastMsg = Date.now();
    let safe = esc(text).replace(/\*\*(.+?)\*\*/g, '<b>$1</b>');
    const msg = { id: uid(), u: socket.user.u, text: safe, t: nowT() };
    db.prepare('INSERT INTO messages(id,room,user_id,uname,text,t,ts) VALUES(?,?,?,?,?,?,?)').run(msg.id, room, socket.user.id, socket.user.u, safe, msg.t, Date.now());
    db.prepare('DELETE FROM messages WHERE room=? AND id NOT IN (SELECT id FROM messages WHERE room=? ORDER BY ts DESC LIMIT 300)').run(room, room);
    io.to(room).emit('message', msg);
    // bots
    const bots = db.prepare('SELECT * FROM bots').all();
    for (const b of bots) {
      if (text.toLowerCase().includes(b.name.toLowerCase()) || text.startsWith('!')) {
        const bm = { id: uid(), u: b.emoji + ' ' + b.name, text: esc(b.reply), t: nowT(), bot: 1 };
        setTimeout(() => {
          db.prepare('INSERT INTO messages(id,room,user_id,uname,text,t,ts) VALUES(?,?,?,?,?,?,?)').run(bm.id, room, 'bot', bm.u, bm.text, bm.t, Date.now());
          io.to(room).emit('message', bm);
        }, 900);
        break;
      }
    }
  });
  socket.on('dm-send', ({ to, text }) => {
    text = String(text || '').slice(0, 500).trim(); if (!text || !to) return;
    const id = [socket.user.id, String(to)].sort().join('__');
    const safe = esc(text).replace(/\*\*(.+?)\*\*/g, '<b>$1</b>');
    const dm = { id: uid(), from: socket.user.id, fromName: socket.user.u, text: safe, t: nowT() };
    db.prepare('INSERT INTO dms(id,conv,from_id,fromName,text,t,ts) VALUES(?,?,?,?,?,?,?)').run(dm.id, id, dm.from, dm.fromName, safe, dm.t, Date.now());
    io.to('u:' + to).emit('dm-receive', dm); socket.emit('dm-receive', dm);
  });
  socket.on('join', (room, cb) => {
    room = String(room || '0:mundo').slice(0, 60);
    if (room.startsWith('p:')) {
      const c = db.prepare('SELECT * FROM channels WHERE id=?').get(room.slice(2));
      const members = c ? JSON.parse(c.members || '[]') : [];
      if (!c || !members.includes(socket.user.id)) { if (typeof cb === 'function') cb([{ u: '🔒 Sistema', text: 'No eres miembro de este canal privado.', t: 'ahora', sys: 1 }]); return; }
    }
    socket.join(room); socket.data.room = room;
    if (typeof cb === 'function') {
      const rows = db.prepare('SELECT uname u, text, t FROM messages WHERE room=? ORDER BY ts DESC LIMIT 100').all(room).reverse();
      cb(rows);
    }
  });
  socket.on('typing', (room) => socket.to(room).emit('typing', socket.user.u));
  // Voz grupal + llamadas 1-a-1 (voiceId = call_<conv>)
  socket.on('voice-join', (voiceId) => {
    voiceId = String(voiceId).slice(0, 60);
    if (!voiceRooms.has(voiceId)) voiceRooms.set(voiceId, new Map());
    const roomV = voiceRooms.get(voiceId);
    for (const [id, user] of roomV) { io.to(id).emit('voice-new-peer', { id: socket.id, u: socket.user.u }); socket.emit('voice-new-peer', { id, u: user.u }); }
    roomV.set(socket.id, { u: socket.user.u });
    socket.data.voiceId = voiceId;
    io.emit('voice-update', { voiceId, users: [...roomV.values()].map(x => x.u) });
  });
  // Llamada directa a un amigo: le avisa aunque no esté en voz
  socket.on('call-user', ({ to }) => {
    io.to('u:' + to).emit('incoming-call', { from: socket.user.id, fromName: socket.user.u });
  });
  socket.on('voice-leave', () => leaveVoice(socket));
  socket.on('signal', ({ to, data }) => { if (to) io.to(to).emit('signal', { from: socket.id, data }); });
  socket.on('disconnect', () => { online.delete(socket.id); leaveVoice(socket); io.emit('presence', [...online.values()].map(o => o.u)); });
});
function leaveVoice(socket) {
  const v = socket.data.voiceId;
  if (v && voiceRooms.has(v)) {
    voiceRooms.get(v).delete(socket.id);
    for (const [id] of voiceRooms.get(v)) io.to(id).emit('voice-peer-left', { id: socket.id });
    io.emit('voice-update', { voiceId: v, users: [...voiceRooms.get(v).values()].map(x => x.u) });
    socket.data.voiceId = null;
  }
}

// ===== perfiles, amigos, bots, DMs, canales =====
app.get('/api/users', authHTTP, (req, res) => {
  const search = String(req.query.q || '').toLowerCase();
  let users = db.prepare('SELECT id,name u,email e FROM users LIMIT 200').all();
  if (search) users = users.filter(x => x.u.toLowerCase().includes(search) || x.e.toLowerCase().includes(search));
  res.json(users.map(u => ({ ...u, p: getProf(u.id) })));
});
function getProf(id) {
  const p = q.getProfile.get(id) || {};
  let stickers = []; try { stickers = JSON.parse(p.stickers || '[]'); } catch {}
  return { bio: p.bio || '', color: p.color || '#8B5CF6', emoji: p.emoji || '💜', status: p.status || '🟣 en línea', avatarUrl: p.avatarUrl || '', bannerUrl: p.bannerUrl || '', videoUrl: p.videoUrl || '', stickers };
}
app.get('/api/profile/:id?', authHTTP, (req, res) => {
  const id = req.params.id || req.user.id;
  const u = q.getUserById.get(id); if (!u) return res.status(404).json({ error: 'No existe' });
  res.json({ id: u.id, u: u.name, e: u.email, ...getProf(id) });
});
app.put('/api/profile', authHTTP, (req, res) => {
  const { bio, color, emoji, status, u, stickers, videoUrl } = req.body;
  if (u && String(u).trim().length >= 2) db.prepare('UPDATE users SET name=? WHERE id=?').run(esc(String(u).trim().slice(0, 20)), req.user.id);
  const prev = getProf(req.user.id);
  db.prepare('UPDATE profiles SET bio=?,color=?,emoji=?,status=?,stickers=?,videoUrl=? WHERE user_id=?').run(
    esc(String(bio ?? prev.bio).slice(0, 300)), String(color || prev.color).slice(0, 9),
    String(emoji || prev.emoji).slice(0, 8), esc(String(status || prev.status).slice(0, 40)),
    JSON.stringify(Array.isArray(stickers) ? stickers.map(s => String(s).slice(0, 200)).slice(0, 12) : prev.stickers),
    String(videoUrl ?? prev.videoUrl).slice(0, 500), req.user.id);
  const user = q.getUserById.get(req.user.id);
  res.json({ ok: true, profile: getProf(req.user.id), u: user.name });
});
const avUpload = multer({ dest: 'uploads/', limits: { fileSize: 2 * 1024 * 1024 }, fileFilter: (qq, f, cb) => { cb(/^image\/(png|jpeg|gif|webp)$/.test(f.mimetype) ? null : new Error('Solo imagen'), /^image\/(png|jpeg|gif|webp)$/.test(f.mimetype)); } });
const banUpload = multer({ dest: 'uploads/', limits: { fileSize: 12 * 1024 * 1024 }, fileFilter: (qq, f, cb) => { const ok = /^(image\/(png|jpeg|gif|webp)|video\/(mp4|webm))$/.test(f.mimetype); cb(ok ? null : new Error('Solo imagen/video'), ok); } });
app.post('/api/profile/avatar', authHTTP, avUpload.single('img'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Sin imagen' });
  db.prepare('UPDATE profiles SET avatarUrl=? WHERE user_id=?').run('/uploads/' + req.file.filename, req.user.id);
  res.json({ ok: true, avatarUrl: '/uploads/' + req.file.filename });
});
app.post('/api/profile/banner', authHTTP, banUpload.single('img'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Sin archivo' });
  const url = '/uploads/' + req.file.filename; const isV = req.file.mimetype.startsWith('video/');
  db.prepare(isV ? 'UPDATE profiles SET videoUrl=? WHERE user_id=?' : 'UPDATE profiles SET bannerUrl=? WHERE user_id=?').run(url, req.user.id);
  res.json({ ok: true, url, isVideo: isV });
});
app.get('/api/channels', authHTTP, (req, res) => {
  res.json(db.prepare('SELECT * FROM channels').all().map(c => ({ id: c.id, name: c.name, owner: c.owner, locked: !!c.passHash, members: JSON.parse(c.members || '[]').length, imIn: JSON.parse(c.members || '[]').includes(req.user.id) })));
});
app.post('/api/channels', authHTTP, async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 20); if (name.length < 2) return res.status(400).json({ error: 'Nombre min 2' });
  const pass = String(req.body.password || '').slice(0, 50);
  const id = uid().slice(0, 8);
  db.prepare('INSERT INTO channels(id,name,passHash,owner,owner_id,members) VALUES(?,?,?,?,?,?)').run(id, esc(name), pass ? await bcrypt.hash(pass, 10) : null, req.user.u, req.user.id, JSON.stringify([req.user.id]));
  res.json({ ok: true, channel: { id, name } });
});
app.post('/api/channels/:id/join', authHTTP, async (req, res) => {
  const c = db.prepare('SELECT * FROM channels WHERE id=?').get(req.params.id); if (!c) return res.status(404).json({ error: 'No existe' });
  let members = JSON.parse(c.members || '[]');
  if (c.passHash && !members.includes(req.user.id)) { const ok = await bcrypt.compare(String(req.body.password || ''), c.passHash); if (!ok) return res.status(403).json({ error: '🔒 Contraseña incorrecta' }); }
  if (!members.includes(req.user.id)) { members.push(req.user.id); db.prepare('UPDATE channels SET members=? WHERE id=?').run(JSON.stringify(members), c.id); }
  res.json({ ok: true, room: 'p:' + c.id, name: c.name });
});
app.delete('/api/channels/:id', authHTTP, (req, res) => {
  db.prepare('DELETE FROM channels WHERE id=? AND owner_id=?').run(req.params.id, req.user.id); res.json({ ok: true });
});
app.get('/api/friends', authHTTP, (req, res) => {
  const mine = db.prepare('SELECT friend_id FROM friends WHERE user_id=?').all(req.user.id).map(r => r.friend_id);
  const friends = mine.map(id => { const u = q.getUserById.get(id); return u ? { id: u.id, u: u.name, p: getProf(id) } : null }).filter(Boolean);
  const pending = db.prepare('SELECT r.from_id from_id, u.name fromName FROM requests r JOIN users u ON u.id=r.from_id WHERE r.to_id=?').all(req.user.id);
  res.json({ friends, pending });
});
app.post('/api/friends/request', authHTTP, (req, res) => {
  const raw = String(req.body.email || req.body.q || '').trim();
  let target = q.getUserByEmail.get(raw.toLowerCase());
  if (!target) target = q.getUserById.get(raw) || db.prepare('SELECT * FROM users WHERE name=?').get(raw);
  if (!target) return res.status(404).json({ error: 'No hay usuario con ese email. Pídele que se registre en tu link.' });
  if (target.id === req.user.id) return res.status(400).json({ error: 'No puedes agregarte a ti mismo 😅' });
  if (db.prepare('SELECT 1 FROM friends WHERE user_id=? AND friend_id=?').get(req.user.id, target.id)) return res.status(400).json({ error: 'Ya son amigos.' });
  try { db.prepare('INSERT INTO requests(from_id,to_id,t) VALUES(?,?,?)').run(req.user.id, target.id, Date.now()); }
  catch { return res.status(400).json({ error: 'Ya enviaste solicitud.' }); }
  const s = [...io.sockets.sockets.values()].find(s => s.user?.id === target.id); if (s) s.emit('friend-req', { from: req.user.u });
  res.json({ ok: true, msg: 'Solicitud enviada a ' + target.name });
});
app.post('/api/friends/accept', authHTTP, (req, res) => {
  const { from } = req.body;
  const r = db.prepare('SELECT * FROM requests WHERE from_id=? AND to_id=?').get(from, req.user.id);
  if (!r) return res.status(404).json({ error: 'Solicitud no encontrada.' });
  db.prepare('DELETE FROM requests WHERE from_id=? AND to_id=?').run(from, req.user.id);
  db.prepare('INSERT OR IGNORE INTO friends(user_id,friend_id) VALUES(?,?)').run(req.user.id, from);
  db.prepare('INSERT OR IGNORE INTO friends(user_id,friend_id) VALUES(?,?)').run(from, req.user.id);
  res.json({ ok: true, msg: '¡Ahora son amigos! 🎉' });
});
app.delete('/api/friends/:id', authHTTP, (req, res) => {
  db.prepare('DELETE FROM friends WHERE user_id=? AND friend_id=?').run(req.user.id, req.params.id);
  res.json({ ok: true });
});
app.get('/api/bots', authHTTP, (req, res) => res.json(db.prepare('SELECT * FROM bots').all()));
app.post('/api/bots', authHTTP, (req, res) => {
  const { name, emoji, reply } = req.body;
  if (!name || String(name).trim().length < 2) return res.status(400).json({ error: 'Nombre min 2.' });
  const bot = { id: uid(), name: esc(String(name).slice(0, 20)), emoji: String(emoji || '🤖').slice(0, 4), reply: esc(String(reply || '¡Hola! Soy un bot 🤖').slice(0, 300)), owner: req.user.u };
  db.prepare('INSERT INTO bots(id,name,emoji,reply,owner) VALUES(?,?,?,?,?)').run(bot.id, bot.name, bot.emoji, bot.reply, bot.owner);
  res.json({ ok: true, bot });
});
app.delete('/api/bots/:id', authHTTP, (req, res) => { db.prepare('DELETE FROM bots WHERE id=?').run(req.params.id); res.json({ ok: true }); });
const dmId = (a, b) => [a, b].sort().join('__');
app.get('/api/dm/:uid', authHTTP, (req, res) => {
  res.json(db.prepare('SELECT from_id "from", fromName, text, t FROM dms WHERE conv=? ORDER BY ts ASC LIMIT 300').all(dmId(req.user.id, req.params.uid)));
});

server.listen(PORT, '0.0.0.0', () => console.log(`🌷💜 Tulipam MS + SQLite en puerto ${PORT}`));
