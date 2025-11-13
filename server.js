// server.js
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const { MongoClient, ObjectId } = require('mongodb');
const leoProfanity = require('leo-profanity');
const axios = require('axios');
const CIDRMatcher = require('cidr-matcher').default;
const { RateLimiterMemory } = require('rate-limiter-flexible');

require('dotenv').config();

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/incisohbet';
const OPER_PASSWORD = process.env.OPER_PASSWORD || 'changeme';
const IP_CHECK_API_KEY = process.env.IP_CHECK_API_KEY || ''; // optional external API key
const PORT = process.env.PORT || 3000;

const app = express();
app.use(helmet());
app.use(express.static('public'));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

// Profanity list
leoProfanity.loadDictionary(); // default dictionaries
// add custom bad words
leoProfanity.add(['s****', 'b****']); // örnek, kendi listeni ekle

// Rate limiter: mesaj başına (örnek)
const msgLimiter = new RateLimiterMemory({
  points: 5,
  duration: 3 // 5 mesaj / 3 sn
});

let db;
let usersCol, bansCol, channelsCol, opsCol;

// In-memory CIDR matcher for zline/gline (reload on changes)
let cidrMatcher = new CIDRMatcher([]);
async function reloadCIDR() {
  const bans = await bansCol.find({ type: { $in: ['zline','gline'] } }).toArray();
  const cidrs = bans.map(b => b.range).filter(Boolean);
  cidrMatcher = new CIDRMatcher(cidrs);
}

// Helper: get client IP (X-Forwarded-For if behind proxy)
function getClientIP(socket) {
  const xff = socket.handshake.headers['x-forwarded-for'];
  if (xff) return xff.split(',')[0].trim();
  const conn = socket.request.connection || socket.conn;
  return (socket.handshake.address || conn.remoteAddress || '').replace('::ffff:', '');
}

// Optional proxy/vpn check using external API (example for IPQualityScore)
// returns true if IP is bad (vpn/proxy/tor)
async function isProxyIP(ip) {
  if (!IP_CHECK_API_KEY) return false;
  try {
    const resp = await axios.get(`https://ipqualityscore.com/api/json/ip/${IP_CHECK_API_KEY}/${ip}`);
    const d = resp.data;
    // ipqualityscore fields: proxy, vpn, tor, recent_abuse, etc.
    return (d.proxy || d.vpn || d.tor || d.fraud_score > 80);
  } catch (e) {
    console.warn('IP check failed', e.message);
    return false;
  }
}

// Basic message sanitizer + profanity filter
function sanitizeMessage(text) {
  if (!text) return '';
  // strip excessive whitespace
  let t = text.trim();
  // profanity filter
  t = leoProfanity.clean(t);
  return t;
}

// Connect to MongoDB
async function initDb() {
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  db = client.db();
  usersCol = db.collection('users');
  bansCol = db.collection('bans');
  channelsCol = db.collection('channels');
  opsCol = db.collection('opers');
  await reloadCIDR();
}
initDb().catch(err => {
  console.error('MongoDB connection failed', err);
  process.exit(1);
});

// Basic Tom bot (server side)
const TOM_NAME = 'Tom';

async function sendTomMessage(room, text) {
  io.to(room).emit('message', { from: TOM_NAME, text, system: true, time: Date.now() });
}

// Utility: check banned
async function isBannedIP(ip) {
  if (!ip) return false;
  // check CIDR zline/gline
  if (cidrMatcher.contains(ip)) return true;
  const rec = await bansCol.findOne({ type: 'ip', ip });
  if (rec) return true;
  return false;
}

// Slash command handler
async function handleCommand(socket, cmdLine) {
  const parts = cmdLine.trim().split(/\s+/);
  const cmd = parts[0].toLowerCase();
  const args = parts.slice(1);

  const userObj = socket.user || { nick: socket.nick || 'Anon' };

  // /ns register <pass>
  if (cmd === '/ns' && args[0] === 'register') {
    const pass = args[1];
    if (!pass) { socket.emit('system', 'Kullanım: /ns register <şifre>'); return; }
    const existing = await usersCol.findOne({ nick: userObj.nick });
    if (existing) { socket.emit('system', 'Bu nick zaten kayıtlı.'); return; }
    const hash = await bcrypt.hash(pass, 10);
    await usersCol.insertOne({ nick: userObj.nick, pass: hash, created: new Date() });
    socket.emit('system', 'Kayıt başarılı. Şimdi /ns identify <şifre> ile giriş yap.');
    return;
  }

  // /ns identify <pass>
  if (cmd === '/ns' && args[0] === 'identify') {
    const pass = args[1];
    if (!pass) { socket.emit('system', 'Kullanım: /ns identify <şifre>'); return; }
    const user = await usersCol.findOne({ nick: userObj.nick });
    if (!user) { socket.emit('system', 'Bu nick kayıtlı değil. /ns register ile kayıt ol.'); return; }
    const ok = await bcrypt.compare(pass, user.pass);
    if (!ok) { socket.emit('system', 'Şifre yanlış.'); return; }
    socket.user = { nick: user.nick, id: user._id, roles: user.roles || [] };
    socket.emit('system', 'Başarıyla kimlik doğrulandı.');
    return;
  }

  // /oper <password>
  if (cmd === '/oper') {
    const pass = args[0];
    if (!pass) { socket.emit('system', 'Kullanım: /oper <şifre>'); return; }
    if (pass === OPER_PASSWORD) {
      socket.isOper = true;
      await opsCol.updateOne({ nick: socket.user?.nick || socket.nick }, { $set: { nick: socket.user?.nick || socket.nick, grantedAt: new Date() } }, { upsert: true });
      socket.emit('system', 'Oper yetkisi verildi.');
      return;
    } else {
      socket.emit('system', 'Oper şifresi yanlış.');
      return;
    }
  }

  // /zline add <cidr> <reason> -- oper only
  if (cmd === '/zline' && args[0] === 'add') {
    if (!socket.isOper) { socket.emit('system', 'Bu komut için oper olman lazım.'); return; }
    const range = args[1];
    const reason = args.slice(2).join(' ') || 'No reason';
    if (!range) { socket.emit('system', 'Kullanım: /zline add <CIDR> <reason>'); return; }
    await bansCol.insertOne({ type: 'zline', range, reason, created: new Date(), by: socket.user?.nick || socket.nick });
    await reloadCIDR();
    socket.emit('system', `Zline eklendi: ${range}`);
    return;
  }

  // /gline add <cidr>
  if (cmd === '/gline' && args[0] === 'add') {
    if (!socket.isOper) { socket.emit('system', 'Bu komut için oper olman lazım.'); return; }
    const range = args[1];
    const reason = args.slice(2).join(' ') || 'No reason';
    if (!range) { socket.emit('system', 'Kullanım: /gline add <CIDR> <reason>'); return; }
    await bansCol.insertOne({ type: 'gline', range, reason, created: new Date(), by: socket.user?.nick || socket.nick });
    await reloadCIDR();
    socket.emit('system', `Gline eklendi: ${range}`);
    return;
  }

  // /nick <yeniNick>
  if (cmd === '/nick') {
    const newnick = args[0];
    if (!newnick) { socket.emit('system', 'Kullanım: /nick <yeniNick>'); return; }
    const coll = await usersCol.findOne({ nick: newnick });
    if (coll) { socket.emit('system', 'Bu nick alınmış.'); return; }
    const old = socket.nick || 'Anon';
    socket.nick = newnick;
    socket.emit('system', `Nick değiştirildi: ${old} -> ${newnick}`);
    return;
  }

  // kanal komutları, chanserv vs. (basit owner değişikliği)
  if (cmd === '/chanserv' && args[0] === 'register') {
    const channel = args[1];
    if (!channel) { socket.emit('system', 'Kullanım: /chanserv register <#oda>'); return; }
    await channelsCol.updateOne({ name: channel }, { $set: { owner: socket.user?.nick || socket.nick, created: new Date() } }, { upsert: true });
    socket.emit('system', `${channel} kanalı kayıt edildi. Sahip: ${socket.user?.nick || socket.nick}`);
    return;
  }

  socket.emit('system', 'Bilinmeyen komut veya kullanım hatası.');
}

// On connection
io.on('connection', async (socket) => {
  const ip = getClientIP(socket);
  console.log('Yeni bağlantı:', ip);

  // Check bans
  if (await isBannedIP(ip)) {
    socket.emit('system', 'IP’niz yasaklı. Bağlantı kesiliyor.');
    socket.disconnect(true);
    return;
  }

  // Check proxy/vpn via external API (if enabled)
  try {
    if (await isProxyIP(ip)) {
      socket.emit('system', 'VPN/Proxy tespit edildi, erişim engellendi.');
      socket.disconnect(true);
      return;
    }
  } catch (e) {
    console.warn('IP check hata', e.message);
  }

  // initial nick (random)
  socket.nick = `Misafir${Math.floor(Math.random()*9000)+1000}`;
  socket.join('lobby'); // default oda
  sendTomMessage('lobby', `${socket.nick} aramıza katıldı.`);

  // on incoming chat message
  socket.on('chat', async (msg) => {
    try {
      await msgLimiter.consume(socket.id);
    } catch (rejRes) {
      socket.emit('system', 'Çok hızlı mesaj atıyorsun, yavaşla.');
      return;
    }

    if (typeof msg !== 'string') return;
    const trimmed = msg.trim();
    if (!trimmed) return;

    // commands start with '/'
    if (trimmed.startsWith('/')) {
      return handleCommand(socket, trimmed);
    }

    // sanitize + profanity
    const clean = sanitizeMessage(trimmed);
    if (!clean) return;

    // if contains banned words after cleaning, warn/auto delete
    if (leoProfanity.check(clean)) {
      socket.emit('system', 'Mesajınız uygun değil, kurallara uyun.');
      // warning logic and tempban on repeats (example)
      socket.warnings = (socket.warnings || 0) + 1;
      if (socket.warnings >= 3) {
        await bansCol.insertOne({ type: 'ip', ip, reason: 'Küfür/isteksiz davranış', created: new Date() });
        socket.emit('system', 'Çok fazla uyarı, IP’niz yasaklandı.');
        socket.disconnect(true);
      }
      return;
    }

    // broadcast to room(s)
    // message object: { from, text, time, room }
