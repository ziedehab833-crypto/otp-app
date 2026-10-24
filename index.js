const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ====== الإعدادات ======
const PORT = process.env.PORT || 3000; // تم التعديل عشان السحابة
const BOT_TOKEN = '8689380941:AAH5X5kpkNXlwEVUt_kFwG5TF1sHus-toQQ'; 

const OTP_TTL_MS = 5 * 60 * 1000;
const MAX_TRIES = 5;
const RESEND_COOLDOWN_MS = 60 * 1000;
const TOKEN_TTL_MS = 60 * 60 * 1000;

const users = new Map();
const index = new Map();
const sessions = new Map();
const tokens = new Map();

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const PHONE_RE = /^\+?\d{8,15}$/;

const isEmail = v => EMAIL_RE.test(String(v).trim());
const normPhone = v => String(v).replace(/[\s\-()]/g, '');
const isPhone = v => PHONE_RE.test(normPhone(v));
const indexKey = v => isPhone(v) ? normPhone(v) : String(v).trim().toLowerCase();

function genCode(len) {
  let out = '';
  while (out.length < len) out += crypto.randomInt(0, 10).toString();
  return out;
}

function maskDest(dest) {
  if (isEmail(dest)) {
    const [name, domain] = dest.split('@');
    return name.slice(0, 2) + '***@' + domain;
  }
  return normPhone(dest).slice(0, 3) + '****' + normPhone(dest).slice(-2);
}

function publicUser(u) {
  return { id: u.id, account: u.account, phone: u.phone };
}

function pickDestination(user, identifier) {
  if (isEmail(identifier)) return identifier.trim();
  if (user.phone) return normPhone(user.phone);
  if (isEmail(user.account)) return user.account;
  throw new Error('لا يوجد بريد إلكتروني');
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  return hash === crypto.scryptSync(password, salt, 64).toString('hex');
}

function getBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try { resolve(JSON.parse(body)); } catch { resolve({}); }
    });
  });
}

function sendJSON(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}

function sendTelegramMessage(chatId, text) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({ chat_id: chatId, text: text, parse_mode: 'HTML' });

    const options = {
      hostname: 'api.telegram.org',
      path: `/bot${BOT_TOKEN}/sendMessage`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      }
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => body += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) resolve();
        else {
          console.error('Telegram API Error:', body);
          reject(new Error('فشل إرسال الرسالة. تأكد أنك عملت Start للبوت.'));
        }
      });
    });

    req.on('error', () => reject(new Error('مشكلة في الاتصال بسيرفر تيليجرام')));
    req.write(data);
    req.end();
  });
}

function checkOtp(sessionId, code) {
  const s = sessions.get(sessionId);
  if (!s) throw new Error('انتهت الجلسة');
  if (Date.now() > s.expiresAt) throw new Error('انتهت صلاحية الكود');
  if (s.tries >= MAX_TRIES) throw new Error('محاولات كثيرة خاطئة');
  s.tries++;
  if (s.code !== String(code)) throw new Error('الكود غير صحيح');
  return s;
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
    fs.readFile(path.join(__dirname, 'public', 'index.html'), (err, data) => {
      if (err) { res.writeHead(500); res.end('Error'); }
      else { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(data); }
    });
    return;
  }

  if (req.method === 'POST') {
    const body = await getBody(req);

    try {
      if (req.url === '/api/signup') {
        const account = String(body.account || '').trim();
        const password = String(body.password || '');
        const chatId = String(body.chatId || '').trim();

        if (!account || password.length < 8) throw new Error('بيانات غير صحيحة');
        if (!chatId) throw new Error('لازم تدخل Chat ID بتاعك عشان تبعتلك الكود');
        
        const accKey = indexKey(account);
        if (index.has(accKey)) throw new Error('هذا الحساب مسجل بالفعل');

        const id = crypto.randomUUID();
        users.set(id, { id, account, chatId, passwordHash: hashPassword(password) });
        index.set(accKey, id);
        return sendJSON(res, 200, { ok: true });
      }

      if (req.url === '/api/login') {
        const identifier = String(body.identifier || '').trim();
        const password = String(body.password || '');
        const id = index.get(indexKey(identifier));
        const user = id && users.get(id);
        
        if (!user || !verifyPassword(password, user.passwordHash)) {
          throw new Error('الحساب أو كلمة المرور غير صحيحة');
        }

        const code = genCode(6);
        const sessionId = crypto.randomUUID();
        sessions.set(sessionId, { id: sessionId, userId: user.id, code, purpose: 'login', chatId: user.chatId, expiresAt: Date.now() + OTP_TTL_MS, tries: 0 });
        
        const message = `🔐 <b>كود تسجيل الدخول</b>\n\nكود التحقق الخاص بك هو:\n<code>${code}</code>\n\nصالح لمدة 5 دقائق.`;
        await sendTelegramMessage(user.chatId, message);

        return sendJSON(res, 200, { ok: true, sessionId, dest: maskDest(user.account), len: 6 });
      }

      if (req.url === '/api/forgot-password') {
        const identifier = String(body.identifier || '').trim();
        const id = index.get(indexKey(identifier));
        const user = id && users.get(id);
        if (!user) throw new Error('لا يوجد حساب');

        const code = genCode(7);
        const sessionId = crypto.randomUUID();
        sessions.set(sessionId, { id: sessionId, userId: user.id, code, purpose: 'reset', chatId: user.chatId, expiresAt: Date.now() + OTP_TTL_MS, tries: 0 });
        
        const message = `🔐 <b>كود استعادة كلمة المرور</b>\n\nكود التحقق الخاص بك هو:\n<code>${code}</code>\n\nصالح لمدة 5 دقائق.`;
        await sendTelegramMessage(user.chatId, message);

        return sendJSON(res, 200, { ok: true, sessionId, dest: maskDest(user.account), len: 7 });
      }

      if (req.url === '/api/verify-otp') {
        const s = checkOtp(String(body.sessionId || ''), String(body.code || '').trim());
        if (s.purpose === 'login') {
          sessions.delete(s.id);
          const token = crypto.randomUUID();
          tokens.set(token, { userId: s.userId });
          return sendJSON(res, 200, { ok: true, purpose: 'login', token, user: publicUser(users.get(s.userId)) });
        }
        s.verified = true; s.tries = 0; s.expiresAt = Date.now() + 10 * 60 * 1000;
        return sendJSON(res, 200, { ok: true, purpose: 'reset' });
      }

      if (req.url === '/api/reset-password') {
        const s = sessions.get(String(body.sessionId || ''));
        if (!s || !s.verified) throw new Error('يجب تأكيد الكود أولاً');
        const user = users.get(s.userId);
        user.passwordHash = hashPassword(String(body.newPassword || ''));
        sessions.delete(s.id);
        return sendJSON(res, 200, { ok: true });
      }

      sendJSON(res, 404, { error: 'Not found' });
    } catch (err) {
      console.error('Server Error:', err.message);
      sendJSON(res, 400, { error: err.message });
    }
    return;
  }
  res.writeHead(404); res.end();
});

server.listen(PORT, () => console.log(`✅ Server running on ${PORT}`));