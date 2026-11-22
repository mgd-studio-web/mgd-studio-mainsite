const RATE_LIMIT_MAX = 3;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const rateLimitStore = new Map();

const PACKAGE_LABELS = {
  vetrina: 'PACCHETTO VETRINA (299€ una tantum)',
  plus: 'PACCHETTO PLUS (449€ una tantum)',
  completo: 'PACCHETTO SU MISURA (da 690€ una tantum)'
};

function getClientIp(req) {
  const xff = req.headers && (req.headers['x-forwarded-for'] || req.headers['X-Forwarded-For']);
  if (typeof xff === 'string' && xff.trim()) {
    return xff.split(',')[0].trim();
  }
  if (Array.isArray(xff) && xff.length > 0) {
    return String(xff[0]).split(',')[0].trim();
  }
  const realIp = req.headers && req.headers['x-real-ip'];
  if (typeof realIp === 'string' && realIp.trim()) {
    return realIp.trim();
  }
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

function checkRateLimit(ip) {
  const now = Date.now();
  if (rateLimitStore.size > 500) {
    for (const [key, timestamps] of rateLimitStore.entries()) {
      const active = timestamps.filter(ts => now - ts < RATE_LIMIT_WINDOW_MS);
      if (active.length === 0) rateLimitStore.delete(key);
      else rateLimitStore.set(key, active);
    }
  }
  const recent = (rateLimitStore.get(ip) || []).filter(ts => now - ts < RATE_LIMIT_WINDOW_MS);
  if (recent.length >= RATE_LIMIT_MAX) {
    const oldest = recent[0];
    const retryAfterSec = Math.max(1, Math.ceil((RATE_LIMIT_WINDOW_MS - (now - oldest)) / 1000));
    rateLimitStore.set(ip, recent);
    return { allowed: false, retryAfterSec };
  }
  recent.push(now);
  rateLimitStore.set(ip, recent);
  return { allowed: true, retryAfterSec: 0 };
}

function readRawBody(req, maxBytes = 64 * 1024) {
  return new Promise((resolve, reject) => {
    if (!req || typeof req.on !== 'function' || req.readableEnded) {
      return resolve('');
    }
    const chunks = [];
    let total = 0;
    req.on('data', chunk => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
      total += buf.length;
      if (total > maxBytes) {
        reject(new Error('Payload too large'));
        if (typeof req.destroy === 'function') req.destroy();
        return;
      }
      chunks.push(buf);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function truncateUnicode(str, maxChars) {
  const chars = Array.from(String(str || ''));
  if (chars.length <= maxChars) return chars.join('');
  return chars.slice(0, Math.max(0, maxChars - 1)).join('') + '…';
}

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Allow', 'POST, OPTIONS');
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST, OPTIONS');
    return res.status(405).json({ ok: false, error: 'Method Not Allowed' });
  }

  const clientIp = getClientIp(req);
  const limit = checkRateLimit(clientIp);
  if (!limit.allowed) {
    res.setHeader('Retry-After', String(limit.retryAfterSec));
    console.error('[api/notify] 429 Too Many Requests', { ip: clientIp, retryAfterSec: limit.retryAfterSec });
    return res.status(429).json({
      ok: false,
      error: `Too Many Requests (riprova tra ${limit.retryAfterSec}s)`,
      retryAfterSec: limit.retryAfterSec
    });
  }

  let data;
  try {
    if (Buffer.isBuffer(req.body)) {
      data = JSON.parse(req.body.toString('utf8'));
    } else if (typeof req.body === 'string') {
      data = req.body.trim() ? JSON.parse(req.body) : null;
    } else if (req.body && typeof req.body === 'object') {
      data = req.body;
    } else {
      const raw = await readRawBody(req);
      data = raw.trim() ? JSON.parse(raw) : null;
    }
  } catch (parseErr) {
    const isTooLarge = parseErr && parseErr.message === 'Payload too large';
    const status = isTooLarge ? 413 : 400;
    const msg = isTooLarge ? 'Payload too large' : 'Invalid JSON body';
    console.error(`[api/notify] ${status} ${msg}`, parseErr && parseErr.message);
    return res.status(status).json({ ok: false, error: msg });
  }

  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    console.error('[api/notify] 400 Invalid JSON body (non-object payload)');
    return res.status(400).json({ ok: false, error: 'Invalid JSON body' });
  }

  // Honeypot anti-spam: se valorizzato, risponde 200 silenziosamente senza inviare a Telegram
  if (typeof data._honey === 'string' && data._honey.trim().length > 0) {
    return res.status(200).json({ ok: true });
  }

  const val = (v, fallback = 'Non indicato', maxLen = 500) => {
    if (v === null || v === undefined) return fallback;
    if (Array.isArray(v)) {
      const joined = v
        .filter(item => item !== null && item !== undefined && typeof item !== 'object')
        .map(item => String(item).trim())
        .filter(Boolean)
        .join(', ');
      return joined ? truncateUnicode(joined, maxLen) : fallback;
    }
    if (typeof v === 'object') return fallback;
    const s = String(v).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim();
    return s ? truncateUnicode(s, maxLen) : fallback;
  };

  const businessName = val(data.businessName, '', 160);
  const fullName = val(data.fullName, '', 160);
  const email = val(data.email, '', 180);
  const phone = val(data.phone, '', 40);

  const missingFields = [];
  if (!businessName) missingFields.push('businessName');
  if (!fullName) missingFields.push('fullName');
  if (!email && !phone) missingFields.push('email/phone');

  if (missingFields.length > 0) {
    const errMsg = `Missing required fields: ${missingFields.join(', ')}`;
    console.error('[api/notify] 400', errMsg);
    return res.status(400).json({ ok: false, error: errMsg, missingFields });
  }

  const botToken = (process.env.TELEGRAM_BOT_TOKEN || '').trim();
  const chatId = (process.env.TELEGRAM_CHAT_ID || '').trim();

  if (!botToken || !chatId) {
    console.error('[api/notify] 500 Missing Telegram env vars', {
      hasBotToken: Boolean(botToken),
      hasChatId: Boolean(chatId)
    });
    return res.status(500).json({ ok: false, error: 'Missing Telegram env vars' });
  }

  const rawPkgId = val(data.package, '', 40).toLowerCase();
  const packageText =
    val(data.pkgLabel, '', 160) ||
    PACKAGE_LABELS[rawPkgId] ||
    val(data.package, 'Non indicato', 120);
  const socialLink = val(data.social_or_site_link, '', 300);
  const wantsWhatsapp = val(data.wantsWhatsapp, '', 80);
  const wantsShowcase = val(data.wantsShowcase, '', 80);
  const referenceLinks = val(data.referenceLinks, '', 300);

  const lines = [
    '📩 Nuova richiesta preventivo — MGD Studio',
    '',
    `🏢 Attività: ${businessName}`,
    `🏷️ Tipo attività: ${val(data.businessType, 'Non indicato', 120)}`,
    `📍 Indirizzo: ${val(data.businessAddress, 'Non indicato', 200)}`,
    `👤 Cliente: ${fullName}`,
    `📞 Telefono: ${phone || 'Non indicato'}`,
    `✉️ Email: ${email || 'Non indicato'}`,
    '',
    `📦 Pacchetto: ${packageText}`,
    `🎨 Stile: ${val(data.style, 'Non indicato', 100)}`,
    `🌈 Colori: ${val(data.colors, 'Da concordare', 200)}`,
    `🧩 Sezioni: ${val(data.sections, 'Non indicato', 600)}`
  ];

  if (socialLink) lines.push(`🌐 Sito / Social / Maps: ${socialLink}`);
  if (wantsWhatsapp) lines.push(`💬 Pulsante WhatsApp: ${wantsWhatsapp}`);
  if (wantsShowcase) lines.push(`🛍️ Vetrina Prodotti/Servizi: ${wantsShowcase}`);
  if (referenceLinks && referenceLinks !== 'Nessuno') lines.push(`🔗 Siti di riferimento: ${referenceLinks}`);

  lines.push(
    `⏱️ Tempistica: ${val(data.timeline, 'Non indicato', 100)}`,
    '',
    `📝 Descrizione:\n${val(data.description, 'Non indicata', 1200)}`,
    '',
    `🗒️ Note:\n${val(data.additionalNotes, 'Nessuna', 500)}`
  );

  const text = truncateUnicode(lines.join('\n'), 4000);

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000);

  try {
    const tgRes = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        chat_id: chatId,
        text
      })
    });

    let tgJson = null;
    let tgRawText = '';
    try {
      tgRawText = await tgRes.text();
      tgJson = tgRawText ? JSON.parse(tgRawText) : null;
    } catch {
      // Risposta non-JSON
    }

    if (!tgRes.ok || (tgJson && tgJson.ok === false)) {
      const tgError = (tgJson && tgJson.description) || tgRawText.slice(0, 200) || `Telegram API error (${tgRes.status})`;
      const status = tgRes.ok ? 502 : tgRes.status;
      console.error('[api/notify] Telegram API error', { status, tgStatus: tgRes.status, tgError });
      return res.status(status).json({ ok: false, error: tgError });
    }

    return res.status(200).json({ ok: true });
  } catch (err) {
    if (err && err.name === 'AbortError') {
      console.error('[api/notify] 504 Telegram request timed out');
      return res.status(504).json({ ok: false, error: 'Telegram request timed out' });
    }
    const errMsg = err && err.message ? err.message : 'Telegram request failed';
    console.error('[api/notify] 502 Telegram request failed:', errMsg);
    return res.status(502).json({ ok: false, error: errMsg });
  } finally {
    clearTimeout(timeoutId);
  }
};
