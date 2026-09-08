require('dotenv').config();

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json({ limit: '20kb' }));

const PORT = process.env.PORT || 10000;
const API_VERSION = process.env.WHATSAPP_API_VERSION || 'v25.0';
const PHONE_NUMBER_ID = process.env.WHATSAPP_PHONE_NUMBER_ID;
const ACCESS_TOKEN = process.env.WHATSAPP_ACCESS_TOKEN;
const DEFAULT_TEMPLATE = process.env.WHATSAPP_TEMPLATE_NAME || 'jaspers_market_plain_text_v1';
const DEFAULT_LANGUAGE = process.env.WHATSAPP_TEMPLATE_LANGUAGE || 'en_US';

function normalizePhone(value) {
  return String(value || '').replace(/[^0-9]/g, '');
}

function isValidPhone(value) {
  return /^[1-9][0-9]{7,14}$/.test(value);
}

function getMessagesUrl() {
  return `https://graph.facebook.com/${API_VERSION}/${PHONE_NUMBER_ID}/messages`;
}

async function sendWhatsApp(payload) {
  if (!ACCESS_TOKEN || !PHONE_NUMBER_ID) {
    throw new Error('WhatsApp environment variables are not configured');
  }

  const response = await fetch(getMessagesUrl(), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${ACCESS_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ messaging_product: 'whatsapp', ...payload })
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data?.error?.message || 'WhatsApp API request failed');
    error.status = response.status;
    error.whatsapp = data;
    throw error;
  }

  return data;
}

app.get('/', (req, res) => {
  res.json({
    service: 'Game API WhatsApp Backend',
    status: 'online',
    apiVersion: API_VERSION,
    endpoints: {
      health: 'GET /health',
      sendTemplate: 'POST /api/whatsapp/send-template',
      sendText: 'POST /api/whatsapp/send-text'
    }
  });
});

app.get('/health', (req, res) => {
  res.json({
    ok: true,
    whatsappConfigured: Boolean(ACCESS_TOKEN && PHONE_NUMBER_ID),
    apiVersion: API_VERSION
  });
});

app.post('/api/whatsapp/send-template', async (req, res) => {
  try {
    const to = normalizePhone(req.body.to);
    const templateName = String(req.body.template || DEFAULT_TEMPLATE).trim();
    const languageCode = String(req.body.language || DEFAULT_LANGUAGE).trim();

    if (!isValidPhone(to)) {
      return res.status(400).json({ ok: false, error: 'Enter a valid recipient phone number in international format.' });
    }

    if (!templateName || !languageCode) {
      return res.status(400).json({ ok: false, error: 'Template name and language are required.' });
    }

    const payload = {
      to,
      type: 'template',
      template: {
        name: templateName,
        language: { code: languageCode }
      }
    };

    const data = await sendWhatsApp(payload);
    res.json({ ok: true, message: 'WhatsApp template message sent.', data });
  } catch (error) {
    console.error('WhatsApp template error:', error.message);
    res.status(error.status || 500).json({
      ok: false,
      error: error.message,
      details: error.whatsapp || undefined
    });
  }
});

app.post('/api/whatsapp/send-text', async (req, res) => {
  try {
    const to = normalizePhone(req.body.to);
    const body = String(req.body.body || '').trim();

    if (!isValidPhone(to)) {
      return res.status(400).json({ ok: false, error: 'Enter a valid recipient phone number in international format.' });
    }

    if (!body) {
      return res.status(400).json({ ok: false, error: 'Message body is required.' });
    }

    const data = await sendWhatsApp({
      to,
      type: 'text',
      text: { preview_url: false, body }
    });

    res.json({ ok: true, message: 'WhatsApp text message sent.', data });
  } catch (error) {
    console.error('WhatsApp text error:', error.message);
    res.status(error.status || 500).json({
      ok: false,
      error: error.message,
      details: error.whatsapp || undefined
    });
  }
});

// In-memory OTP store for initial testing. Replace with Redis/Postgres before production.
const otpStore = new Map();
const OTP_TTL_MS = 10 * 60 * 1000;
const MAX_OTP_ATTEMPTS = 5;

app.post('/api/auth/send-whatsapp-otp', async (req, res) => {
  try {
    const to = normalizePhone(req.body.to);
    if (!isValidPhone(to)) {
      return res.status(400).json({ ok: false, error: 'Enter a valid recipient phone number in international format.' });
    }

    const otp = crypto.randomInt(100000, 1000000).toString();
    const otpHash = crypto.createHash('sha256').update(otp).digest('hex');

    // Authentication templates normally require a template configured in WhatsApp Manager.
    const templateName = String(req.body.template || process.env.WHATSAPP_OTP_TEMPLATE_NAME || 'game_api_otp').trim();
    const languageCode = String(req.body.language || process.env.WHATSAPP_OTP_TEMPLATE_LANGUAGE || 'en_US').trim();

    const template = {
      name: templateName,
      language: { code: languageCode },
      components: [
        {
          type: 'body',
          parameters: [{ type: 'text', text: otp }]
        }
      ]
    };

    const data = await sendWhatsApp({
      to,
      type: 'template',
      template
    });

    otpStore.set(to, {
      hash: otpHash,
      expiresAt: Date.now() + OTP_TTL_MS,
      attempts: 0
    });

    res.json({ ok: true, message: 'OTP sent through WhatsApp.', messageId: data?.messages?.[0]?.id || null });
  } catch (error) {
    console.error('OTP send error:', error.message);
    res.status(error.status || 500).json({
      ok: false,
      error: error.message,
      details: error.whatsapp || undefined
    });
  }
});

app.post('/api/auth/verify-whatsapp-otp', (req, res) => {
  const to = normalizePhone(req.body.to);
  const otp = String(req.body.otp || '').trim();
  const record = otpStore.get(to);

  if (!record) {
    return res.status(400).json({ ok: false, verified: false, error: 'No active OTP found.' });
  }

  if (Date.now() > record.expiresAt) {
    otpStore.delete(to);
    return res.status(400).json({ ok: false, verified: false, error: 'OTP has expired.' });
  }

  if (record.attempts >= MAX_OTP_ATTEMPTS) {
    otpStore.delete(to);
    return res.status(429).json({ ok: false, verified: false, error: 'Too many OTP attempts.' });
  }

  record.attempts += 1;
  const submittedHash = crypto.createHash('sha256').update(otp).digest('hex');
  const valid = crypto.timingSafeEqual(Buffer.from(submittedHash), Buffer.from(record.hash));

  if (!valid) {
    return res.status(400).json({ ok: false, verified: false, error: 'Invalid OTP.' });
  }

  otpStore.delete(to);
  res.json({ ok: true, verified: true, message: 'WhatsApp number verified successfully.' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Game API WhatsApp backend listening on port ${PORT}`);
});
