// ════════════════════════════════════════════════════════════
// EDIXDATA PLUG — Backend Server
// Node.js + Express
//
// SETUP:
//   npm init -y
//   npm install express axios crypto dotenv cors
//   node server.js
//
// DEPLOY FREE ON: Railway.app / Render.com / Vercel
// ════════════════════════════════════════════════════════════

require('dotenv').config();
const express = require('express');
const axios   = require('axios');
const crypto  = require('crypto');
const cors    = require('cors');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── SECRETS (store in .env file, NEVER commit to GitHub) ──
const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const ADMIN_WA_NUMBER = process.env.ADMIN_WA || '233531861148';

// ── MIDDLEWARE ──
app.use(cors({ origin: '*' })); // restrict to your domain in production
app.use('/webhook/paystack', express.raw({ type: 'application/json' })); // raw body for webhook HMAC
app.use(express.json());

// ════════════════════════════════════════════════════════════
// 1. PAYSTACK WEBHOOK
//    Paste this URL in Paystack Dashboard → Settings → Webhooks:
//    https://YOUR-SERVER-URL/webhook/paystack
//
//    This endpoint:
//    - Verifies the request is genuinely from Paystack (HMAC SHA512)
//    - Handles charge.success → marks order as confirmed
//    - Prevents duplicate processing (idempotency)
// ════════════════════════════════════════════════════════════
const processedRefs = new Set(); // in production use a DB (Redis / Postgres)

app.post('/webhook/paystack', (req, res) => {
  // ── Step 1: Verify HMAC signature ──
  const hash = crypto
    .createHmac('sha512', PAYSTACK_SECRET)
    .update(req.body) // raw buffer
    .digest('hex');

  if (hash !== req.headers['x-paystack-signature']) {
    console.warn('⚠️  Invalid Paystack webhook signature — rejected');
    return res.status(401).json({ status: 'invalid signature' });
  }

  const event = JSON.parse(req.body.toString());
  console.log('📩 Paystack webhook received:', event.event);

  // ── Step 2: Handle charge.success ──
  if (event.event === 'charge.success') {
    const data = event.data;
    const ref  = data.reference;

    // Idempotency — ignore if already processed
    if (processedRefs.has(ref)) {
      console.log(`ℹ️  Duplicate webhook for ref ${ref} — skipped`);
      return res.sendStatus(200);
    }
    processedRefs.add(ref);

    const amountGHS  = data.amount / 100; // Paystack sends in pesewas
    const email      = data.customer?.email;
    const metadata   = data.metadata?.custom_fields || [];
    const phone      = metadata.find(f => f.variable_name === 'phone')?.value || 'Unknown';
    const orderInfo  = metadata.find(f => f.variable_name === 'order')?.value || 'Unknown plan';
    const custName   = metadata.find(f => f.variable_name === 'customer_name')?.value || email;

    console.log(`✅ Payment confirmed: ${ref} | ${custName} | ${orderInfo} | GH₵${amountGHS}`);

    // In production: update your database order status to 'paid'
    // e.g. await db.orders.updateOne({ txnRef: ref }, { $set: { status: 'processing' } });

    // Optional: send confirmation WhatsApp via your WA Business API
    // notifyAdmin({ ref, custName, phone, orderInfo, amountGHS });
  }

  // ── Step 3: Handle refund.processed ──
  if (event.event === 'refund.processed') {
    const ref = event.data.transaction_reference;
    console.log(`🔄 Refund processed for ref: ${ref}`);
    // Update order status in DB
  }

  res.sendStatus(200); // Always respond 200 to Paystack
});

// ════════════════════════════════════════════════════════════
// 2. VERIFY PAYMENT (called from frontend after Paystack popup)
//    Frontend calls: POST /verify-payment { reference: "TXN-..." }
//    Backend verifies with Paystack API using secret key
// ════════════════════════════════════════════════════════════
app.post('/verify-payment', async (req, res) => {
  const { reference } = req.body;

  if (!reference) {
    return res.status(400).json({ status: false, message: 'Reference required' });
  }

  try {
    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` } }
    );

    const data   = response.data.data;
    const status = data.status; // 'success' | 'failed' | 'abandoned'

    if (status !== 'success') {
      return res.json({ status: false, message: `Payment ${status}`, data });
    }

    // ── Fraud checks ──
    const amountGHS = data.amount / 100;
    const { expected_amount, order_id } = req.body;

    // 1. Amount mismatch check
    if (expected_amount && Math.abs(amountGHS - expected_amount) > 0.01) {
      console.warn(`🚨 FRAUD ALERT: Amount mismatch on ${reference}. Expected GH₵${expected_amount}, got GH₵${amountGHS}`);
      return res.json({ status: false, message: 'Amount mismatch — payment flagged', fraud: true });
    }

    // 2. Duplicate reference check
    if (processedRefs.has(reference)) {
      console.warn(`🚨 Duplicate reference attempt: ${reference}`);
      return res.json({ status: false, message: 'Reference already used', fraud: true });
    }

    processedRefs.add(reference);

    return res.json({
      status: true,
      message: 'Payment verified successfully',
      data: {
        reference,
        amount: amountGHS,
        email: data.customer?.email,
        paid_at: data.paid_at,
        channel: data.channel,
      }
    });

  } catch (err) {
    console.error('Paystack verify error:', err.message);
    return res.status(500).json({ status: false, message: 'Verification failed', error: err.message });
  }
});

// ════════════════════════════════════════════════════════════
// 3. LIST TRANSACTIONS (admin — server-side only, secret key)
// ════════════════════════════════════════════════════════════
app.get('/admin/transactions', async (req, res) => {
  // Add your own admin token check here
  const adminToken = req.headers['x-admin-token'];
  if (adminToken !== process.env.ADMIN_TOKEN) {
    return res.status(403).json({ message: 'Forbidden' });
  }
  try {
    const response = await axios.get('https://api.paystack.co/transaction?perPage=50', {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` }
    });
    res.json(response.data);
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════
// 4. INITIATE REFUND (admin only)
// ════════════════════════════════════════════════════════════
app.post('/admin/refund', async (req, res) => {
  const adminToken = req.headers['x-admin-token'];
  if (adminToken !== process.env.ADMIN_TOKEN) {
    return res.status(403).json({ message: 'Forbidden' });
  }
  const { transaction_id, amount } = req.body;
  try {
    const response = await axios.post(
      'https://api.paystack.co/refund',
      { transaction: transaction_id, amount: amount ? amount * 100 : undefined },
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET}`, 'Content-Type': 'application/json' } }
    );
    res.json(response.data);
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════
// 5. HEALTH CHECK
// ════════════════════════════════════════════════════════════
app.get('/', (req, res) => {
  res.json({ status: 'EDIXDATA PLUG backend is running ✅', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`\n🚀 EDIXDATA PLUG Server running on port ${PORT}`);
  console.log(`📡 Webhook URL: https://YOUR-DOMAIN/webhook/paystack`);
  console.log(`🔒 Payment verification: POST /verify-payment`);
  console.log(`⚠️  Remember: Add PAYSTACK_SECRET and ADMIN_TOKEN to your .env file!\n`);
});
