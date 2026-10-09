/**
 * StockOS Cloud — Multi-Godown Live Stock Worker
 * ═══════════════════════════════════════════════════════════════════
 * Lets a firm's salesmen check real, live godown stock from anywhere,
 * and record sales that instantly deduct from it — so everyone always
 * sees the true number, not a guess.
 *
 * This is a SEPARATE system from your license Worker — different data,
 * different purpose. Deploy it as its own Worker (own name, own D1
 * database), same way you deployed stockos-worker earlier.
 *
 * ── ONE-TIME SETUP ──────────────────────────────────────────────────
 * 1. Create the database:  wrangler d1 create stockos_cloud_db
 *    (or via Cloudflare dashboard → Storage & databases → D1)
 * 2. Copy the printed database_id into wrangler.toml
 * 3. Load the schema:      wrangler d1 execute stockos_cloud_db --file=schema.sql
 * 4. Secrets (same style as before):
 *      wrangler secret put TOKEN_SECRET     (any long random string —
 *        used to sign login sessions, keep it private)
 *      wrangler secret put PIN_SALT         (any long random string —
 *        used to hash staff/owner PINs)
 * 5. wrangler deploy
 * ═══════════════════════════════════════════════════════════════════
 */

const ALLOWED_ORIGIN = 'https://stockospro.github.io'; // ← change if hosted elsewhere

function cors(resp) {
  resp.headers.set('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  resp.headers.set('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  resp.headers.set('Access-Control-Allow-Headers', 'Content-Type');
  return resp;
}
function json(data, status = 200) {
  return cors(new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } }));
}

async function hmacHex(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ── Simple signed session token (no session table needed) ──
async function makeToken(payload, env) {
  const body = btoa(JSON.stringify(payload));
  const sig = await hmacHex(env.TOKEN_SECRET, body);
  return body + '.' + sig;
}
async function verifyToken(token, env) {
  if (!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expected = await hmacHex(env.TOKEN_SECRET, body);
  if (!safeEqual(sig, expected)) return null;
  try { return JSON.parse(atob(body)); } catch (e) { return null; }
}
async function requireAuth(req, env) {
  let parsed = {};
  try { parsed = await req.json(); } catch(e) {}
  const payload = await verifyToken(parsed.token, env);
  if (!payload) return { error: json({ error: 'Not logged in — please log in again.' }, 401) };
  return { payload, body: parsed };
}

// ── Email OTP via Brevo (free 300/day, no domain needed, sends to anyone) ─────
// Requires BREVO_API_KEY secret set in Cloudflare Workers → Settings → Variables
// Get free API key at: https://brevo.com → Sign Up → SMTP & API → API Keys
// Free plan: 300 emails/day, unlimited contacts — no domain verification needed
async function sendOtpEmail(toEmail, otp, env) {
  if (!env.BREVO_API_KEY) return { ok: false, error: 'Email service not configured — add BREVO_API_KEY in Worker settings.' };
  if (!toEmail || !toEmail.includes('@')) return { ok: false, error: 'Invalid email address' };
  try {
    const res = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'api-key': env.BREVO_API_KEY,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        sender: { name: 'StockOS Pro', email: 'noreply@sendinblue.com' },
        to: [{ email: toEmail }],
        subject: `${otp} — Your StockOS Pro OTP`,
        htmlContent: `
          <div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:24px">
            <h2 style="color:#f97316;margin-bottom:8px">StockOS Pro</h2>
            <p style="font-size:16px;color:#374151">Your one-time password is:</p>
            <div style="font-size:40px;font-weight:bold;letter-spacing:8px;color:#111;margin:16px 0">${otp}</div>
            <p style="font-size:13px;color:#6b7280">Valid for 10 minutes. Do not share this with anyone.</p>
          </div>`
      })
    });
    const data = await res.json();
    if (res.ok && (data.messageId || res.status === 201)) return { ok: true };
    return { ok: false, error: data.message || 'Email send failed' };
  } catch(e) { return { ok: false, error: String(e) }; }
}

function maskPhone(phone) {
  const p = phone.replace(/\D/g, '').slice(-10);
  return p.slice(0, 2) + '******' + p.slice(-2);
}
function maskEmail(email) {
  const [user, domain] = email.split('@');
  return user.slice(0, 2) + '****@' + domain;
}

// ── Ensure pending_signups table exists (no FK — used before firm is created) ──
async function ensurePendingTable(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS pending_signups (
      phone TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      pin TEXT NOT NULL,
      otp TEXT NOT NULL,
      expires TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    )`).run();
}

// ── Signup Step 1: send OTP via email (firm NOT created yet) ─────────────────
async function signupSendOtp(req, env) {
  let body = {};
  try { body = await req.json(); } catch(e) {}
  const { name, phone, pin, email } = body;
  if (!name || !phone || !pin || !email) return json({ error: 'Name, phone, email, and PIN are required' }, 400);
  if (!/^\d{4,6}$/.test(pin)) return json({ error: 'PIN must be 4–6 digits' }, 400);
  if (!email.includes('@')) return json({ error: 'Valid email address required' }, 400);
  const existing = await env.DB.prepare('SELECT id FROM firms WHERE owner_phone=?').bind(phone).first();
  if (existing) return json({ error: 'This phone number is already registered' }, 409);
  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  try {
    await ensurePendingTable(env);
    await env.DB.prepare(`
      INSERT INTO pending_signups (phone, name, email, pin, otp, expires)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(phone) DO UPDATE SET name=excluded.name, email=excluded.email,
        pin=excluded.pin, otp=excluded.otp, expires=excluded.expires, created_at=datetime('now')`)
      .bind(phone, name, email, pin, otp, expires).run();
  } catch(e) { return json({ error: 'Database error: ' + String(e) }, 500); }
  const result = await sendOtpEmail(email, otp, env);
  if (!result.ok) return json({ error: 'Failed to send OTP email. ' + (result.error || '') }, 500);
  return json({ ok: true, maskedPhone: maskPhone(phone), maskedEmail: maskEmail(email) });
}

// ── Signup Step 2: verify OTP and create firm ─────────────────────────────
async function signupVerifyOtp(req, env) {
  let body = {};
  try { body = await req.json(); } catch(e) {}
  const { phone, otp, deviceId } = body;
  if (!phone || !otp) return json({ error: 'phone and otp required' }, 400);
  await ensurePendingTable(env);
  const row = await env.DB.prepare('SELECT * FROM pending_signups WHERE phone=?').bind(phone).first();
  if (!row) return json({ error: 'No pending signup found. Please start over.' }, 400);
  if (new Date(row.expires) < new Date()) {
    await env.DB.prepare('DELETE FROM pending_signups WHERE phone=?').bind(phone).run();
    return json({ error: 'OTP expired. Please start the signup again.' }, 400);
  }
  if (!safeEqual(row.otp, otp)) return json({ error: 'Wrong OTP. Check your email and try again.' }, 403);
  // OTP valid — check phone not already taken
  const existing = await env.DB.prepare('SELECT id FROM firms WHERE owner_phone=?').bind(phone).first();
  if (existing) {
    await env.DB.prepare('DELETE FROM pending_signups WHERE phone=?').bind(phone).run();
    return json({ error: 'This phone number was already registered.' }, 409);
  }
  const pinHash = await hmacHex(env.PIN_SALT, row.phone + ':' + row.pin);
  let result;
  try {
    result = await env.DB.prepare(
      'INSERT INTO firms (name, owner_phone, owner_pin, owner_email, device_id) VALUES (?, ?, ?, ?, ?)'
    ).bind(row.name, row.phone, pinHash, row.email, deviceId || null).run();
  } catch(e) {
    // Fallback if owner_email column doesn't exist yet
    result = await env.DB.prepare(
      'INSERT INTO firms (name, owner_phone, owner_pin, device_id) VALUES (?, ?, ?, ?)'
    ).bind(row.name, row.phone, pinHash, deviceId || null).run();
  }
  const firmId = result.meta.last_row_id;
  // Clean up pending row
  await env.DB.prepare('DELETE FROM pending_signups WHERE phone=?').bind(phone).run();
  const token = await makeToken({ role: 'owner', firmId, name: row.name }, env);
  return json({ token, firmId, role: 'owner', name: row.name });
}

// ── Forgot firm PIN: send OTP via email to owner's email (public) ────────────
async function sendForgotPinOtp(req, env) {
  let body = {};
  try { body = await req.json(); } catch(e) {}
  const { phone } = body;
  if (!phone) return json({ error: 'Phone number required' }, 400);
  const firm = await env.DB.prepare('SELECT id, name, owner_email FROM firms WHERE owner_phone=?').bind(phone).first();
  if (!firm) return json({ error: 'No account found for this phone number' }, 404);
  const email = firm.owner_email;
  if (!email || !email.includes('@')) return json({ error: 'No email address on file. Contact support.' }, 400);
  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  await env.DB.prepare(`
    INSERT INTO firm_version (firm_id, updated_at, otp_code, otp_expires)
    VALUES (?, datetime('now'), ?, ?)
    ON CONFLICT(firm_id) DO UPDATE SET otp_code=excluded.otp_code, otp_expires=excluded.otp_expires, updated_at=datetime('now')`)
    .bind(firm.id, otp, expires).run();
  const result = await sendOtpEmail(email, otp, env);
  if (!result.ok) return json({ error: 'Failed to send OTP email. ' + (result.error || '') }, 500);
  return json({ ok: true, maskedPhone: maskPhone(phone), maskedEmail: maskEmail(email) });
}

// ── Verify OTP and reset PIN (public — works for both firm + staff flows) ──
async function verifyOtpResetPin(req, env) {
  let body = {};
  try { body = await req.json(); } catch(e) {}
  const { phone, otp, newPin } = body;
  if (!phone || !otp || !newPin) return json({ error: 'phone, otp and newPin required' }, 400);
  if (!/^\d{4,6}$/.test(newPin)) return json({ error: 'PIN must be 4-6 digits' }, 400);
  const firm = await env.DB.prepare('SELECT id FROM firms WHERE owner_phone=?').bind(phone).first();
  if (!firm) return json({ error: 'No account found for this phone number' }, 404);
  const fv = await env.DB.prepare('SELECT otp_code, otp_expires FROM firm_version WHERE firm_id=?').bind(firm.id).first();
  if (!fv || !fv.otp_code) return json({ error: 'No OTP found. Please request a new one.' }, 400);
  // Handle case where otp_code might be a JSON blob from pending signup
  let storedOtp = fv.otp_code;
  try { const p = JSON.parse(fv.otp_code); if (p && p.otp) storedOtp = p.otp; } catch(e) {}
  if (new Date(fv.otp_expires) < new Date()) return json({ error: 'OTP expired. Please request a new one.' }, 400);
  if (!safeEqual(storedOtp, otp)) return json({ error: 'Wrong OTP. Check your email and try again.' }, 403);
  await env.DB.prepare('UPDATE firm_version SET otp_code=NULL, otp_expires=NULL WHERE firm_id=?').bind(firm.id).run();
  const newHash = await hmacHex(env.PIN_SALT, phone + ':' + newPin);
  await env.DB.prepare('UPDATE firms SET owner_pin=? WHERE id=?').bind(newHash, firm.id).run();
  return json({ ok: true });
}

// ── Staff forgot PIN: send OTP via email to owner's email (public) ───────────
async function sendStaffForgotPinOtp(req, env) {
  let body = {};
  try { body = await req.json(); } catch(e) {}
  const { phone } = body; // owner's phone to identify firm
  if (!phone) return json({ error: 'Owner phone number required' }, 400);
  const firm = await env.DB.prepare('SELECT id, name, owner_phone, owner_email FROM firms WHERE owner_phone=?').bind(phone).first();
  if (!firm) return json({ error: 'No firm found for this phone number' }, 404);
  const email = firm.owner_email;
  if (!email || !email.includes('@')) return json({ error: 'No email address on file for this account.' }, 400);
  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  await env.DB.prepare(`
    INSERT INTO firm_version (firm_id, updated_at, otp_code, otp_expires)
    VALUES (?, datetime('now'), ?, ?)
    ON CONFLICT(firm_id) DO UPDATE SET otp_code=excluded.otp_code, otp_expires=excluded.otp_expires, updated_at=datetime('now')`)
    .bind(firm.id, otp, expires).run();
  const result = await sendOtpEmail(email, otp, env);
  if (!result.ok) return json({ error: 'Failed to send OTP email. ' + (result.error || '') }, 500);
  return json({ ok: true, maskedPhone: maskPhone(phone), maskedEmail: maskEmail(email), firmId: firm.id });
}

// ── Firm signup — legacy (no email verification) ──────────────────────────
async function firmSignup(req, env) {
  const { name, phone, pin, deviceId } = await req.json();
  if (!name || !phone || !pin) return json({ error: 'Missing name, phone, or PIN' }, 400);
  const pinHash = await hmacHex(env.PIN_SALT, phone + ':' + pin);
  const result = await env.DB.prepare(
    'INSERT INTO firms (name, owner_phone, owner_pin, device_id) VALUES (?, ?, ?, ?)'
  ).bind(name, phone, pinHash, deviceId || null).run();
  const firmId = result.meta.last_row_id;
  const token = await makeToken({ role: 'owner', firmId, name }, env);
  return json({ token, firmId, role: 'owner', name });
}

// ── Login — owner or staff, same endpoint, tells them apart by phone match ──
async function login(req, env) {
  const { phone, pin } = await req.json();
  if (!phone || !pin) return json({ error: 'Enter phone and PIN' }, 400);
  const pinHash = await hmacHex(env.PIN_SALT, phone + ':' + pin);

  const owner = await env.DB.prepare('SELECT * FROM firms WHERE owner_phone = ?').bind(phone).first();
  if (owner && safeEqual(owner.owner_pin, pinHash)) {
    const token = await makeToken({ role: 'owner', firmId: owner.id, name: owner.name }, env);
    return json({ token, role: 'owner', firmId: owner.id, name: owner.name });
  }

  const staff = await env.DB.prepare('SELECT * FROM staff WHERE phone = ? AND active = 1').bind(phone).first();
  if (staff && safeEqual(staff.pin_hash, pinHash)) {
    const token = await makeToken({ role: 'staff', firmId: staff.firm_id, staffId: staff.id, name: staff.name }, env);
    return json({ token, role: 'staff', firmId: staff.firm_id, staffId: staff.id, name: staff.name });
  }

  return json({ error: 'Wrong phone or PIN' }, 401);
}

// ── Owner: add a godown ──
async function godownAdd(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  if (payload.role !== 'owner') return json({ error: 'Only the owner can add godowns' }, 403);
  const { name } = body||{};
  if (!name) return json({ error: 'Missing godown name' }, 400);
  const r = await env.DB.prepare('INSERT INTO godowns (firm_id, name) VALUES (?, ?)').bind(payload.firmId, name).run();
  return json({ id: r.meta.last_row_id, name });
}

// ── Owner: add a salesman ──
async function staffAdd(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  if (payload.role !== 'owner') return json({ error: 'Only the owner can add staff' }, 403);
  const { name, phone, pin } = body||{};
  if (!name || !phone || !pin) return json({ error: 'Missing name, phone, or PIN' }, 400);
  const pinHash = await hmacHex(env.PIN_SALT, phone + ':' + pin);
  const r = await env.DB.prepare('INSERT INTO staff (firm_id, name, phone, pin_hash) VALUES (?, ?, ?, ?)')
    .bind(payload.firmId, name, phone, pinHash).run();
  return json({ id: r.meta.last_row_id, name, phone });
}

// ── Owner: add a product ──
async function productAdd(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  if (payload.role !== 'owner') return json({ error: 'Only the owner can add products' }, 403);
  const { name, sku, unit, price } = body||{};
  if (!name) return json({ error: 'Missing product name' }, 400);
  const r = await env.DB.prepare('INSERT INTO products (firm_id, name, sku, unit, price) VALUES (?, ?, ?, ?, ?)')
    .bind(payload.firmId, name, sku || '', unit || 'pcs', price || 0).run();
  return json({ id: r.meta.last_row_id, name });
}

// ── Owner: set/adjust stock for a product at a godown ──
async function stockSet(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  if (payload.role !== 'owner') return json({ error: 'Only the owner can set stock' }, 403);
  const { productId, godownId, qty } = body||{};
  if (!productId || !godownId || qty === undefined) return json({ error: 'Missing productId, godownId, or qty' }, 400);
  await env.DB.prepare(
    `INSERT INTO stock (product_id, godown_id, qty, updated_at) VALUES (?, ?, ?, datetime('now'))
     ON CONFLICT(product_id, godown_id) DO UPDATE SET qty = excluded.qty, updated_at = datetime('now')`
  ).bind(productId, godownId, qty).run();
  return json({ ok: true });
}

// ── Everyone (owner + staff): live stock list ──
async function stockList(req, env) {
  const { payload, error } = await requireAuth(req, env); if (error) return error;
  const rows = await env.DB.prepare(`
    SELECT p.id as product_id, p.name as product_name, p.sku, p.unit, p.price,
           g.id as godown_id, g.name as godown_name,
           COALESCE(s.qty, 0) as qty
    FROM products p
    CROSS JOIN godowns g ON g.firm_id = p.firm_id
    LEFT JOIN stock s ON s.product_id = p.id AND s.godown_id = g.id
    WHERE p.firm_id = ?
    ORDER BY p.name, g.name
  `).bind(payload.firmId).all();
  return json({ stock: rows.results });
}

// ── Staff: record a sale ──
async function saleCreate(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  const { productId, godownId, qty, amount, customerName } = body||{};
  if (!productId || !godownId || !qty) return json({ error: 'Missing productId, godownId, or qty' }, 400);
  const current = await env.DB.prepare('SELECT qty FROM stock WHERE product_id = ? AND godown_id = ?')
    .bind(productId, godownId).first();
  const currentQty = current ? current.qty : 0;
  if (currentQty < qty) return json({ error: `Only ${currentQty} in stock` }, 400);
  const staffId = payload.staffId || null;
  await env.DB.batch([
    env.DB.prepare(`UPDATE stock SET qty = qty - ?, updated_at = datetime('now') WHERE product_id = ? AND godown_id = ?`)
      .bind(qty, productId, godownId),
    env.DB.prepare(`INSERT INTO sales (firm_id, godown_id, staff_id, product_id, qty, amount, customer_name) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .bind(payload.firmId, godownId, staffId, productId, qty, amount || 0, customerName || ''),
  ]);
  return json({ ok: true, remaining: currentQty - qty });
}

// ── Owner: sales report ──
async function salesList(req, env) {
  const { payload, error } = await requireAuth(req, env); if (error) return error;
  if (payload.role !== 'owner') return json({ error: 'Only the owner can view the full sales report' }, 403);
  const rows = await env.DB.prepare(`
    SELECT s.id, s.qty, s.amount, s.customer_name, s.created_at,
           p.name as product_name, g.name as godown_name, st.name as staff_name
    FROM sales s
    JOIN products p ON p.id = s.product_id
    JOIN godowns g ON g.id = s.godown_id
    LEFT JOIN staff st ON st.id = s.staff_id
    WHERE s.firm_id = ?
    ORDER BY s.created_at DESC
    LIMIT 200
  `).bind(payload.firmId).all();
  return json({ sales: rows.results });
}

// ── Owner: lists of godowns/staff/products (for building dropdowns in the UI) ──
async function meta(req, env) {
  const { payload, error } = await requireAuth(req, env); if (error) return error;
  const [godowns, products, staff] = await Promise.all([
    env.DB.prepare('SELECT id, name FROM godowns WHERE firm_id = ? ORDER BY name').bind(payload.firmId).all(),
    env.DB.prepare('SELECT id, name, sku, unit, price FROM products WHERE firm_id = ? ORDER BY name').bind(payload.firmId).all(),
    payload.role === 'owner'
      ? env.DB.prepare('SELECT id, name, phone, active FROM staff WHERE firm_id = ? ORDER BY name').bind(payload.firmId).all()
      : { results: [] },
  ]);
  return json({ godowns: godowns.results, products: products.results, staff: staff.results, role: payload.role, name: payload.name });
}

// ── Version check — tiny fast endpoint, just returns last-updated timestamp ──
async function getVersion(req, env) {
  const { payload, error } = await requireAuth(req, env); if (error) return error;
  const row = await env.DB.prepare(
    'SELECT updated_at FROM firm_version WHERE firm_id = ?'
  ).bind(payload.firmId).first();
  return json({ version: row ? row.updated_at : '0' });
}

async function bumpVersion(env, firmId) {
  const ts = Date.now().toString();
  await env.DB.prepare(
    `INSERT INTO firm_version (firm_id, updated_at) VALUES (?, ?)
     ON CONFLICT(firm_id) DO UPDATE SET updated_at = excluded.updated_at`
  ).bind(firmId, ts).run();
  return ts;
}

// ── Sync push — save all firm data to D1 ──
async function syncPush(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  if (payload.role !== 'owner') return json({ error: 'Only owner can sync' }, 403);
  const { items, categories, bills, debtors, creditors, biz } = body||{};

  await env.DB.batch([
    env.DB.prepare('DELETE FROM inv_items WHERE firm_id=?').bind(payload.firmId),
    env.DB.prepare('DELETE FROM inv_categories WHERE firm_id=?').bind(payload.firmId),
    env.DB.prepare('DELETE FROM inv_bills WHERE firm_id=?').bind(payload.firmId),
    env.DB.prepare('DELETE FROM inv_ledger WHERE firm_id=?').bind(payload.firmId),
  ]);

  const stmts = [];
  for (const item of (items||[])) {
    stmts.push(env.DB.prepare(
      `INSERT INTO inv_items (firm_id,name,sku,category,qty,min_qty,price,purchase_price,sold,unit,expiry,expiry_batches,image,place,gst_rate,hsn_code)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(payload.firmId, item.name||'', item.sku||'', item.category||'',
      item.qty||0, item.minQty||item.min_qty||0, item.price||0,
      item.purchasePrice||item.purchase_price||0, item.sold||0,
      item.unit||'pcs', item.expiry||'',
      JSON.stringify(item.expiryBatches||item.expiry_batches||[]),
      item.image||'', item.place||'', item.gstRate||item.gst_rate||0, item.hsnCode||item.hsn_code||''));
  }
  for (const cat of (categories||[])) {
    stmts.push(env.DB.prepare(
      'INSERT INTO inv_categories (firm_id,name,color,icon) VALUES (?,?,?,?)'
    ).bind(payload.firmId, cat.name||'', cat.color||'#f97316', cat.icon||'📦'));
  }
  for (const bill of (bills||[])) {
    const cart = Array.isArray(bill.cart) ? JSON.stringify(bill.cart) : (bill.cart||'[]');
    stmts.push(env.DB.prepare(
      `INSERT INTO inv_bills (firm_id,total,discount,customer,phone,pay_mode,cart,bill_date,gst_enabled,total_gst,total_taxable,gst_type,discount_pct)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(payload.firmId, bill.total||0, bill.discount||0,
      bill.customer||'', bill.phone||'', bill.payMode||bill.pay_mode||'',
      cart, bill.date||new Date().toISOString(),
      bill.gstEnabled?1:0, bill.totalGST||0, bill.totalTaxable||0,
      bill.gstType||'intra', bill.discountPct||0));
  }
  for (const e of [...(debtors||[]), ...(creditors||[])]) {
    stmts.push(env.DB.prepare(
      'INSERT INTO inv_ledger (firm_id,name,phone,notes,type,transactions) VALUES (?,?,?,?,?,?)'
    ).bind(payload.firmId, e.name||'', e.phone||'', e.notes||'',
      e.type||'debtor', JSON.stringify(e.transactions||[])));
  }
  if (biz) {
    const ex = await env.DB.prepare('SELECT id FROM inv_biz WHERE firm_id=?').bind(payload.firmId).first();
    if (ex) {
      stmts.push(env.DB.prepare(
        `UPDATE inv_biz SET name=?,gst=?,address=?,phone=?,logo=?,updated_at=datetime('now') WHERE firm_id=?`
      ).bind(biz.name||'', biz.gst||'', biz.address||'', biz.phone||'', biz.logo||'', payload.firmId));
    } else {
      stmts.push(env.DB.prepare(
        'INSERT INTO inv_biz (firm_id,name,gst,address,phone,logo) VALUES (?,?,?,?,?,?)'
      ).bind(payload.firmId, biz.name||'', biz.gst||'', biz.address||'', biz.phone||'', biz.logo||''));
    }
  }

  for (let i = 0; i < stmts.length; i += 50) {
    await env.DB.batch(stmts.slice(i, i + 50));
  }
  const version = await bumpVersion(env, payload.firmId);
  return json({ ok: true, version });
}

// ── Sync load — return all firm data ──
async function syncLoad(req, env) {
  const { payload, error } = await requireAuth(req, env); if (error) return error;
  const [itemsR, catsR, billsR, ledgerR, bizR, verR] = await Promise.all([
    env.DB.prepare('SELECT * FROM inv_items WHERE firm_id=? ORDER BY name').bind(payload.firmId).all(),
    env.DB.prepare('SELECT * FROM inv_categories WHERE firm_id=? ORDER BY name').bind(payload.firmId).all(),
    env.DB.prepare('SELECT * FROM inv_bills WHERE firm_id=? ORDER BY created_at DESC LIMIT 500').bind(payload.firmId).all(),
    env.DB.prepare('SELECT * FROM inv_ledger WHERE firm_id=? ORDER BY name').bind(payload.firmId).all(),
    env.DB.prepare('SELECT * FROM inv_biz WHERE firm_id=?').bind(payload.firmId).first(),
    env.DB.prepare('SELECT updated_at FROM firm_version WHERE firm_id=?').bind(payload.firmId).first(),
  ]);
  return json({
    version: verR ? verR.updated_at : '0',
    items: itemsR.results,
    categories: catsR.results,
    bills: billsR.results,
    debtors:   ledgerR.results.filter(r => r.type === 'debtor'),
    creditors: ledgerR.results.filter(r => r.type === 'creditor'),
    biz: bizR || {},
  });
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return cors(new Response(null, { status: 204 }));
    const url = new URL(req.url);
    try {
      // Auth
      if (req.method === 'POST' && url.pathname === '/firm-signup')    return await firmSignup(req, env);
      if (req.method === 'POST' && url.pathname === '/login')          return await login(req, env);
      // Version check (fast, tiny)
      if (req.method === 'POST' && url.pathname === '/version')        return await getVersion(req, env);
      // Full sync (first load / fallback)
      if (req.method === 'POST' && url.pathname === '/sync-push')      return await syncPush(req, env);
      if (req.method === 'POST' && url.pathname === '/sync-load')      return await syncLoad(req, env);
      // Delta — items
      if (req.method === 'POST' && url.pathname === '/item-upsert')    return await itemUpsert(req, env);
      if (req.method === 'POST' && url.pathname === '/item-delete')    return await itemDelete(req, env);
      // Delta — categories
      if (req.method === 'POST' && url.pathname === '/category-upsert')return await categoryUpsert(req, env);
      if (req.method === 'POST' && url.pathname === '/category-delete')return await categoryDelete(req, env);
      // Delta — bills
      if (req.method === 'POST' && url.pathname === '/bill-insert')    return await billInsert(req, env);
      if (req.method === 'POST' && url.pathname === '/bill-delete')    return await billDelete(req, env);
      // Delta — ledger
      if (req.method === 'POST' && url.pathname === '/ledger-upsert')  return await ledgerUpsert(req, env);
      if (req.method === 'POST' && url.pathname === '/ledger-delete')  return await ledgerDelete(req, env);
      // Delta — biz
      if (req.method === 'POST' && url.pathname === '/biz-upsert')     return await bizUpsert(req, env);
      // Atomic sale deduct (prevents concurrent sale qty conflicts)
      if (req.method === 'POST' && url.pathname === '/sale-deduct')    return await saleDeduct(req, env);
      // PIN management
      if (req.method === 'POST' && url.pathname === '/change-pin')     return await changePin(req, env);
      // Staff lock sync
      if (req.method === 'POST' && url.pathname === '/staff-lock-set') return await staffLockSet(req, env);
      if (req.method === 'POST' && url.pathname === '/staff-lock-get') return await staffLockGet(req, env);
      // Email OTP — signup with email verification (2-step)
      if (req.method === 'POST' && url.pathname === '/signup-send-otp')   return await signupSendOtp(req, env);
      if (req.method === 'POST' && url.pathname === '/signup-verify-otp') return await signupVerifyOtp(req, env);
      // Email OTP — forgot firm PIN (public, no token needed)
      if (req.method === 'POST' && url.pathname === '/forgot-pin-otp')    return await sendForgotPinOtp(req, env);
      // Email OTP — staff forgot PIN (public, sends to owner's email)
      if (req.method === 'POST' && url.pathname === '/staff-forgot-otp')  return await sendStaffForgotPinOtp(req, env);
      // Email OTP — verify OTP and set new PIN (used by both forgot-pin flows)
      if (req.method === 'POST' && url.pathname === '/verify-otp-pin')    return await verifyOtpResetPin(req, env);
      // Legacy OTP endpoints (kept for compatibility)
      if (req.method === 'POST' && url.pathname === '/otp-generate')      return await otpGenerate(req, env);
      if (req.method === 'POST' && url.pathname === '/otp-verify-pin')    return await otpVerifyPin(req, env);
      if (req.method === 'POST' && url.pathname === '/otp-reset-firm')    return await otpResetFirm(req, env);
      // Ledger atomic transaction append/delete
      if (req.method === 'POST' && url.pathname === '/ledger-tx-add')  return await ledgerTxAdd(req, env);
      if (req.method === 'POST' && url.pathname === '/ledger-tx-del')  return await ledgerTxDel(req, env);
      // Godown/staff/stock
      if (req.method === 'POST' && url.pathname === '/godown-add')     return await godownAdd(req, env);
      if (req.method === 'POST' && url.pathname === '/staff-add')      return await staffAdd(req, env);
      if (req.method === 'POST' && url.pathname === '/product-add')    return await productAdd(req, env);
      if (req.method === 'POST' && url.pathname === '/stock-set')      return await stockSet(req, env);
      if (req.method === 'POST' && url.pathname === '/stock-list')     return await stockList(req, env);
      if (req.method === 'POST' && url.pathname === '/sale-create')    return await saleCreate(req, env);
      if (req.method === 'POST' && url.pathname === '/sales-list')     return await salesList(req, env);
      if (req.method === 'POST' && url.pathname === '/meta')           return await meta(req, env);
      return json({ error: 'Not found' }, 404);
    } catch (e) {
      return json({ error: 'Server error', detail: String(e) }, 500);
    }
  },
};

// ══════════════════════════════════════════════════════════════
// DELTA SYNC — individual record endpoints (fast, small payloads)
// ══════════════════════════════════════════════════════════════

// ── Items ──────────────────────────────────────────────────────
async function itemUpsert(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  const item = body.item; if (!item||!item.name) return json({ error: 'Missing item' }, 400);
  const batches = JSON.stringify(item.expiryBatches||[]);
  if (item.cloudId) {
    await env.DB.prepare(`UPDATE inv_items SET
      name=?,sku=?,category=?,qty=?,min_qty=?,price=?,purchase_price=?,sold=?,unit=?,
      expiry=?,expiry_batches=?,place=?,gst_rate=?,hsn_code=?,updated_at=datetime('now')
      WHERE id=? AND firm_id=?`)
    .bind(item.name,item.sku||'',item.category||'',item.qty||0,item.minQty||0,
      item.price||0,item.purchasePrice||0,item.sold||0,item.unit||'pcs',
      item.expiry||'',batches,item.place||'',item.gstRate||0,item.hsnCode||'',
      item.cloudId,payload.firmId).run();
    await bumpVersion(env, payload.firmId);
    return json({ ok:true, cloudId:item.cloudId });
  } else {
    const r = await env.DB.prepare(`INSERT INTO inv_items
      (firm_id,name,sku,category,qty,min_qty,price,purchase_price,sold,unit,expiry,expiry_batches,place,gst_rate,hsn_code)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .bind(payload.firmId,item.name,item.sku||'',item.category||'',item.qty||0,
      item.minQty||0,item.price||0,item.purchasePrice||0,item.sold||0,
      item.unit||'pcs',item.expiry||'',batches,item.place||'',item.gstRate||0,item.hsnCode||'').run();
    await bumpVersion(env, payload.firmId);
    return json({ ok:true, cloudId:r.meta.last_row_id });
  }
}

async function itemDelete(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  if (!body.cloudId) return json({ error: 'Missing cloudId' }, 400);
  await env.DB.prepare('DELETE FROM inv_items WHERE id=? AND firm_id=?').bind(body.cloudId, payload.firmId).run();
  await bumpVersion(env, payload.firmId);
  return json({ ok:true });
}

// ── Categories ─────────────────────────────────────────────────
async function categoryUpsert(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  const cat = body.category; if (!cat||!cat.name) return json({ error: 'Missing category' }, 400);
  if (cat.cloudId) {
    await env.DB.prepare('UPDATE inv_categories SET name=?,color=?,icon=? WHERE id=? AND firm_id=?')
      .bind(cat.name,cat.color||'#f97316',cat.icon||'📦',cat.cloudId,payload.firmId).run();
    await bumpVersion(env, payload.firmId);
    return json({ ok:true, cloudId:cat.cloudId });
  } else {
    const r = await env.DB.prepare('INSERT INTO inv_categories (firm_id,name,color,icon) VALUES (?,?,?,?)')
      .bind(payload.firmId,cat.name,cat.color||'#f97316',cat.icon||'📦').run();
    await bumpVersion(env, payload.firmId);
    return json({ ok:true, cloudId:r.meta.last_row_id });
  }
}

async function categoryDelete(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  if (!body.cloudId) return json({ error: 'Missing cloudId' }, 400);
  await env.DB.prepare('DELETE FROM inv_categories WHERE id=? AND firm_id=?').bind(body.cloudId, payload.firmId).run();
  await bumpVersion(env, payload.firmId);
  return json({ ok:true });
}

// ── Bills ──────────────────────────────────────────────────────
async function billInsert(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  const bill = body.bill; if (!bill) return json({ error: 'Missing bill' }, 400);
  const cart = JSON.stringify((bill.lines||bill.cart||[]).map(c=>({
    name:c.name||'',qty:c.qty??1,price:c.price??0,unit:c.unit||'pcs',
    sku:c.sku||'',gstRate:c.gstRate??0,gstAmt:c.gstAmt??0,
    taxable:c.taxable??0,subtotal:c.subtotal??((c.qty??1)*(c.price??0))
  })));
  const r = await env.DB.prepare(`INSERT INTO inv_bills
    (firm_id,total,discount,customer,phone,pay_mode,cart,bill_date,gst_enabled,total_gst,total_taxable,gst_type,discount_pct)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
  .bind(payload.firmId,bill.total||0,bill.discountAmt??bill.discount??0,
    bill.customerName||bill.customer||'',bill.customerPhone||bill.phone||'',
    bill.payMode||'',cart,
    bill.date?(bill.time?bill.date+'T'+bill.time:bill.date):new Date().toISOString(),
    bill.gstEnabled?1:0,bill.totalGST||0,bill.totalTaxable||0,
    bill.gstType||'intra',bill.discountPct||0).run();
  await bumpVersion(env, payload.firmId);
  return json({ ok:true, cloudId:r.meta.last_row_id });
}

async function billDelete(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  if (!body.cloudId) return json({ error: 'Missing cloudId' }, 400);
  await env.DB.prepare('DELETE FROM inv_bills WHERE id=? AND firm_id=?').bind(body.cloudId, payload.firmId).run();
  await bumpVersion(env, payload.firmId);
  return json({ ok:true });
}

// ── Ledger ─────────────────────────────────────────────────────
async function ledgerUpsert(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  const entry = body.entry; if (!entry||!entry.name) return json({ error: 'Missing entry' }, 400);
  const txs = JSON.stringify(entry.transactions||[]);
  if (entry.cloudId) {
    await env.DB.prepare(`UPDATE inv_ledger SET name=?,phone=?,notes=?,type=?,transactions=?,updated_at=datetime('now') WHERE id=? AND firm_id=?`)
      .bind(entry.name,entry.phone||'',entry.notes||'',entry.type||'debtor',txs,entry.cloudId,payload.firmId).run();
    await bumpVersion(env, payload.firmId);
    return json({ ok:true, cloudId:entry.cloudId });
  } else {
    const r = await env.DB.prepare('INSERT INTO inv_ledger (firm_id,name,phone,notes,type,transactions) VALUES (?,?,?,?,?,?)')
      .bind(payload.firmId,entry.name,entry.phone||'',entry.notes||'',entry.type||'debtor',txs).run();
    await bumpVersion(env, payload.firmId);
    return json({ ok:true, cloudId:r.meta.last_row_id });
  }
}

async function ledgerDelete(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  if (!body.cloudId) return json({ error: 'Missing cloudId' }, 400);
  await env.DB.prepare('DELETE FROM inv_ledger WHERE id=? AND firm_id=?').bind(body.cloudId, payload.firmId).run();
  await bumpVersion(env, payload.firmId);
  return json({ ok:true });
}

// ── Biz profile ────────────────────────────────────────────────
async function bizUpsert(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  const biz = body.biz; if (!biz) return json({ error: 'Missing biz' }, 400);
  const ex = await env.DB.prepare('SELECT id FROM inv_biz WHERE firm_id=?').bind(payload.firmId).first();
  if (ex) {
    await env.DB.prepare(`UPDATE inv_biz SET name=?,gst=?,address=?,phone=?,updated_at=datetime('now') WHERE firm_id=?`)
      .bind(biz.name||'',biz.gst||'',biz.address||'',biz.phone||'',payload.firmId).run();
  } else {
    await env.DB.prepare('INSERT INTO inv_biz (firm_id,name,gst,address,phone) VALUES (?,?,?,?,?)')
      .bind(payload.firmId,biz.name||'',biz.gst||'',biz.address||'',biz.phone||'').run();
  }
  await bumpVersion(env, payload.firmId);
  return json({ ok:true });
}

// ── Atomic Sale Deduct ─────────────────────────────────────────────────────
// Uses SQL qty = qty - ? so two simultaneous sales both apply correctly.
// Both persons' deductions are applied — never overwritten by each other.
async function saleDeduct(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  const { items } = body; // array of { cloudId, qtyDeduct, soldAdd }
  if (!Array.isArray(items) || !items.length) return json({ error: 'Missing items' }, 400);
  for (const it of items) {
    if (!it.cloudId || !it.qtyDeduct) continue;
    await env.DB.prepare(`
      UPDATE inv_items
      SET qty  = MAX(0, qty - ?),
          sold = sold + ?,
          updated_at = datetime('now')
      WHERE id=? AND firm_id=?`)
      .bind(it.qtyDeduct, it.soldAdd||it.qtyDeduct, it.cloudId, payload.firmId).run();
  }
  await bumpVersion(env, payload.firmId);
  return json({ ok: true });
}

// ── Change PIN (owner) ─────────────────────────────────────────────────────
async function changePin(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  const { oldPin, newPin } = body;
  if (!oldPin || !newPin) return json({ error: 'oldPin and newPin required' }, 400);
  if (!/^\d{4,6}$/.test(newPin)) return json({ error: 'PIN must be 4-6 digits' }, 400);
  const firm = await env.DB.prepare('SELECT owner_pin, owner_phone FROM firms WHERE id=?').bind(payload.firmId).first();
  if (!firm) return json({ error: 'Firm not found' }, 404);
  const oldHash = await hmacHex(env.PIN_SALT, firm.owner_phone + ':' + oldPin);
  if (!safeEqual(firm.owner_pin, oldHash)) return json({ error: 'Current PIN is incorrect' }, 403);
  const newHash = await hmacHex(env.PIN_SALT, firm.owner_phone + ':' + newPin);
  await env.DB.prepare('UPDATE firms SET owner_pin=? WHERE id=?').bind(newHash, payload.firmId).run();
  return json({ ok: true });
}

// ── Staff Lock Sync ────────────────────────────────────────────────────────
// Stores staff lock state in D1 so locking on one device locks all devices.
async function staffLockSet(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  const locked = body.locked ? 1 : 0;
  // Ensure firm_version row exists first, then update staff_locked
  await env.DB.prepare(`
    INSERT INTO firm_version (firm_id, updated_at, staff_locked)
    VALUES (?, datetime('now'), ?)
    ON CONFLICT(firm_id) DO UPDATE SET staff_locked=excluded.staff_locked, updated_at=datetime('now')`)
    .bind(payload.firmId, locked).run();
  await bumpVersion(env, payload.firmId);
  return json({ ok: true });
}
async function staffLockGet(req, env) {
  const { payload, error } = await requireAuth(req, env); if (error) return error;
  const row = await env.DB.prepare('SELECT staff_locked FROM firm_version WHERE firm_id=?')
    .bind(payload.firmId).first();
  return json({ locked: row ? !!row.staff_locked : false });
}

// ── OTP Generate (for staff forgot PIN) ───────────────────────────────────
// Generates a 6-digit OTP stored in D1 for 10 minutes.
// Owner sees it on their own logged-in device and tells staff verbally.
async function otpGenerate(req, env) {
  const { payload, error } = await requireAuth(req, env); if (error) return error;
  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  // Ensure firm_version row exists, then set OTP
  await env.DB.prepare(`
    INSERT INTO firm_version (firm_id, updated_at, otp_code, otp_expires)
    VALUES (?, datetime('now'), ?, ?)
    ON CONFLICT(firm_id) DO UPDATE SET otp_code=excluded.otp_code, otp_expires=excluded.otp_expires`)
    .bind(payload.firmId, otp, expires).run();
  return json({ otp }); // returned to owner's device only (they are authenticated)
}

// ── OTP Verify + Reset PIN ─────────────────────────────────────────────────
// Staff enters the OTP the owner told them — if valid, new PIN is set.
async function otpVerifyPin(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  const { otp, newPin } = body;
  if (!otp || !newPin) return json({ error: 'otp and newPin required' }, 400);
  if (!/^\d{4,6}$/.test(newPin)) return json({ error: 'PIN must be 4-6 digits' }, 400);
  const row = await env.DB.prepare('SELECT otp_code, otp_expires FROM firm_version WHERE firm_id=?')
    .bind(payload.firmId).first();
  if (!row || !row.otp_code) return json({ error: 'No OTP generated. Ask owner to generate one.' }, 400);
  if (new Date(row.otp_expires) < new Date()) return json({ error: 'OTP expired. Ask owner for a new one.' }, 400);
  if (!safeEqual(row.otp_code, otp)) return json({ error: 'Wrong OTP' }, 403);
  // Clear OTP after use
  await env.DB.prepare(`UPDATE firm_version SET otp_code=NULL, otp_expires=NULL WHERE firm_id=?`)
    .bind(payload.firmId).run();
  // Update firm owner PIN — use same hash format as login (phone + ':' + pin)
  const firm2 = await env.DB.prepare('SELECT owner_phone FROM firms WHERE id=?').bind(payload.firmId).first();
  const newHash = await hmacHex(env.PIN_SALT, (firm2 ? firm2.owner_phone : '') + ':' + newPin);
  await env.DB.prepare('UPDATE firms SET owner_pin=? WHERE id=?').bind(newHash, payload.firmId).run();
  return json({ ok: true });
}

// ── Ledger Atomic Transaction Append ──────────────────────────────────────
// Appends a single transaction to the JSON array in D1 atomically.
// Two staff adding transactions simultaneously both get saved.
async function ledgerTxAdd(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  const { cloudId, tx } = body;
  if (!cloudId || !tx) return json({ error: 'cloudId and tx required' }, 400);
  const row = await env.DB.prepare('SELECT transactions FROM inv_ledger WHERE id=? AND firm_id=?')
    .bind(cloudId, payload.firmId).first();
  if (!row) return json({ error: 'Ledger entry not found' }, 404);
  let txns = [];
  try { txns = JSON.parse(row.transactions || '[]'); } catch(e) {}
  // Avoid duplicate tx by id
  if (!txns.find(t => t.id === tx.id)) txns.push(tx);
  await env.DB.prepare(`UPDATE inv_ledger SET transactions=?, updated_at=datetime('now') WHERE id=? AND firm_id=?`)
    .bind(JSON.stringify(txns), cloudId, payload.firmId).run();
  await bumpVersion(env, payload.firmId);
  return json({ ok: true });
}

// ── Ledger Atomic Transaction Delete ──────────────────────────────────────
async function ledgerTxDel(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  const { cloudId, txId } = body;
  if (!cloudId || !txId) return json({ error: 'cloudId and txId required' }, 400);
  const row = await env.DB.prepare('SELECT transactions FROM inv_ledger WHERE id=? AND firm_id=?')
    .bind(cloudId, payload.firmId).first();
  if (!row) return json({ error: 'Ledger entry not found' }, 404);
  let txns = [];
  try { txns = JSON.parse(row.transactions || '[]'); } catch(e) {}
  txns = txns.filter(t => String(t.id) !== String(txId));
  await env.DB.prepare(`UPDATE inv_ledger SET transactions=?, updated_at=datetime('now') WHERE id=? AND firm_id=?`)
    .bind(JSON.stringify(txns), cloudId, payload.firmId).run();
  await bumpVersion(env, payload.firmId);
  return json({ ok: true });
}

// ── OTP Reset Firm PIN (public — no token, for forgot firm login PIN) ──────
// Owner generates OTP from their logged-in device (via /otp-generate which needs token).
// Staff/other device uses this endpoint with phone + OTP + newPin — no token needed.
async function otpResetFirm(req, env) {
  let body = {};
  try { body = await req.json(); } catch(e) {}
  const { phone, otp, newPin } = body;
  if (!phone || !otp || !newPin) return json({ error: 'phone, otp and newPin required' }, 400);
  if (!/^\d{4,6}$/.test(newPin)) return json({ error: 'PIN must be 4-6 digits' }, 400);
  // Find firm by phone
  const firm = await env.DB.prepare('SELECT id FROM firms WHERE owner_phone=?').bind(phone).first();
  if (!firm) return json({ error: 'No firm found for this phone number' }, 404);
  const fv = await env.DB.prepare('SELECT otp_code, otp_expires FROM firm_version WHERE firm_id=?').bind(firm.id).first();
  if (!fv || !fv.otp_code) return json({ error: 'No OTP generated. Owner must generate one from their device first.' }, 400);
  if (new Date(fv.otp_expires) < new Date()) return json({ error: 'OTP expired. Ask owner to generate a new one.' }, 400);
  if (!safeEqual(fv.otp_code, otp)) return json({ error: 'Wrong OTP' }, 403);
  // Clear OTP + update PIN — use same hash format as login (phone + ':' + pin)
  await env.DB.prepare('UPDATE firm_version SET otp_code=NULL, otp_expires=NULL WHERE firm_id=?').bind(firm.id).run();
  const newHash = await hmacHex(env.PIN_SALT, phone + ':' + newPin);
  await env.DB.prepare('UPDATE firms SET owner_pin=? WHERE id=?').bind(newHash, firm.id).run();
  return json({ ok: true });
}
