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
  const { token } = await req.json().catch(() => ({}));
  const payload = await verifyToken(token, env);
  if (!payload) return { error: json({ error: 'Not logged in — please log in again.' }, 401) };
  return { payload, token };
}

// ── Firm signup — one-time, done by the firm owner ──
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
  const { payload, error } = await requireAuth(req, env); if (error) return error;
  if (payload.role !== 'owner') return json({ error: 'Only the owner can add godowns' }, 403);
  const { name } = await req.json();
  if (!name) return json({ error: 'Missing godown name' }, 400);
  const r = await env.DB.prepare('INSERT INTO godowns (firm_id, name) VALUES (?, ?)').bind(payload.firmId, name).run();
  return json({ id: r.meta.last_row_id, name });
}

// ── Owner: add a salesman ──
async function staffAdd(req, env) {
  const { payload, error } = await requireAuth(req, env); if (error) return error;
  if (payload.role !== 'owner') return json({ error: 'Only the owner can add staff' }, 403);
  const { name, phone, pin } = await req.json();
  if (!name || !phone || !pin) return json({ error: 'Missing name, phone, or PIN' }, 400);
  const pinHash = await hmacHex(env.PIN_SALT, phone + ':' + pin);
  const r = await env.DB.prepare('INSERT INTO staff (firm_id, name, phone, pin_hash) VALUES (?, ?, ?, ?)')
    .bind(payload.firmId, name, phone, pinHash).run();
  return json({ id: r.meta.last_row_id, name, phone });
}

// ── Owner: add a product ──
async function productAdd(req, env) {
  const { payload, error } = await requireAuth(req, env); if (error) return error;
  if (payload.role !== 'owner') return json({ error: 'Only the owner can add products' }, 403);
  const { name, sku, unit, price } = await req.json();
  if (!name) return json({ error: 'Missing product name' }, 400);
  const r = await env.DB.prepare('INSERT INTO products (firm_id, name, sku, unit, price) VALUES (?, ?, ?, ?, ?)')
    .bind(payload.firmId, name, sku || '', unit || 'pcs', price || 0).run();
  return json({ id: r.meta.last_row_id, name });
}

// ── Owner: set/adjust stock for a product at a godown ──
async function stockSet(req, env) {
  const { payload, error } = await requireAuth(req, env); if (error) return error;
  if (payload.role !== 'owner') return json({ error: 'Only the owner can set stock' }, 403);
  const { productId, godownId, qty } = await req.json();
  if (!productId || !godownId || qty === undefined) return json({ error: 'Missing productId, godownId, or qty' }, 400);
  await env.DB.prepare(
    `INSERT INTO stock (product_id, godown_id, qty, updated_at) VALUES (?, ?, ?, datetime('now'))
     ON CONFLICT(product_id, godown_id) DO UPDATE SET qty = excluded.qty, updated_at = datetime('now')`
  ).bind(productId, godownId, qty).run();
  return json({ ok: true });
}

// ── Everyone (owner + staff): live stock list — this is the core feature ──
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

// ── Staff: record a sale — deducts stock live, right here ──
async function saleCreate(req, env) {
  const { payload, error } = await requireAuth(req, env); if (error) return error;
  const { productId, godownId, qty, amount, customerName } = await req.json();
  if (!productId || !godownId || !qty) return json({ error: 'Missing productId, godownId, or qty' }, 400);

  const current = await env.DB.prepare('SELECT qty FROM stock WHERE product_id = ? AND godown_id = ?')
    .bind(productId, godownId).first();
  const currentQty = current ? current.qty : 0;
  if (currentQty < qty) return json({ error: `Only ${currentQty} in stock — not enough for this sale` }, 400);

  const staffId = payload.staffId || null; // owner can also log a sale directly
  await env.DB.batch([
    env.DB.prepare(`UPDATE stock SET qty = qty - ?, updated_at = datetime('now') WHERE product_id = ? AND godown_id = ?`)
      .bind(qty, productId, godownId),
    env.DB.prepare(`INSERT INTO sales (firm_id, godown_id, staff_id, product_id, qty, amount, customer_name)
                     VALUES (?, ?, ?, ?, ?, ?, ?)`)
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

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return cors(new Response(null, { status: 204 }));
    const url = new URL(req.url);
    try {
      if (req.method === 'POST' && url.pathname === '/firm-signup') return await firmSignup(req, env);
      if (req.method === 'POST' && url.pathname === '/login') return await login(req, env);
      if (req.method === 'POST' && url.pathname === '/godown-add') return await godownAdd(req, env);
      if (req.method === 'POST' && url.pathname === '/staff-add') return await staffAdd(req, env);
      if (req.method === 'POST' && url.pathname === '/product-add') return await productAdd(req, env);
      if (req.method === 'POST' && url.pathname === '/stock-set') return await stockSet(req, env);
      if (req.method === 'POST' && url.pathname === '/stock-list') return await stockList(req, env);
      if (req.method === 'POST' && url.pathname === '/sale-create') return await saleCreate(req, env);
      if (req.method === 'POST' && url.pathname === '/sales-list') return await salesList(req, env);
      if (req.method === 'POST' && url.pathname === '/meta') return await meta(req, env);
      return json({ error: 'Not found' }, 404);
    } catch (e) {
      return json({ error: 'Server error', detail: String(e) }, 500);
    }
  },
};
