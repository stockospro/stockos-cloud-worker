/**
 * StockOS Cloud Worker — Full Online Database
 * All inventory, bills, ledger, categories, products, stock synced to D1
 */

const ALLOWED_ORIGIN = 'https://stockospro.github.io';

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
  let body;
  try { body = await req.json(); } catch(e) { body = {}; }
  const payload = await verifyToken(body.token, env);
  if (!payload) return { error: json({ error: 'Not logged in — please log in again.' }, 401), body: null };
  return { payload, body };
}

// ── Firm signup ──
async function firmSignup(req, env) {
  const { name, phone, pin, deviceId } = await req.json();
  if (!name || !phone || !pin) return json({ error: 'Missing name, phone, or PIN' }, 400);
  const existing = await env.DB.prepare('SELECT id FROM firms WHERE owner_phone = ?').bind(phone).first();
  if (existing) return json({ error: 'An account with this phone already exists. Please log in.' }, 409);
  const pinHash = await hmacHex(env.PIN_SALT, phone + ':' + pin);
  const result = await env.DB.prepare(
    'INSERT INTO firms (name, owner_phone, owner_pin, device_id) VALUES (?, ?, ?, ?)'
  ).bind(name, phone, pinHash, deviceId || null).run();
  const firmId = result.meta.last_row_id;
  const token = await makeToken({ role: 'owner', firmId, name }, env);
  return json({ token, firmId, role: 'owner', name });
}

// ── Login ──
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

// ══════════════════════════════════════════════════════════════
// INVENTORY ITEMS — full CRUD, synced to cloud
// ══════════════════════════════════════════════════════════════

async function itemsList(req, env) {
  const { payload, error } = await requireAuth(req, env); if (error) return error;
  const rows = await env.DB.prepare(
    'SELECT * FROM inv_items WHERE firm_id = ? ORDER BY name'
  ).bind(payload.firmId).all();
  const items = rows.results.map(r => ({
    ...r,
    expiryBatches: r.expiry_batches ? JSON.parse(r.expiry_batches) : [],
    minQty: r.min_qty,
    purchasePrice: r.purchase_price,
    place: r.place || '',
    gstRate: r.gst_rate || 0,
    hsnCode: r.hsn_code || '',
  }));
  return json({ items });
}

async function itemSave(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  const item = body.item;
  if (!item || !item.name) return json({ error: 'Missing item data' }, 400);
  const batches = JSON.stringify(item.expiryBatches || []);
  if (item.cloudId) {
    // Update existing
    await env.DB.prepare(`UPDATE inv_items SET
      name=?,sku=?,category=?,qty=?,min_qty=?,price=?,purchase_price=?,sold=?,unit=?,
      expiry=?,expiry_batches=?,image=?,place=?,gst_rate=?,hsn_code=?,updated_at=datetime('now')
      WHERE id=? AND firm_id=?`
    ).bind(
      item.name, item.sku||'', item.category||'', item.qty||0, item.minQty||0,
      item.price||0, item.purchasePrice||0, item.sold||0, item.unit||'pcs',
      item.expiry||'', batches, item.image||'', item.place||'',
      item.gstRate||0, item.hsnCode||'', item.cloudId, payload.firmId
    ).run();
    return json({ ok: true, cloudId: item.cloudId });
  } else {
    // Insert new
    const r = await env.DB.prepare(`INSERT INTO inv_items
      (firm_id,name,sku,category,qty,min_qty,price,purchase_price,sold,unit,expiry,expiry_batches,image,place,gst_rate,hsn_code)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      payload.firmId, item.name, item.sku||'', item.category||'', item.qty||0,
      item.minQty||0, item.price||0, item.purchasePrice||0, item.sold||0,
      item.unit||'pcs', item.expiry||'', batches, item.image||'', item.place||'',
      item.gstRate||0, item.hsnCode||''
    ).run();
    return json({ ok: true, cloudId: r.meta.last_row_id });
  }
}

async function itemDelete(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  if (!body.cloudId) return json({ error: 'Missing cloudId' }, 400);
  await env.DB.prepare('DELETE FROM inv_items WHERE id=? AND firm_id=?')
    .bind(body.cloudId, payload.firmId).run();
  return json({ ok: true });
}

// ══════════════════════════════════════════════════════════════
// CATEGORIES
// ══════════════════════════════════════════════════════════════

async function categoriesList(req, env) {
  const { payload, error } = await requireAuth(req, env); if (error) return error;
  const rows = await env.DB.prepare('SELECT * FROM inv_categories WHERE firm_id = ? ORDER BY name').bind(payload.firmId).all();
  return json({ categories: rows.results });
}

async function categorySave(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  const cat = body.category;
  if (!cat || !cat.name) return json({ error: 'Missing category data' }, 400);
  if (cat.cloudId) {
    await env.DB.prepare('UPDATE inv_categories SET name=?,color=?,icon=? WHERE id=? AND firm_id=?')
      .bind(cat.name, cat.color||'#f97316', cat.icon||'📦', cat.cloudId, payload.firmId).run();
    return json({ ok: true, cloudId: cat.cloudId });
  } else {
    const r = await env.DB.prepare('INSERT INTO inv_categories (firm_id,name,color,icon) VALUES (?,?,?,?)')
      .bind(payload.firmId, cat.name, cat.color||'#f97316', cat.icon||'📦').run();
    return json({ ok: true, cloudId: r.meta.last_row_id });
  }
}

async function categoryDelete(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  if (!body.cloudId) return json({ error: 'Missing cloudId' }, 400);
  await env.DB.prepare('DELETE FROM inv_categories WHERE id=? AND firm_id=?')
    .bind(body.cloudId, payload.firmId).run();
  return json({ ok: true });
}

// ══════════════════════════════════════════════════════════════
// BILLS
// ══════════════════════════════════════════════════════════════

async function billsList(req, env) {
  const { payload, error } = await requireAuth(req, env); if (error) return error;
  const rows = await env.DB.prepare(
    'SELECT * FROM inv_bills WHERE firm_id = ? ORDER BY created_at DESC LIMIT 500'
  ).bind(payload.firmId).all();
  const bills = rows.results.map(r => ({ ...r, cart: r.cart ? JSON.parse(r.cart) : [] }));
  return json({ bills });
}

async function billSave(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  const bill = body.bill;
  if (!bill) return json({ error: 'Missing bill data' }, 400);
  const cart = JSON.stringify(bill.cart || []);
  const r = await env.DB.prepare(`INSERT INTO inv_bills
    (firm_id,total,discount,customer,phone,pay_mode,cart,bill_date)
    VALUES (?,?,?,?,?,?,?,?)`
  ).bind(
    payload.firmId, bill.total||0, bill.discount||0,
    bill.customer||'', bill.phone||'', bill.payMode||'',
    cart, bill.date||new Date().toISOString()
  ).run();
  return json({ ok: true, cloudId: r.meta.last_row_id });
}

async function billDelete(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  if (!body.cloudId) return json({ error: 'Missing cloudId' }, 400);
  await env.DB.prepare('DELETE FROM inv_bills WHERE id=? AND firm_id=?')
    .bind(body.cloudId, payload.firmId).run();
  return json({ ok: true });
}

// ══════════════════════════════════════════════════════════════
// LEDGER — debtors & creditors
// ══════════════════════════════════════════════════════════════

async function ledgerList(req, env) {
  const { payload, error } = await requireAuth(req, env); if (error) return error;
  const rows = await env.DB.prepare(
    'SELECT * FROM inv_ledger WHERE firm_id = ? ORDER BY name'
  ).bind(payload.firmId).all();
  const entries = rows.results.map(r => ({
    ...r, transactions: r.transactions ? JSON.parse(r.transactions) : []
  }));
  return json({ entries });
}

async function ledgerSave(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  const entry = body.entry;
  if (!entry || !entry.name) return json({ error: 'Missing entry data' }, 400);
  const txs = JSON.stringify(entry.transactions || []);
  if (entry.cloudId) {
    await env.DB.prepare(`UPDATE inv_ledger SET name=?,phone=?,notes=?,type=?,transactions=?,updated_at=datetime('now')
      WHERE id=? AND firm_id=?`)
      .bind(entry.name, entry.phone||'', entry.notes||'', entry.type||'debtor', txs, entry.cloudId, payload.firmId).run();
    return json({ ok: true, cloudId: entry.cloudId });
  } else {
    const r = await env.DB.prepare('INSERT INTO inv_ledger (firm_id,name,phone,notes,type,transactions) VALUES (?,?,?,?,?,?)')
      .bind(payload.firmId, entry.name, entry.phone||'', entry.notes||'', entry.type||'debtor', txs).run();
    return json({ ok: true, cloudId: r.meta.last_row_id });
  }
}

async function ledgerDelete(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  if (!body.cloudId) return json({ error: 'Missing cloudId' }, 400);
  await env.DB.prepare('DELETE FROM inv_ledger WHERE id=? AND firm_id=?')
    .bind(body.cloudId, payload.firmId).run();
  return json({ ok: true });
}

// ══════════════════════════════════════════════════════════════
// BIZ PROFILE
// ══════════════════════════════════════════════════════════════

async function bizGet(req, env) {
  const { payload, error } = await requireAuth(req, env); if (error) return error;
  const row = await env.DB.prepare('SELECT * FROM inv_biz WHERE firm_id = ?').bind(payload.firmId).first();
  return json({ biz: row || {} });
}

async function bizSave(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  const biz = body.biz;
  if (!biz) return json({ error: 'Missing biz data' }, 400);
  const existing = await env.DB.prepare('SELECT id FROM inv_biz WHERE firm_id = ?').bind(payload.firmId).first();
  if (existing) {
    await env.DB.prepare(`UPDATE inv_biz SET name=?,gst=?,address=?,phone=?,logo=?,updated_at=datetime('now') WHERE firm_id=?`)
      .bind(biz.name||'', biz.gst||'', biz.address||'', biz.phone||'', biz.logo||'', payload.firmId).run();
  } else {
    await env.DB.prepare('INSERT INTO inv_biz (firm_id,name,gst,address,phone,logo) VALUES (?,?,?,?,?,?)')
      .bind(payload.firmId, biz.name||'', biz.gst||'', biz.address||'', biz.phone||'', biz.logo||'').run();
  }
  return json({ ok: true });
}

// ══════════════════════════════════════════════════════════════
// SYNC — push all local data to cloud at once (first-time migration)
// ══════════════════════════════════════════════════════════════

async function syncPush(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  if (payload.role !== 'owner') return json({ error: 'Only owner can sync' }, 403);
  const { items, categories, bills, debtors, creditors, biz } = body;

  // Clear existing data for this firm and re-insert
  await env.DB.batch([
    env.DB.prepare('DELETE FROM inv_items WHERE firm_id=?').bind(payload.firmId),
    env.DB.prepare('DELETE FROM inv_categories WHERE firm_id=?').bind(payload.firmId),
    env.DB.prepare('DELETE FROM inv_bills WHERE firm_id=?').bind(payload.firmId),
    env.DB.prepare('DELETE FROM inv_ledger WHERE firm_id=?').bind(payload.firmId),
  ]);

  const stmts = [];

  // Insert items
  for (const item of (items||[])) {
    stmts.push(env.DB.prepare(`INSERT INTO inv_items
      (firm_id,name,sku,category,qty,min_qty,price,purchase_price,sold,unit,expiry,expiry_batches,image,place,gst_rate,hsn_code)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind(payload.firmId, item.name||'', item.sku||'', item.category||'', item.qty||0,
        item.minQty||0, item.price||0, item.purchasePrice||0, item.sold||0,
        item.unit||'pcs', item.expiry||'', JSON.stringify(item.expiryBatches||[]),
        item.image||'', item.place||'', item.gstRate||0, item.hsnCode||''));
  }

  // Insert categories
  for (const cat of (categories||[])) {
    stmts.push(env.DB.prepare('INSERT INTO inv_categories (firm_id,name,color,icon) VALUES (?,?,?,?)')
      .bind(payload.firmId, cat.name||'', cat.color||'#f97316', cat.icon||'📦'));
  }

  // Insert bills (skip images in cart to save space)
  for (const bill of (bills||[])) {
    const cart = (bill.cart||[]).map(c=>({...c,image:undefined}));
    stmts.push(env.DB.prepare(`INSERT INTO inv_bills (firm_id,total,discount,customer,phone,pay_mode,cart,bill_date) VALUES (?,?,?,?,?,?,?,?)`)
      .bind(payload.firmId, bill.total||0, bill.discount||0,
        bill.customer||'', bill.phone||'', bill.payMode||'',
        JSON.stringify(cart), bill.date||new Date().toISOString()));
  }

  // Insert ledger entries
  for (const d of (debtors||[])) {
    stmts.push(env.DB.prepare('INSERT INTO inv_ledger (firm_id,name,phone,notes,type,transactions) VALUES (?,?,?,?,?,?)')
      .bind(payload.firmId, d.name||'', d.phone||'', d.notes||'', 'debtor', JSON.stringify(d.transactions||[])));
  }
  for (const c of (creditors||[])) {
    stmts.push(env.DB.prepare('INSERT INTO inv_ledger (firm_id,name,phone,notes,type,transactions) VALUES (?,?,?,?,?,?)')
      .bind(payload.firmId, c.name||'', c.phone||'', c.notes||'', 'creditor', JSON.stringify(c.transactions||[])));
  }

  // Biz profile
  if (biz) {
    const existingBiz = await env.DB.prepare('SELECT id FROM inv_biz WHERE firm_id=?').bind(payload.firmId).first();
    if (existingBiz) {
      stmts.push(env.DB.prepare(`UPDATE inv_biz SET name=?,gst=?,address=?,phone=?,logo=?,updated_at=datetime('now') WHERE firm_id=?`)
        .bind(biz.name||'', biz.gst||'', biz.address||'', biz.phone||'', biz.logo||'', payload.firmId));
    } else {
      stmts.push(env.DB.prepare('INSERT INTO inv_biz (firm_id,name,gst,address,phone,logo) VALUES (?,?,?,?,?,?)')
        .bind(payload.firmId, biz.name||'', biz.gst||'', biz.address||'', biz.phone||'', biz.logo||''));
    }
  }

  // Execute in batches of 50 (D1 limit)
  for (let i = 0; i < stmts.length; i += 50) {
    await env.DB.batch(stmts.slice(i, i + 50));
  }

  return json({ ok: true, synced: { items: (items||[]).length, categories: (categories||[]).length, bills: (bills||[]).length, ledger: (debtors||[]).length + (creditors||[]).length } });
}

// ══════════════════════════════════════════════════════════════
// FULL LOAD — get all data in one call
// ══════════════════════════════════════════════════════════════

async function syncLoad(req, env) {
  const { payload, error } = await requireAuth(req, env); if (error) return error;
  const [itemsR, catsR, billsR, ledgerR, bizR] = await Promise.all([
    env.DB.prepare('SELECT * FROM inv_items WHERE firm_id=? ORDER BY name').bind(payload.firmId).all(),
    env.DB.prepare('SELECT * FROM inv_categories WHERE firm_id=? ORDER BY name').bind(payload.firmId).all(),
    env.DB.prepare('SELECT * FROM inv_bills WHERE firm_id=? ORDER BY created_at DESC LIMIT 500').bind(payload.firmId).all(),
    env.DB.prepare('SELECT * FROM inv_ledger WHERE firm_id=? ORDER BY name').bind(payload.firmId).all(),
    env.DB.prepare('SELECT * FROM inv_biz WHERE firm_id=?').bind(payload.firmId).first(),
  ]);

  const items = itemsR.results.map(r => ({
    id: r.id, cloudId: r.id, name: r.name, sku: r.sku, category: r.category,
    qty: r.qty, minQty: r.min_qty, price: r.price, purchasePrice: r.purchase_price,
    sold: r.sold||0, unit: r.unit, expiry: r.expiry||'', place: r.place||'',
    gstRate: r.gst_rate||0, hsnCode: r.hsn_code||'', image: r.image||'',
    expiryBatches: r.expiry_batches ? JSON.parse(r.expiry_batches) : [],
  }));

  const categories = catsR.results.map(r => ({
    id: r.id, cloudId: r.id, name: r.name, color: r.color, icon: r.icon,
  }));

  const bills = billsR.results.map(r => ({
    id: r.id, cloudId: r.id, total: r.total, discount: r.discount,
    customer: r.customer, phone: r.phone, payMode: r.pay_mode,
    date: r.bill_date, cart: r.cart ? JSON.parse(r.cart) : [],
  }));

  const ledger = ledgerR.results.map(r => ({
    id: r.id, cloudId: r.id, name: r.name, phone: r.phone,
    notes: r.notes, type: r.type, transactions: r.transactions ? JSON.parse(r.transactions) : [],
  }));

  return json({
    items,
    categories,
    bills,
    debtors: ledger.filter(e => e.type === 'debtor'),
    creditors: ledger.filter(e => e.type === 'creditor'),
    biz: bizR || {},
    role: payload.role,
    name: payload.name,
  });
}

// ══════════════════════════════════════════════════════════════
// GODOWN / STAFF (original endpoints kept)
// ══════════════════════════════════════════════════════════════

async function godownAdd(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  if (payload.role !== 'owner') return json({ error: 'Only the owner can add godowns' }, 403);
  const { name } = body;
  if (!name) return json({ error: 'Missing godown name' }, 400);
  const r = await env.DB.prepare('INSERT INTO godowns (firm_id, name) VALUES (?, ?)').bind(payload.firmId, name).run();
  return json({ id: r.meta.last_row_id, name });
}

async function staffAdd(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  if (payload.role !== 'owner') return json({ error: 'Only the owner can add staff' }, 403);
  const { name, phone, pin } = body;
  if (!name || !phone || !pin) return json({ error: 'Missing name, phone, or PIN' }, 400);
  const pinHash = await hmacHex(env.PIN_SALT, phone + ':' + pin);
  const r = await env.DB.prepare('INSERT INTO staff (firm_id, name, phone, pin_hash) VALUES (?, ?, ?, ?)')
    .bind(payload.firmId, name, phone, pinHash).run();
  return json({ id: r.meta.last_row_id, name, phone });
}

async function stockSet(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  if (payload.role !== 'owner') return json({ error: 'Only the owner can set stock' }, 403);
  const { productId, godownId, qty } = body;
  if (!productId || !godownId || qty === undefined) return json({ error: 'Missing productId, godownId, or qty' }, 400);
  await env.DB.prepare(
    `INSERT INTO stock (product_id, godown_id, qty, updated_at) VALUES (?, ?, ?, datetime('now'))
     ON CONFLICT(product_id, godown_id) DO UPDATE SET qty = excluded.qty, updated_at = datetime('now')`
  ).bind(productId, godownId, qty).run();
  return json({ ok: true });
}

async function stockList(req, env) {
  const { payload, error } = await requireAuth(req, env); if (error) return error;
  const rows = await env.DB.prepare(`
    SELECT p.id as product_id, p.name as product_name, p.sku, p.unit, p.price,
           g.id as godown_id, g.name as godown_name, COALESCE(s.qty, 0) as qty
    FROM products p CROSS JOIN godowns g ON g.firm_id = p.firm_id
    LEFT JOIN stock s ON s.product_id = p.id AND s.godown_id = g.id
    WHERE p.firm_id = ? ORDER BY p.name, g.name
  `).bind(payload.firmId).all();
  return json({ stock: rows.results });
}

async function saleCreate(req, env) {
  const { payload, body, error } = await requireAuth(req, env); if (error) return error;
  const { productId, godownId, qty, amount, customerName } = body;
  if (!productId || !godownId || !qty) return json({ error: 'Missing productId, godownId, or qty' }, 400);
  const current = await env.DB.prepare('SELECT qty FROM stock WHERE product_id = ? AND godown_id = ?').bind(productId, godownId).first();
  const currentQty = current ? current.qty : 0;
  if (currentQty < qty) return json({ error: `Only ${currentQty} in stock` }, 400);
  const staffId = payload.staffId || null;
  await env.DB.batch([
    env.DB.prepare(`UPDATE stock SET qty = qty - ?, updated_at = datetime('now') WHERE product_id = ? AND godown_id = ?`).bind(qty, productId, godownId),
    env.DB.prepare(`INSERT INTO sales (firm_id, godown_id, staff_id, product_id, qty, amount, customer_name) VALUES (?, ?, ?, ?, ?, ?, ?)`).bind(payload.firmId, godownId, staffId, productId, qty, amount || 0, customerName || ''),
  ]);
  return json({ ok: true, remaining: currentQty - qty });
}

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
      if (req.method === 'POST' && url.pathname === '/firm-signup')    return await firmSignup(req, env);
      if (req.method === 'POST' && url.pathname === '/login')          return await login(req, env);
      // Full sync endpoints
      if (req.method === 'POST' && url.pathname === '/sync-push')      return await syncPush(req, env);
      if (req.method === 'POST' && url.pathname === '/sync-load')      return await syncLoad(req, env);
      // Items
      if (req.method === 'POST' && url.pathname === '/items-list')     return await itemsList(req, env);
      if (req.method === 'POST' && url.pathname === '/item-save')      return await itemSave(req, env);
      if (req.method === 'POST' && url.pathname === '/item-delete')    return await itemDelete(req, env);
      // Categories
      if (req.method === 'POST' && url.pathname === '/categories-list')return await categoriesList(req, env);
      if (req.method === 'POST' && url.pathname === '/category-save')  return await categorySave(req, env);
      if (req.method === 'POST' && url.pathname === '/category-delete')return await categoryDelete(req, env);
      // Bills
      if (req.method === 'POST' && url.pathname === '/bills-list')     return await billsList(req, env);
      if (req.method === 'POST' && url.pathname === '/bill-save')      return await billSave(req, env);
      if (req.method === 'POST' && url.pathname === '/bill-delete')    return await billDelete(req, env);
      // Ledger
      if (req.method === 'POST' && url.pathname === '/ledger-list')    return await ledgerList(req, env);
      if (req.method === 'POST' && url.pathname === '/ledger-save')    return await ledgerSave(req, env);
      if (req.method === 'POST' && url.pathname === '/ledger-delete')  return await ledgerDelete(req, env);
      // Biz profile
      if (req.method === 'POST' && url.pathname === '/biz-get')        return await bizGet(req, env);
      if (req.method === 'POST' && url.pathname === '/biz-save')       return await bizSave(req, env);
      // Godown/staff/stock (original)
      if (req.method === 'POST' && url.pathname === '/godown-add')     return await godownAdd(req, env);
      if (req.method === 'POST' && url.pathname === '/staff-add')      return await staffAdd(req, env);
      if (req.method === 'POST' && url.pathname === '/stock-set')      return await stockSet(req, env);
      if (req.method === 'POST' && url.pathname === '/stock-list')     return await stockList(req, env);
      if (req.method === 'POST' && url.pathname === '/sale-create')    return await saleCreate(req, env);
      if (req.method === 'POST' && url.pathname === '/meta')           return await meta(req, env);
      return json({ error: 'Not found' }, 404);
    } catch (e) {
      return json({ error: 'Server error', detail: String(e) }, 500);
    }
  },
};
