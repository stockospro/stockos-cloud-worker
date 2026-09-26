-- Original tables (kept as-is)
CREATE TABLE IF NOT EXISTS firms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  owner_phone TEXT NOT NULL,
  device_id TEXT,
  owner_pin TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS godowns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  firm_id INTEGER NOT NULL REFERENCES firms(id),
  name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS staff (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  firm_id INTEGER NOT NULL REFERENCES firms(id),
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  pin_hash TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  firm_id INTEGER NOT NULL REFERENCES firms(id),
  name TEXT NOT NULL,
  sku TEXT,
  unit TEXT NOT NULL DEFAULT 'pcs',
  price REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS stock (
  product_id INTEGER NOT NULL REFERENCES products(id),
  godown_id INTEGER NOT NULL REFERENCES godowns(id),
  qty REAL NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (product_id, godown_id)
);
CREATE TABLE IF NOT EXISTS sales (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  firm_id INTEGER NOT NULL REFERENCES firms(id),
  godown_id INTEGER NOT NULL REFERENCES godowns(id),
  staff_id INTEGER REFERENCES staff(id),
  product_id INTEGER NOT NULL REFERENCES products(id),
  qty REAL NOT NULL,
  amount REAL NOT NULL,
  customer_name TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- NEW: Full inventory stored in cloud
CREATE TABLE IF NOT EXISTS inv_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  firm_id INTEGER NOT NULL REFERENCES firms(id),
  name TEXT NOT NULL,
  sku TEXT DEFAULT '',
  category TEXT DEFAULT '',
  qty REAL DEFAULT 0,
  min_qty REAL DEFAULT 0,
  price REAL DEFAULT 0,
  purchase_price REAL DEFAULT 0,
  sold REAL DEFAULT 0,
  unit TEXT DEFAULT 'pcs',
  expiry TEXT DEFAULT '',
  expiry_batches TEXT DEFAULT '[]',
  image TEXT DEFAULT '',
  place TEXT DEFAULT '',
  gst_rate REAL DEFAULT 0,
  hsn_code TEXT DEFAULT '',
  updated_at TEXT DEFAULT (datetime('now'))
);

-- NEW: Categories
CREATE TABLE IF NOT EXISTS inv_categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  firm_id INTEGER NOT NULL REFERENCES firms(id),
  name TEXT NOT NULL,
  color TEXT DEFAULT '#f97316',
  icon TEXT DEFAULT '📦'
);

-- NEW: Bills/invoices
CREATE TABLE IF NOT EXISTS inv_bills (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  firm_id INTEGER NOT NULL REFERENCES firms(id),
  total REAL DEFAULT 0,
  discount REAL DEFAULT 0,
  customer TEXT DEFAULT '',
  phone TEXT DEFAULT '',
  pay_mode TEXT DEFAULT '',
  cart TEXT DEFAULT '[]',
  bill_date TEXT DEFAULT (datetime('now')),
  created_at TEXT DEFAULT (datetime('now'))
);

-- NEW: Ledger (debtors + creditors)
CREATE TABLE IF NOT EXISTS inv_ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  firm_id INTEGER NOT NULL REFERENCES firms(id),
  name TEXT NOT NULL,
  phone TEXT DEFAULT '',
  notes TEXT DEFAULT '',
  type TEXT DEFAULT 'debtor',
  transactions TEXT DEFAULT '[]',
  updated_at TEXT DEFAULT (datetime('now'))
);

-- NEW: Business profile
CREATE TABLE IF NOT EXISTS inv_biz (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  firm_id INTEGER NOT NULL REFERENCES firms(id),
  name TEXT DEFAULT '',
  gst TEXT DEFAULT '',
  address TEXT DEFAULT '',
  phone TEXT DEFAULT '',
  logo TEXT DEFAULT '',
  updated_at TEXT DEFAULT (datetime('now'))
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_staff_firm ON staff(firm_id);
CREATE INDEX IF NOT EXISTS idx_products_firm ON products(firm_id);
CREATE INDEX IF NOT EXISTS idx_godowns_firm ON godowns(firm_id);
CREATE INDEX IF NOT EXISTS idx_sales_firm ON sales(firm_id);
CREATE INDEX IF NOT EXISTS idx_sales_staff ON sales(staff_id);
CREATE INDEX IF NOT EXISTS idx_stock_godown ON stock(godown_id);
CREATE INDEX IF NOT EXISTS idx_inv_items_firm ON inv_items(firm_id);
CREATE INDEX IF NOT EXISTS idx_inv_cats_firm ON inv_categories(firm_id);
CREATE INDEX IF NOT EXISTS idx_inv_bills_firm ON inv_bills(firm_id);
CREATE INDEX IF NOT EXISTS idx_inv_ledger_firm ON inv_ledger(firm_id);
CREATE INDEX IF NOT EXISTS idx_inv_biz_firm ON inv_biz(firm_id);
