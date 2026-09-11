-- StockOS Cloud — multi-godown, multi-salesman live stock system
-- Run this once when setting up your D1 database (see setup steps in README.md)

-- One row per paying firm/distributor (tied to their existing StockOS Pro Device ID,
-- so this plugs into the licensing system you already have)
CREATE TABLE firms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  owner_phone TEXT NOT NULL,
  device_id TEXT,                -- links to the existing StockOS Pro license, optional
  owner_pin TEXT NOT NULL,       -- owner's own login PIN (hashed, see worker.js)
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Godowns/warehouses belonging to a firm
CREATE TABLE godowns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  firm_id INTEGER NOT NULL REFERENCES firms(id),
  name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Salesmen / staff — each gets their own phone + PIN login
CREATE TABLE staff (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  firm_id INTEGER NOT NULL REFERENCES firms(id),
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  pin_hash TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Products
CREATE TABLE products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  firm_id INTEGER NOT NULL REFERENCES firms(id),
  name TEXT NOT NULL,
  sku TEXT,
  unit TEXT NOT NULL DEFAULT 'pcs',
  price REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Current stock of each product, per godown — this is the live number
-- salesmen check before promising anything to a customer.
CREATE TABLE stock (
  product_id INTEGER NOT NULL REFERENCES products(id),
  godown_id INTEGER NOT NULL REFERENCES godowns(id),
  qty REAL NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (product_id, godown_id)
);

-- Every sale a salesman records — this is what deducts stock live,
-- and gives the firm a full audit trail of who sold what, when, where.
CREATE TABLE sales (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  firm_id INTEGER NOT NULL REFERENCES firms(id),
  godown_id INTEGER NOT NULL REFERENCES godowns(id),
  staff_id INTEGER NOT NULL REFERENCES staff(id),
  product_id INTEGER NOT NULL REFERENCES products(id),
  qty REAL NOT NULL,
  amount REAL NOT NULL,
  customer_name TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_staff_firm ON staff(firm_id);
CREATE INDEX idx_products_firm ON products(firm_id);
CREATE INDEX idx_godowns_firm ON godowns(firm_id);
CREATE INDEX idx_sales_firm ON sales(firm_id);
CREATE INDEX idx_sales_staff ON sales(staff_id);
CREATE INDEX idx_stock_godown ON stock(godown_id);
