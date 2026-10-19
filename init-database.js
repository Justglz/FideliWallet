const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, 'fideli.db');
const db = new Database(dbPath);

console.log('Mise à jour de la structure de la base de données...\n');

// 1. SUPPRESSION DES ANCIENNES TABLES (Pour repartir propre)
db.exec('DROP TABLE IF EXISTS registrations');
db.exec('DROP TABLE IF EXISTS loyalty_cards');
db.exec('DROP TABLE IF EXISTS customers');
db.exec('DROP TABLE IF EXISTS merchants');

// 2. TABLE MERCHANTS (Ajout de la colonne password !)
db.exec(`
  CREATE TABLE merchants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    password TEXT NOT NULL,
    brand_color TEXT DEFAULT '#000000',
    max_stamps INTEGER DEFAULT 10,
    reward TEXT DEFAULT 'Récompense gratuite',
    notification_message TEXT,
    reply_email TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);
console.log('✅ Table merchants mise à jour (avec password).');

// 3. TABLE CUSTOMERS
db.exec(`
  CREATE TABLE customers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);
console.log('✅ Table customers créée.');

// 4. TABLE LOYALTY_CARDS
db.exec(`
  CREATE TABLE loyalty_cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id TEXT NOT NULL,
    merchant_id TEXT NOT NULL,
    stamps INTEGER DEFAULT 0,
    last_scan DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES customers(id),
    FOREIGN KEY (merchant_id) REFERENCES merchants(id),
    UNIQUE(customer_id, merchant_id)
  )
`);
console.log('✅ Table loyalty_cards créée.');

// 5. NOUVELLE TABLE : REGISTRATIONS (Pour les notifications Push Apple)
db.exec(`
  CREATE TABLE registrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    push_token TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    authentication_token TEXT,
    updated_at INTEGER DEFAULT 0,
    UNIQUE(device_id, serial_number)
  )
`);
console.log('✅ Table registrations créée (indispensable pour les Push).');

// --- INSERTION DE DONNÉES DE TEST ---

db.exec(`
  INSERT INTO merchants (id, name, password, max_stamps, reward) VALUES 
  ('barber-001', 'Le Barbier Cool', 'admin123', 10, 'Coupe gratuite')
`);

db.exec(`
  INSERT INTO customers (id, name, email) VALUES 
  ('cust-test', 'Utilisateur Test', 'test@email.com')
`);

db.exec(`
  INSERT INTO loyalty_cards (customer_id, merchant_id, stamps) VALUES 
  ('cust-test', 'barber-001', 0)
`);

// 6. TABLE STAMP_LOGS
db.exec(`
  CREATE TABLE stamp_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    merchant_id TEXT NOT NULL,
    customer_id TEXT NOT NULL,
    stamps_before INTEGER NOT NULL,
    stamps_after INTEGER NOT NULL,
    action TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);
console.log('✅ Table stamp_logs créée.');

// 7. TABLE SEND_LOGS
db.exec(`
  CREATE TABLE send_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    merchant_id TEXT NOT NULL,
    customer_id TEXT,
    type TEXT NOT NULL,
    status TEXT NOT NULL,
    detail TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);
console.log('✅ Table send_logs créée.');

db.close();
console.log('\n🚀 Base de données initialisée avec la structure complète !');