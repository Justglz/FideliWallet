require('dotenv').config();
const express    = require('express');
const QRCode     = require('qrcode');
const { PKPass } = require('passkit-generator');
const Database   = require('better-sqlite3');
const fs         = require('fs');
const path       = require('path');
const basicAuth  = require('express-basic-auth');
const { execSync }    = require('child_process');
const crypto          = require('crypto');
const { randomUUID }  = crypto;
const apn    = require('apn');
const bcrypt = require('bcrypt');
const cron   = require('node-cron');
const { Resend }      = require('resend');
const { GoogleAuth }  = require('google-auth-library');
const Stripe          = require('stripe');
const stripe          = new Stripe(process.env.STRIPE_SECRET_KEY);

// ==========================================
// --- CONFIG ---
// ==========================================
const PORT      = process.env.PORT      || 3000;
const BASE_URL  = process.env.BASE_URL  || 'http://localhost:3000';
const AUTH_TOKEN = process.env.AUTH_TOKEN;
if (!AUTH_TOKEN) throw new Error('AUTH_TOKEN manquant : definissez-le dans le fichier .env');

const app = express();

// Webhook Stripe — doit être AVANT express.json() pour recevoir le body brut
app.post('/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        console.error('❌ Webhook Stripe invalide:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        const session    = event.data.object;
        const merchantId = session.metadata.merchantId;
        db.prepare('UPDATE merchants SET stripe_customer_id = ?, last_paid_at = ? WHERE id = ?')
          .run(session.customer, Date.now(), merchantId);
        console.log(`✅ Paiement enregistré : ${merchantId}`);
    }

    if (event.type === 'invoice.payment_succeeded') {
        const invoice  = event.data.object;
        const merchant = db.prepare('SELECT id FROM merchants WHERE stripe_customer_id = ?').get(invoice.customer);
        if (merchant) {
            db.prepare('UPDATE merchants SET last_paid_at = ? WHERE id = ?').run(Date.now(), merchant.id);
            console.log(`✅ Renouvellement enregistré : ${merchant.id}`);
        }
    }

    res.json({ received: true });
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Assets des templates (logo, strip…) accessibles publiquement
app.get('/pass-assets/:merchantId/:file', (req, res) => {
    const filePath = path.join(__dirname, 'templates', `${req.params.merchantId}.pass`, req.params.file);
    if (fs.existsSync(filePath)) return res.sendFile(filePath);
    res.status(404).send('Not found');
});

// Logger des appels Apple PassKit
app.use((req, _res, next) => {
    if (req.path.startsWith('/v1/')) {
        console.log(`🌐 ${req.method} ${req.url} | Auth: ${req.get('Authorization') ? 'OUI' : 'NON'}`);
    }
    next();
});

// ==========================================
// --- BASE DE DONNÉES ---
// ==========================================
const DB_PATH = process.env.DB_PATH || './fideli.db';
const db = new Database(DB_PATH);

// Migrations
try { db.exec('ALTER TABLE merchants ADD COLUMN reply_email TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE merchants ADD COLUMN logo_url TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE merchants ADD COLUMN stripe_customer_id TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE merchants ADD COLUMN subscribed_until INTEGER DEFAULT 0'); } catch (e) {}
try { db.exec('ALTER TABLE merchants ADD COLUMN last_paid_at INTEGER'); } catch (e) {}
try { db.exec('ALTER TABLE loyalty_cards ADD COLUMN active INTEGER DEFAULT 1'); } catch (e) {}
try {
    db.exec(`CREATE TABLE stamp_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        merchant_id TEXT NOT NULL,
        customer_id TEXT NOT NULL,
        stamps_before INTEGER NOT NULL,
        stamps_after INTEGER NOT NULL,
        action TEXT NOT NULL,
        source TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
} catch (e) {}

function logStamp(merchantId, customerId, before, after, action, source) {
    try {
        db.prepare('INSERT INTO stamp_logs (merchant_id, customer_id, stamps_before, stamps_after, action, source) VALUES (?, ?, ?, ?, ?, ?)')
          .run(merchantId, customerId, before, after, action, source);
    } catch (e) {}
}

try {
    db.exec(`CREATE TABLE send_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        merchant_id TEXT NOT NULL,
        customer_id TEXT,
        type TEXT NOT NULL,
        status TEXT NOT NULL,
        detail TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
} catch (e) {}

function logSend(merchantId, customerId, type, status, detail = null) {
    try {
        db.prepare('INSERT INTO send_logs (merchant_id, customer_id, type, status, detail) VALUES (?, ?, ?, ?, ?)')
          .run(merchantId, customerId, type, status, detail);
    } catch (e) {}
}

// ==========================================
// --- BACKUP AUTOMATIQUE ---
// ==========================================
const BACKUP_DIR = process.env.BACKUP_DIR || './backups';
if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });

cron.schedule('0 3 * * *', () => {
    try {
        const date = new Date().toISOString().split('T')[0];
        const dest = path.join(BACKUP_DIR, `fideli-${date}.db`);
        fs.copyFileSync(DB_PATH, dest);

        // Garder uniquement les 7 derniers backups
        const files = fs.readdirSync(BACKUP_DIR).filter(f => f.endsWith('.db')).sort();
        if (files.length > 7) {
            files.slice(0, files.length - 7).forEach(f => fs.unlinkSync(path.join(BACKUP_DIR, f)));
        }
        console.log(`✅ Backup DB créé : fideli-${date}.db`);
    } catch (err) {
        console.error('❌ Erreur backup:', err.message);
    }
});

// ==========================================
// --- CERTIFICATS (Signature du Pass) ---
// ==========================================
const certs = {
    wwdr:       fs.readFileSync('./wwdr.pem'),
    signerCert: fs.readFileSync('./certificate.pem'),
    signerKey:  fs.readFileSync('./key.pem'),
};

// ==========================================
// --- RESEND (Emails) ---
// ==========================================
const resend = new Resend(process.env.RESEND_API_KEY);

async function sendEmail(merchant, customer, subject, body) {
    // Remplace les variables dans le sujet et le corps
    const replace = (str) => str
        .replace(/\{nom\}/gi,        customer.name)
        .replace(/\{tampons\}/gi,    String(customer.stamps))
        .replace(/\{recompense\}/gi, merchant.reward)
        .replace(/\{max\}/gi,        String(merchant.max_stamps));

    const htmlBody = `
    <!DOCTYPE html>
    <html lang="fr">
    <head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
    <body style="margin:0; padding:0; background:#f4f7f6; font-family:-apple-system,sans-serif;">
        <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f7f6; padding:30px 0;">
            <tr><td align="center">
                <table width="560" cellpadding="0" cellspacing="0" style="background:white; border-radius:12px; overflow:hidden; box-shadow:0 4px 15px rgba(0,0,0,0.08);">
                    <!-- En-tête -->
                    <tr><td style="background:#000; padding:24px 30px;">
                        <p style="margin:0; color:#d4af37; font-size:1.3em; font-weight:bold;">${merchant.name}</p>
                        <p style="margin:4px 0 0; color:#888; font-size:0.85em;">Carte de fidélité numérique</p>
                    </td></tr>
                    <!-- Corps -->
                    <tr><td style="padding:30px;">
                        <p style="margin:0 0 16px; color:#333; font-size:1em; line-height:1.6;">${replace(body).replace(/\n/g, '<br>')}</p>
                    </td></tr>
                    <!-- Footer -->
                    <tr><td style="padding:16px 30px; background:#f8f9fa; border-top:1px solid #eee;">
                        <p style="margin:0; color:#aaa; font-size:0.78em; text-align:center;">
                            Envoyé via <b>Fideliwallet</b> · <a href="${BASE_URL}" style="color:#aaa;">${BASE_URL}</a>
                        </p>
                    </td></tr>
                </table>
            </td></tr>
        </table>
    </body></html>`;

    return resend.emails.send({
        from:     `${merchant.name} <${process.env.MAIL_FROM || 'noreply@example.com'}>`,
        to:       customer.email,
        reply_to: merchant.reply_email || undefined,
        subject:  replace(subject),
        html:     htmlBody,
    });
}

// ==========================================
// --- APNs (Notifications Push Apple) ---
// ==========================================
const apnProvider = new apn.Provider({
    pfx:        './apns_signer.p12',
    passphrase: process.env.APNS_P12_PASSPHRASE,
    production: true,
});

async function sendPushUpdate(serialNumber) {
    console.log('🔍 Recherche appareils pour serial:', serialNumber);
    const devices = db.prepare('SELECT push_token FROM registrations WHERE serial_number = ?').all(serialNumber);
    if (devices.length === 0) {
        console.log('⚠️ Aucun appareil trouvé pour ce serial.');
        return;
    }

    const notification = new apn.Notification();
    notification.topic  = process.env.APPLE_PASS_TYPE_ID;
    notification.priority = 5;
    notification.expiry = Math.floor(Date.now() / 1000) + 3600;
    notification.payload = {};

    for (const device of devices) {
        try {
            const result = await apnProvider.send(notification, device.push_token);
            if (result.failed?.length > 0) {
                for (const failure of result.failed) {
                    const reason = failure.response?.reason;
                    if (['BadDeviceToken', 'DeviceTokenNotForTopic', 'Unregistered'].includes(reason)) {
                        db.prepare('DELETE FROM registrations WHERE push_token = ?').run(failure.device);
                        console.log(`🗑️ Token invalide supprimé (${reason})`);
                    } else {
                        console.error('❌ APNs échoué:', reason);
                    }
                }
            } else {
                console.log('✅ Push envoyé à:', device.push_token?.substring(0, 12) + '...');
            }
        } catch (err) {
            console.error('❌ Erreur APNs:', err.message);
        }
    }

    db.prepare('UPDATE registrations SET updated_at = ? WHERE serial_number = ?').run(Date.now(), serialNumber);
}

// ==========================================
// --- GOOGLE WALLET ---
// ==========================================
const GW_ISSUER_ID = process.env.GOOGLE_WALLET_ISSUER_ID;
const GW_BASE_URL  = 'https://walletobjects.googleapis.com/walletobjects/v1';

let _gwClientPromise = null;
async function getGWClient() {
    if (!_gwClientPromise) {
        const auth = new GoogleAuth({
            keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS,
            scopes: ['https://www.googleapis.com/auth/wallet_object.issuer'],
        });
        _gwClientPromise = auth.getClient().then(client => {
            client.setMaxListeners(50);
            return client;
        });
    }
    return _gwClientPromise;
}

const gwClassId  = (mid) => `${GW_ISSUER_ID}.${mid}`;
const gwObjectId = (cid, mid) => `${GW_ISSUER_ID}.${mid}_${cid}`;

async function ensureLoyaltyClass(merchant) {
    const client  = await getGWClient();
    const classId = gwClassId(merchant.id);
    const gwLogoFile = fs.existsSync(path.join(__dirname, 'templates', `${merchant.id}.pass`, 'logo-gw.png')) ? 'logo-gw.png' : 'logo.png';
    const logoUrl  = merchant.logo_url || `${BASE_URL}/pass-assets/${merchant.id}/${gwLogoFile}`;
    const stripUrl = `${BASE_URL}/pass-assets/${merchant.id}/strip.png`;
    const body = {
        id:           classId,
        issuerName:   'Fideliwallet',
        programName:  merchant.name,
        reviewStatus: 'UNDER_REVIEW',
        loyaltyPoints: { label: 'Tampons' },
        programLogo: {
            sourceUri:          { uri: logoUrl },
            contentDescription: { defaultValue: { language: 'fr-FR', value: merchant.name } },
        },
        heroImage: {
            sourceUri:          { uri: stripUrl },
            contentDescription: { defaultValue: { language: 'fr-FR', value: merchant.name } },
        },
        hexBackgroundColor: merchant.brand_color || '#000000',
    };
    try {
        await client.request({ url: `${GW_BASE_URL}/loyaltyClass/${encodeURIComponent(classId)}`, method: 'GET' });
        await client.request({ url: `${GW_BASE_URL}/loyaltyClass/${encodeURIComponent(classId)}`, method: 'PUT', data: body });
    } catch (err) {
        if (err.response?.status === 404) {
            await client.request({ url: `${GW_BASE_URL}/loyaltyClass`, method: 'POST', data: body });
        } else { throw err; }
    }
}

async function upsertLoyaltyObject(customerId, merchantId) {
    const client = await getGWClient();
    const data   = db.prepare(`
        SELECT c.name AS customer_name, m.max_stamps, m.reward, lc.stamps
        FROM loyalty_cards lc
        JOIN customers c ON lc.customer_id = c.id
        JOIN merchants  m ON lc.merchant_id = m.id
        WHERE lc.customer_id = ? AND lc.merchant_id = ?
    `).get(customerId, merchantId);
    if (!data) throw new Error('Données introuvables');

    const objectId = gwObjectId(customerId, merchantId);
    const classId  = gwClassId(merchantId);
    const body = {
        id:          objectId,
        classId:     classId,
        state:       'ACTIVE',
        accountId:   data.customer_name,
        accountName: data.customer_name,
        loyaltyPoints: {
            label:   'Tampons',
            balance: { int: data.stamps },
        },
        secondaryLoyaltyPoints: {
            label:   `Objectif`,
            balance: { int: data.max_stamps },
        },
        textModulesData: [
            { id: 'reward', header: 'RÉCOMPENSE', body: data.reward },
        ],
        barcode: {
            type:          'QR_CODE',
            value:         `${BASE_URL}/scan/${customerId}/${merchantId}`,
            alternateText: data.customer_name,
        },
        hexBackgroundColor: '#000000',
    };
    try {
        await client.request({ url: `${GW_BASE_URL}/loyaltyObject/${encodeURIComponent(objectId)}`, method: 'GET' });
        await client.request({ url: `${GW_BASE_URL}/loyaltyObject/${encodeURIComponent(objectId)}`, method: 'PUT', data: body });
    } catch (err) {
        if (err.response?.status === 404) {
            await client.request({ url: `${GW_BASE_URL}/loyaltyObject`, method: 'POST', data: body });
        } else { throw err; }
    }
    return objectId;
}

async function generateGoogleWalletLink(customerId, merchantId) {
    const merchant = db.prepare('SELECT * FROM merchants WHERE id = ?').get(merchantId);
    await ensureLoyaltyClass(merchant);
    const objectId    = await upsertLoyaltyObject(customerId, merchantId);
    const credentials = JSON.parse(fs.readFileSync(process.env.GOOGLE_APPLICATION_CREDENTIALS, 'utf8'));

    const claims = {
        iss: credentials.client_email,
        aud: 'google',
        typ: 'savetowallet',
        iat: Math.floor(Date.now() / 1000),
        payload: { loyaltyObjects: [{ id: objectId }] },
    };

    const header  = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
    const signer  = crypto.createSign('RSA-SHA256');
    signer.update(`${header}.${payload}`);
    const token = `${header}.${payload}.${signer.sign(credentials.private_key, 'base64url')}`;

    return `https://pay.google.com/gp/v/save/${token}`;
}

function syncGoogleWallet(customerId, merchantId) {
    if (!GW_ISSUER_ID) return;
    upsertLoyaltyObject(customerId, merchantId).catch(err =>
        console.error('❌ Google Wallet sync:', err.message)
    );
}

// ==========================================
// --- HELPERS ---
// ==========================================
const rateLimitMap = new Map();
function isRateLimited(ip, maxPerMinute = 10) {
    const now   = Date.now();
    const entry = rateLimitMap.get(ip) || { count: 0, reset: now + 60000 };
    if (now > entry.reset) { entry.count = 0; entry.reset = now + 60000; }
    entry.count++;
    rateLimitMap.set(ip, entry);
    return entry.count > maxPerMinute;
}

function getTemplatePath(merchantId) {
    const specific = path.join(__dirname, 'templates', `${merchantId}.pass`);
    const fallback  = path.join(__dirname, 'templates', 'default.pass');
    return fs.existsSync(specific) ? specific : fallback;
}

async function generateStripBuffer(stamps, maxStamps, bgImagePath, width, height, label) {
    const sharp = require('sharp');
    const bg = await sharp(bgImagePath)
        .resize(width, height, { fit: 'cover' })
        .blur(4)
        .modulate({ brightness: 0.45 })
        .png()
        .toBuffer();

    const cols      = Math.ceil(maxStamps / 2);
    const rows      = 2;
    const margin    = width * 0.08;
    const usable    = width - margin * 2;
    const colSpacing = cols > 1 ? usable / (cols - 1) : 0;
    const r          = Math.min(usable / cols * 0.34, height * 0.19);
    const rowCY      = [height * 0.32, height * 0.72];

    let circles = '';
    for (let i = 0; i < maxStamps; i++) {
        const row = Math.floor(i / cols);
        const col = i % cols;
        const cx  = cols === 1 ? width / 2 : margin + col * colSpacing;
        const cy  = rowCY[row];
        if (i < stamps) {
            circles += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="rgba(255,255,255,0.92)"/>
            <text x="${cx}" y="${cy + r * 0.38}" text-anchor="middle" font-size="${r * 1.3}" fill="#222" font-family="Arial, sans-serif" font-weight="bold">✓</text>`;
        } else {
            circles += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="rgba(255,255,255,0.75)" stroke-width="${Math.max(2.5, r * 0.12)}"/>`;
        }
    }

    const labelSvg = label ? `
        <defs><filter id="blur"><feGaussianBlur stdDeviation="7"/></filter></defs>
        <text x="${width / 2}" y="${height * 0.62}" text-anchor="middle"
              font-size="${height * 1.1}" fill="white" opacity="0.13"
              font-family="Arial Black, Impact, sans-serif" font-weight="900"
              filter="url(#blur)" letter-spacing="${width * 0.04}">${label.toUpperCase()}</text>` : '';

    const svg = Buffer.from(`<svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">${labelSvg}${circles}</svg>`);
    return sharp(bg).composite([{ input: svg }]).png().toBuffer();
}

async function sendPass(res, customerId, merchantId) {
    const data = db.prepare(`
        SELECT c.name AS customer_name, m.name AS merchant_name, m.max_stamps, m.reward, m.notification_message, lc.stamps
        FROM loyalty_cards lc
        JOIN customers c ON lc.customer_id = c.id
        JOIN merchants  m ON lc.merchant_id = m.id
        WHERE lc.customer_id = ? AND lc.merchant_id = ?
    `).get(customerId, merchantId);

    if (!data) return res.status(404).send('Données introuvables.');

    const serial = `${customerId}-${merchantId}`;
    const pass   = await PKPass.from(
        { model: getTemplatePath(merchantId), certificates: certs },
        { serialNumber: serial, webServiceURL: BASE_URL, authenticationToken: AUTH_TOKEN }
    );

    // Mise à jour des champs du recto
    const setField = (fields, key, val) => {
        const f = fields?.find(i => i.key === key);
        if (f) {
            f.value = val;
            f.changeMessage = 'Votre carte a été mise à jour : %@';
        }
    };
    const displayName = data.customer_name.charAt(0).toUpperCase() + data.customer_name.slice(1);
    setField(pass.secondaryFields, 'customer',      displayName);
    setField(pass.secondaryFields, 'reward',        data.reward);
    setField(pass.secondaryFields, 'stamps',        `${data.stamps} / ${data.max_stamps}`);
    setField(pass.auxiliaryFields, 'stamps',        `${data.stamps} / ${data.max_stamps}`);
    setField(pass.headerFields,    'stamps_header', `${data.stamps} / ${data.max_stamps}`);

    // Promo au verso — changeMessage déclenche la bannière iOS
    const msgField = pass.backFields?.find(f => f.key === 'notification');
    if (msgField && data.notification_message) {
        msgField.value         = data.notification_message;
        msgField.changeMessage = '📢 %@';
    }

    // Strip dynamique avec cercles tampons (uniquement si strip-bg.png existe)
    const bgPath = path.join(getTemplatePath(merchantId), 'strip-bg.png');
    if (fs.existsSync(bgPath)) {
        try {
            const label   = data.merchant_name || '';
            const strip1x = await generateStripBuffer(data.stamps, data.max_stamps, bgPath, 375, 144, label);
            const strip2x = await generateStripBuffer(data.stamps, data.max_stamps, bgPath, 750, 288, label);
            pass.addBuffer('strip.png',    strip1x);
            pass.addBuffer('strip@2x.png', strip2x);
        } catch (e) {
            console.error('⚠️ Strip dynamique échoué, fallback statique:', e.message);
        }
    }

    pass.setBarcodes(`${BASE_URL}/scan/${customerId}/${merchantId}`);

    res.set({
        'Content-Type':        'application/vnd.apple.pkpass',
        'Content-Disposition': `attachment; filename="${merchantId}-loyalty.pkpass"`,
        'Cache-Control':       'no-cache, no-store, must-revalidate',
        'Pragma':              'no-cache',
        'Expires':             '0',
        'Last-Modified':       new Date().toUTCString(),
    });
    res.send(pass.getAsBuffer());
}

// ==========================================
// --- AUTHENTIFICATION ---
// ==========================================
if (!process.env.SUPER_ADMIN_PASS) throw new Error('SUPER_ADMIN_PASS manquant : definissez-le dans le fichier .env');
const superAdminAuth = basicAuth({
    users:     { boss: process.env.SUPER_ADMIN_PASS },
    challenge: true,
    realm:     'Fideliwallet SuperAdmin',
});

const merchantAuth = async (req, res, next) => {
    const authHeader = req.get('Authorization');
    if (!authHeader) {
        res.set('WWW-Authenticate', 'Basic realm="Admin Commerçant"');
        return res.status(401).send('Authentification requise');
    }
    const [login, password] = Buffer.from(authHeader.split(' ')[1] || '', 'base64').toString().split(':');
    const merchant = db.prepare('SELECT id, password FROM merchants WHERE id = ?').get(req.params.merchantId);

    if (!merchant || login !== 'admin') {
        res.set('WWW-Authenticate', 'Basic realm="Admin Commerçant"');
        return res.status(401).send('Identifiants invalides');
    }

    let valid = false;
    if (merchant.password.startsWith('$2b$')) {
        // Mot de passe déjà hashé
        valid = await bcrypt.compare(password, merchant.password);
    } else {
        // Mot de passe en clair (legacy) — on vérifie puis on migre vers bcrypt
        valid = password === merchant.password;
        if (valid) {
            const hashed = await bcrypt.hash(password, 10);
            db.prepare('UPDATE merchants SET password = ? WHERE id = ?').run(hashed, merchant.id);
            console.log(`🔐 Mot de passe migré vers bcrypt : ${merchant.id}`);
        }
    }

    if (valid) return next();
    res.set('WWW-Authenticate', 'Basic realm="Admin Commerçant"');
    return res.status(401).send('Identifiants invalides');
};

const appleAuth = (req, res, next) => {
    const token = (req.get('Authorization') || '').replace('ApplePass ', '');
    if (token !== AUTH_TOKEN) return res.sendStatus(401);
    next();
};

// ==========================================
// --- SUPER ADMIN ---
// ==========================================
app.get('/super-admin/dashboard', superAdminAuth, (req, res) => {
    const merchants      = db.prepare('SELECT * FROM merchants').all();
    const totalMerchants = merchants.length;
    const totalCustomers = db.prepare('SELECT COUNT(*) as c FROM customers').get().c;
    const totalStamps    = db.prepare("SELECT COUNT(*) as c FROM stamp_logs WHERE action = 'add'").get().c;
    const now            = Date.now();

    const merchantRows = merchants.map(m => {
        const clients  = db.prepare('SELECT COUNT(*) as c FROM loyalty_cards WHERE merchant_id = ?').get(m.id).c;
        const stamps   = db.prepare("SELECT COUNT(*) as c FROM stamp_logs WHERE merchant_id = ? AND action = 'add'").get(m.id).c;
        const subStatus = m.last_paid_at
            ? `<span style="color:#27ae60;">Payé le ${new Date(m.last_paid_at).toLocaleDateString('fr-FR')}</span>`
            : `<span style="color:#aaa;">—</span>`;
        return `
        <tr style="border-bottom:1px solid #f0f0f0;">
            <td style="padding:12px 14px;"><code style="background:#f5f5f5; padding:2px 6px; border-radius:4px;">${m.id}</code></td>
            <td style="padding:12px 14px; font-weight:bold;">${m.name}</td>
            <td style="padding:12px 14px; text-align:center;">${clients}</td>
            <td style="padding:12px 14px; text-align:center;">${stamps}</td>
            <td style="padding:12px 14px;">${subStatus}</td>
            <td style="padding:12px 14px; white-space:nowrap;">
                <a href="/${m.id}/admin" target="_blank" style="color:#007aff; font-weight:bold; margin-right:10px;">Dashboard ↗</a>
                <form action="/super-admin/delete-merchant/${m.id}" method="POST" style="display:inline;" onsubmit="return confirm('Supprimer ${m.name} ?')">
                    <button style="background:none; color:#e74c3c; border:none; cursor:pointer; font-size:0.9em; margin-left:6px;">🗑️</button>
                </form>
            </td>
        </tr>`;
    }).join('');

    res.send(`<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Super Admin — Fideliwallet</title>
    <style>
        * { box-sizing: border-box; }
        body { margin:0; padding:24px; font-family:-apple-system,sans-serif; background:#f0f2f5; }
        h1 { margin:0 0 20px; font-size:1.5em; }
        .stats { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px; }
        .stat { background:white; border-radius:12px; padding:16px 20px; text-align:center; flex:1; min-width:100px; box-shadow:0 2px 8px rgba(0,0,0,0.06); }
        .stat .val { font-size:1.8em; font-weight:bold; }
        .stat .lbl { font-size:0.78em; color:#888; margin-top:2px; }
        .card { background:white; border-radius:12px; padding:20px; margin-bottom:16px; box-shadow:0 2px 8px rgba(0,0,0,0.06); }
        input, select { padding:8px 10px; border:1px solid #ddd; border-radius:6px; font-size:0.9em; width:100%; }
        .form-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(160px,1fr)); gap:10px; margin-top:12px; }
        .btn-primary { background:#007aff; color:white; border:none; border-radius:8px; padding:10px 18px; font-weight:bold; cursor:pointer; width:100%; margin-top:8px; }
        table { width:100%; border-collapse:collapse; }
        th { padding:10px 14px; background:#f8f9fa; text-align:left; font-size:0.82em; color:#666; font-weight:600; }
        tr:hover td { background:#fafafa; }
    </style>
</head>
<body>
    <h1>🚀 Super Admin — Fideliwallet</h1>

    <div class="stats">
        <div class="stat"><div class="val" style="color:#007aff;">${totalMerchants}</div><div class="lbl">Commerçants</div></div>
        <div class="stat"><div class="val" style="color:#27ae60;">${totalCustomers}</div><div class="lbl">Clients totaux</div></div>
        <div class="stat"><div class="val" style="color:#f39c12;">${totalStamps}</div><div class="lbl">Tampons donnés</div></div>
    </div>

    <div class="card">
        <h2 style="margin:0 0 4px;">➕ Nouveau commerçant</h2>
        <form action="/super-admin/add-merchant" method="POST">
            <div class="form-grid">
                <input type="text"   name="id"         placeholder="ID (ex: barber-02)"   required>
                <input type="text"   name="name"       placeholder="Nom de la boutique"    required>
                <input type="text"   name="password"   placeholder="Mot de passe"          required>
                <input type="number" name="max_stamps" placeholder="Tampons max" value="10" required>
                <input type="text"   name="reward"     placeholder="Récompense"            required>
            </div>
            <button type="submit" class="btn-primary">Créer le commerçant</button>
        </form>
    </div>

    <div class="card" style="padding:0; overflow:hidden;">
        <table>
            <thead>
                <tr>
                    <th>ID</th><th>Nom</th><th style="text-align:center;">Clients</th>
                    <th style="text-align:center;">Tampons</th><th>Abonnement</th><th>Actions</th>
                </tr>
            </thead>
            <tbody>${merchantRows}</tbody>
        </table>
    </div>
</body></html>`);
});


app.post('/super-admin/delete-merchant/:merchantId', superAdminAuth, (req, res) => {
    const { merchantId } = req.params;
    db.prepare('DELETE FROM loyalty_cards WHERE merchant_id = ?').run(merchantId);
    db.prepare('DELETE FROM stamp_logs WHERE merchant_id = ?').run(merchantId);
    db.prepare('DELETE FROM send_logs WHERE merchant_id = ?').run(merchantId);
    db.prepare('DELETE FROM registrations WHERE serial_number LIKE ?').run(`%-${merchantId}`);
    db.prepare('DELETE FROM merchants WHERE id = ?').run(merchantId);
    res.redirect('/super-admin/dashboard');
});

app.post('/super-admin/add-merchant', superAdminAuth, async (req, res) => {
    const { id, name, password, max_stamps, reward } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.prepare('INSERT INTO merchants (id, name, password, max_stamps, reward) VALUES (?, ?, ?, ?, ?)').run(id, name, hashedPassword, max_stamps, reward);
        const newPath    = path.join(__dirname, 'templates', `${id}.pass`);
        const sourcePath = path.join(__dirname, 'templates', 'barber-001.pass');
        if (!fs.existsSync(newPath) && fs.existsSync(sourcePath)) execSync(`cp -r "${sourcePath}" "${newPath}"`);
        res.redirect('/super-admin/dashboard');
    } catch (err) {
        res.status(500).send('Erreur : ' + err.message);
    }
});

// ==========================================
// --- DASHBOARD COMMERÇANT ---
// ==========================================
app.get('/:merchantId/subscribe', merchantAuth, async (req, res) => {
    const { merchantId } = req.params;
    const merchant = db.prepare('SELECT * FROM merchants WHERE id = ?').get(merchantId);
    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
            mode: 'subscription',
            success_url: `${BASE_URL}/${merchantId}/admin`,
            cancel_url:  `${BASE_URL}/${merchantId}/admin`,
            metadata:    { merchantId },
            customer_email: merchant.reply_email || undefined,
        });
        res.redirect(session.url);
    } catch (err) {
        console.error('❌ Stripe:', err.message);
        res.status(500).send('Erreur Stripe : ' + err.message);
    }
});

app.get('/:merchantId/admin', merchantAuth, (req, res) => {
    const { merchantId } = req.params;
    const merchant  = db.prepare('SELECT * FROM merchants WHERE id = ?').get(merchantId);
    if (!merchant) return res.status(404).send('Commerce introuvable.');

    const customers = db.prepare(`
        SELECT c.id, c.name, c.email, lc.stamps, lc.last_scan
        FROM customers c
        JOIN loyalty_cards lc ON c.id = lc.customer_id
        WHERE lc.merchant_id = ? AND lc.active = 1
        ORDER BY c.name ASC
    `).all(merchantId);

    // Statistiques
    const monthStart = new Date(); monthStart.setDate(1); monthStart.setHours(0,0,0,0);
    const stats = {
        totalClients:   customers.length,
        newThisMonth:   db.prepare(`SELECT COUNT(*) as c FROM loyalty_cards WHERE merchant_id = ? AND active = 1 AND created_at >= ?`).get(merchantId, monthStart.toISOString()).c,
        stampsThisMonth:db.prepare(`SELECT COUNT(*) as c FROM stamp_logs WHERE merchant_id = ? AND created_at >= ? AND action = 'add'`).get(merchantId, monthStart.toISOString()).c,
        rewardsTotal:   db.prepare(`SELECT COUNT(*) as c FROM stamp_logs WHERE merchant_id = ? AND action = 'reward'`).get(merchantId).c,
        activeThisMonth:db.prepare(`SELECT COUNT(*) as c FROM loyalty_cards WHERE merchant_id = ? AND active = 1 AND last_scan >= ?`).get(merchantId, monthStart.toISOString()).c,
    };

    // Historique des tampons (pour l'onglet)
    const stampHistory = db.prepare(`
        SELECT sl.*, c.name AS customer_name, c.email
        FROM stamp_logs sl
        JOIN customers c ON sl.customer_id = c.id
        WHERE sl.merchant_id = ?
        ORDER BY sl.created_at DESC LIMIT 200
    `).all(merchantId);

    const formatDate = (d) => {
        if (!d) return '<span style="color:#bbb;">Jamais</span>';
        return new Date(d).toLocaleDateString('fr-FR', { day:'2-digit', month:'2-digit', year:'numeric' });
    };
    const formatDateTime = (d) => new Date(d).toLocaleString('fr-FR', { day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' });

    res.send(`<!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>${merchant.name} — Admin</title>
        <style>
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { font-family: -apple-system, sans-serif; background: #f4f7f6; padding: 12px; font-size: 13px; }
            .card { background: white; border-radius: 12px; box-shadow: 0 3px 10px rgba(0,0,0,0.06); padding: 14px 16px; margin-bottom: 12px; }
            h1 { font-size: 1.3em; }
            h2 { font-size: 1em; margin-bottom: 10px; color: #333; }
            input[type=text], input[type=email], input[type=number], input[type=password] { padding: 7px 9px; border: 1px solid #ddd; border-radius: 6px; font-size: 0.9em; }
            button.btn { padding: 7px 13px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; font-size: 0.88em; }
            .btn-green  { background: #28a745; color: white; }
            .btn-red    { background: none; color: #dc3545; padding: 0; font-size: 0.9em; }
            .table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
            table { width: 100%; border-collapse: collapse; min-width: 520px; }
            th { padding: 8px 9px; background: #f8f9fa; text-align: left; font-size: 0.82em; color: #666; font-weight: 600; white-space: nowrap; }
            td { padding: 8px 9px; border-bottom: 1px solid #f0f0f0; font-size: 0.88em; }
            .email-cell { max-width: 140px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #888; }
            tr.hidden-row { display: none; }
            .notif-bar { position: sticky; bottom: 10px; background: white; border: 2px solid #5856d6; border-radius: 10px; padding: 10px 14px; box-shadow: 0 6px 20px rgba(88,86,214,0.2); display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
            #filterActive { display:none; font-size:0.82em; color:#5856d6; margin-top:8px; }
            .filters-grid { display: flex; gap: 8px; flex-wrap: wrap; align-items: flex-end; }
            .filter-group label { font-size: 0.75em; color: #888; display: block; margin-bottom: 3px; }
            /* Onglets */
            .tabs { display: flex; gap: 4px; background: white; border-radius: 12px; padding: 6px; box-shadow: 0 3px 10px rgba(0,0,0,0.06); margin-bottom: 12px; }
            .tab-btn { flex: 1; padding: 9px 6px; border: none; border-radius: 8px; cursor: pointer; font-size: 0.88em; font-weight: 600; background: none; color: #888; transition: all 0.15s; }
            .tab-btn.active { background: #007aff; color: white; }
            .tab-panel { display: none; }
            .tab-panel.active { display: block; }
            select { padding: 7px 9px; border: 1px solid #ddd; border-radius: 6px; font-size: 0.88em; background: white; }
        </style>
    </head>
    <body>

    <!-- EN-TÊTE -->
    <div class="card" style="display:flex; justify-content:space-between; align-items:center; padding:20px 25px; flex-wrap:wrap; gap:10px;">
        <h1>${merchant.name}</h1>
        <a href="/${merchantId}/qrcode" style="text-decoration:none; background:#007aff; color:white; padding:8px 13px; border-radius:8px; font-weight:bold; font-size:0.85em;">🖨️ QR Code</a>
    </div>

    <!-- ONGLETS -->
    <div class="tabs">
        <button class="tab-btn active" onclick="showTab('clients', this)">👥 Clients</button>
        <button class="tab-btn" onclick="showTab('stats', this)">📊 Statistiques</button>
        <button class="tab-btn" onclick="showTab('settings', this)">⚙️ Réglages</button>
    </div>

    <!-- ONGLET CLIENTS -->
    <div id="tab-clients" class="tab-panel active">

        <!-- FILTRES -->
        <div class="card">
            <h2>🔍 Filtrer les clients</h2>
            <div class="filters-grid">
                <div class="filter-group">
                    <label>Recherche</label>
                    <input type="text" id="fSearch" placeholder="Nom ou email…" style="width:140px;" oninput="applyFilters()">
                </div>
                <div class="filter-group">
                    <label>Tampons min</label>
                    <input type="number" id="fStampsMin" min="0" max="${merchant.max_stamps}" value="0" style="width:62px;" oninput="applyFilters()">
                </div>
                <div class="filter-group">
                    <label>Tampons max</label>
                    <input type="number" id="fStampsMax" min="0" max="${merchant.max_stamps}" value="${merchant.max_stamps}" style="width:62px;" oninput="applyFilters()">
                </div>
                <div class="filter-group">
                    <label>Dernier scan</label>
                    <select id="fScan" onchange="applyFilters()">
                        <option value="tous">Tous</option>
                        <option value="jamais">Jamais scanné</option>
                        <option value="inactif30">Inactif +30 jours</option>
                        <option value="inactif7">Inactif +7 jours</option>
                        <option value="actif7">Actif ces 7 jours</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label>Trier par</label>
                    <select id="fSort" onchange="applySort()">
                        <option value="name">Nom A→Z</option>
                        <option value="stamps_desc">Tampons ↓</option>
                        <option value="stamps_asc">Tampons ↑</option>
                        <option value="scan_desc">Scan récent</option>
                        <option value="scan_asc">Scan ancien</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label>&nbsp;</label>
                    <button class="btn" onclick="resetFilters()" style="background:#eee; color:#555;">↺ Reset</button>
                </div>
            </div>
            <p id="filterActive"><span id="filterCount"></span> client(s) correspondent</p>
        </div>

        <!-- LISTE DES CLIENTS -->
        <div class="card" style="padding-bottom:180px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; flex-wrap:wrap; gap:8px;">
                <div style="display:flex; align-items:center; gap:8px;">
                    <h2>👥 Clients <span id="totalCount" style="font-weight:normal; color:#888;">(${customers.length})</span></h2>
                    <button type="button" class="btn" onclick="toggleSelectAll()" id="selectAllBtn"
                        style="background:#eee; color:#555; padding:4px 10px;">
                        Tout sélectionner
                    </button>
                </div>
                <form action="/${merchantId}/admin/add-customer" method="POST" style="display:flex; gap:6px; flex-wrap:wrap;">
                    <input type="text"  name="name"  placeholder="Nom" required style="width:120px;">
                    <input type="email" name="email" placeholder="Email" required style="width:160px;">
                    <button type="submit" class="btn btn-green">+ Ajouter</button>
                </form>
            </div>

            <div class="table-wrap">
            <table id="customerTable">
                <thead>
                    <tr>
                        <th style="width:36px;"></th>
                        <th>Nom</th>
                        <th>Email</th>
                        <th>Tampons</th>
                        <th>Dernier scan</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${customers.map(c => {
                        const daysSince = c.last_scan
                            ? Math.floor((Date.now() - new Date(c.last_scan).getTime()) / 86400000)
                            : 9999;
                        const stampPct = Math.round((c.stamps / merchant.max_stamps) * 100);
                        return `
                    <tr data-name="${c.name.toLowerCase()}" data-email="${c.email.toLowerCase()}"
                        data-stamps="${c.stamps}" data-days="${daysSince}" data-id="${c.id}">
                        <td style="text-align:center;">
                            <input type="checkbox" class="row-check" data-id="${c.id}">
                        </td>
                        <td><b>${c.name}</b></td>
                        <td class="email-cell">${c.email}</td>
                        <td>
                            <div style="display:flex; align-items:center; gap:5px;">
                                <span style="font-weight:bold; white-space:nowrap;">${c.stamps}/${merchant.max_stamps}</span>
                                <div style="flex:1; height:5px; background:#eee; border-radius:3px; min-width:35px;">
                                    <div style="width:${stampPct}%; height:100%; background:${stampPct >= 90 ? '#e74c3c' : stampPct >= 50 ? '#f39c12' : '#27ae60'}; border-radius:3px;"></div>
                                </div>
                            </div>
                        </td>
                        <td style="white-space:nowrap; color:${daysSince >= 30 ? '#e74c3c' : daysSince <= 7 ? '#27ae60' : '#555'};">
                            ${formatDate(c.last_scan)}
                        </td>
                        <td style="white-space:nowrap;">
                            <form action="/${merchantId}/admin/stamp/${c.id}" method="POST" style="display:inline;">
                                <button type="submit" class="btn btn-green" style="padding:4px 8px;">+1</button>
                            </form>
                            <form action="/${merchantId}/admin/remove-customer/${c.id}" method="POST" style="display:inline;" onsubmit="return confirm('Retirer ${c.name} ?')">
                                <button type="submit" class="btn btn-red">🗑️</button>
                            </form>
                        </td>
                    </tr>`;
                    }).join('')}
                </tbody>
            </table>
            </div>
        </div>

        <!-- BARRE EMAIL (sticky) -->
        <form id="emailForm" action="/${merchantId}/admin/send-email" method="POST" onsubmit="return injectIds('hiddenEmailIds')">
            <div class="notif-bar" style="border-color:#27ae60; box-shadow:0 6px 20px rgba(39,174,96,0.15); margin-bottom:8px;">
                <span style="font-weight:bold; color:#27ae60; white-space:nowrap;">📧 Email</span>
                <span id="emailCount" style="font-size:0.85em; color:#888; white-space:nowrap;">— aucun sélectionné</span>
                <input type="text" name="subject" placeholder="Sujet…" required style="width:150px; border-color:#b7e4c7; flex-shrink:0;">
                <textarea name="body" placeholder="Votre message…" required
                    style="flex:1; min-width:120px; padding:7px 9px; border:1px solid #b7e4c7; border-radius:6px; font-size:0.88em; resize:none; height:36px; font-family:inherit;"></textarea>
                <button type="submit" class="btn" style="background:#27ae60; color:white; white-space:nowrap;">Envoyer 📧</button>
            </div>
            <div id="hiddenEmailIds"></div>
        </form>

        <!-- BARRE PUSH (sticky) -->
        <form id="notifForm" action="/${merchantId}/admin/notify-group" method="POST" onsubmit="return injectIds('hiddenIds')">
            <div class="notif-bar">
                <span style="font-weight:bold; color:#5856d6; white-space:nowrap;">📢 Push</span>
                <span id="notifCount" style="font-size:0.85em; color:#888; white-space:nowrap;">— aucun sélectionné</span>
                <input type="text" name="message" placeholder="Message push…" required style="flex:1; min-width:200px; border-color:#c5d0f0;">
                <button type="submit" class="btn" style="background:#5856d6; color:white; white-space:nowrap;">Envoyer 🔔</button>
            </div>
            <div id="hiddenIds"></div>
        </form>

    </div><!-- /tab-clients -->

    <!-- ONGLET STATISTIQUES + HISTORIQUE -->
    <div id="tab-stats" class="tab-panel">
        <div class="card">
            <h2 style="margin-bottom:12px;">📊 Ce mois-ci</h2>
            <div style="display:flex; gap:10px; flex-wrap:wrap;">
                <div style="flex:1; min-width:100px; background:#f0f4ff; border-radius:10px; padding:12px; text-align:center;">
                    <div style="font-size:1.8em; font-weight:bold; color:#5856d6;">${stats.totalClients}</div>
                    <div style="font-size:0.78em; color:#888; margin-top:2px;">Clients total</div>
                </div>
                <div style="flex:1; min-width:100px; background:#f0fff4; border-radius:10px; padding:12px; text-align:center;">
                    <div style="font-size:1.8em; font-weight:bold; color:#27ae60;">+${stats.newThisMonth}</div>
                    <div style="font-size:0.78em; color:#888; margin-top:2px;">Nouveaux</div>
                </div>
                <div style="flex:1; min-width:100px; background:#fff8f0; border-radius:10px; padding:12px; text-align:center;">
                    <div style="font-size:1.8em; font-weight:bold; color:#f39c12;">${stats.stampsThisMonth}</div>
                    <div style="font-size:0.78em; color:#888; margin-top:2px;">Tampons donnés</div>
                </div>
                <div style="flex:1; min-width:100px; background:#fff0f0; border-radius:10px; padding:12px; text-align:center;">
                    <div style="font-size:1.8em; font-weight:bold; color:#e74c3c;">${stats.rewardsTotal}</div>
                    <div style="font-size:0.78em; color:#888; margin-top:2px;">Récompenses</div>
                </div>
                <div style="flex:1; min-width:100px; background:#f5f5f5; border-radius:10px; padding:12px; text-align:center;">
                    <div style="font-size:1.8em; font-weight:bold; color:#555;">${stats.activeThisMonth}</div>
                    <div style="font-size:0.78em; color:#888; margin-top:2px;">Actifs ce mois</div>
                </div>
            </div>
            <p style="margin-top:12px; font-size:0.75em; color:#bbb;">Un client est considéré actif s'il a été scanné depuis le 1er du mois.</p>
        </div>

        <div class="card">
            <h2 style="margin-bottom:12px;">📋 Historique des tampons</h2>
            ${stampHistory.length === 0 ? '<p style="color:#aaa; font-size:0.9em;">Aucun événement pour l\'instant.</p>' : `
            <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Client</th>
                        <th>Action</th>
                        <th>Avant</th>
                        <th>Après</th>
                        <th>Source</th>
                    </tr>
                </thead>
                <tbody>
                    ${stampHistory.map(h => `
                    <tr>
                        <td style="white-space:nowrap; color:#888;">${formatDateTime(h.created_at)}</td>
                        <td><b>${h.customer_name}</b><br><span style="font-size:0.78em; color:#aaa;">${h.email}</span></td>
                        <td>
                            ${h.action === 'add'    ? '<span style="color:#27ae60; font-weight:bold;">+1 tampon</span>' :
                              h.action === 'reward' ? '<span style="color:#e74c3c; font-weight:bold;">Récompense</span>' :
                              h.action}
                        </td>
                        <td style="text-align:center;">${h.stamps_before}</td>
                        <td style="text-align:center; font-weight:bold;">${h.stamps_after}</td>
                        <td style="font-size:0.82em; color:#888;">${h.source}</td>
                    </tr>`).join('')}
                </tbody>
            </table>
            <form action="/${merchantId}/admin/clear-history" method="POST" style="margin-top:12px;" onsubmit="return confirm('Effacer tout l\'historique des scans ?')">
                <button type="submit" style="background:none; border:1px solid #e74c3c; color:#e74c3c; padding:7px 14px; border-radius:8px; cursor:pointer; font-size:0.82em;">🗑️ Effacer l'historique</button>
            </form>
            </div>`}
        </div>
    </div><!-- /tab-stats -->

    <!-- ONGLET RÉGLAGES -->
    <div id="tab-settings" class="tab-panel">

        <!-- Infos du commerce -->
        <div class="card" style="border-left:3px solid #007aff;">
            <h2 style="margin-bottom:12px;">🏪 Informations du commerce</h2>
            <div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
                <span style="font-size:0.9em; color:#555;"><b>${merchant.name}</b> — ${merchant.max_stamps} tampons — ${merchant.reward}</span>
                <button type="button" class="btn" style="background:#eee; color:#555; padding:4px 10px;"
                    onclick="document.getElementById('infoForm').style.display='flex'; this.style.display='none';">
                    Modifier
                </button>
            </div>
            <form id="infoForm" action="/${merchantId}/admin/update-info" method="POST"
                style="display:none; gap:8px; align-items:center; margin-top:10px; flex-wrap:wrap;">
                <input type="text"   name="name"       value="${merchant.name}"       placeholder="Nom"         required style="width:160px;">
                <input type="text"   name="reward"     value="${merchant.reward}"     placeholder="Récompense"  required style="width:180px;">
                <input type="number" name="max_stamps" value="${merchant.max_stamps}" placeholder="Tampons max" required style="width:90px;" min="1">
                <button type="submit" class="btn" style="background:#007aff; color:white;">Enregistrer</button>
            </form>
        </div>

        <!-- Mot de passe -->
        <div class="card" style="border-left:3px solid #e74c3c;">
            <h2 style="margin-bottom:12px;">🔐 Mot de passe admin</h2>
            <div style="display:flex; align-items:center; gap:12px;">
                <span style="font-size:0.9em; color:#555;">••••••••</span>
                <button type="button" class="btn" style="background:#eee; color:#555; padding:4px 10px;"
                    onclick="document.getElementById('pwdForm').style.display='flex'; this.style.display='none';">
                    Changer
                </button>
            </div>
            <form id="pwdForm" action="/${merchantId}/admin/change-password" method="POST"
                style="display:none; gap:8px; align-items:center; margin-top:10px; flex-wrap:wrap;">
                <input type="password" name="new_password"     placeholder="Nouveau mot de passe" required style="width:190px;">
                <input type="password" name="confirm_password" placeholder="Confirmer"            required style="width:160px;">
                <button type="submit" class="btn" style="background:#e74c3c; color:white;">Enregistrer</button>
            </form>
        </div>

        <!-- Email de réponse -->
        <div class="card" style="border-left:3px solid #27ae60;">
            <h2 style="margin-bottom:12px;">📧 Email de réponse</h2>
            ${merchant.reply_email ? `
            <div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
                <span style="font-size:0.9em; color:#555;">Reply-to : <b>${merchant.reply_email}</b></span>
                <button type="button" class="btn" style="background:#eee; color:#555; padding:4px 10px;"
                    onclick="document.getElementById('replyEmailForm').style.display='flex'; this.style.display='none';">
                    Changer
                </button>
            </div>
            <form id="replyEmailForm" action="/${merchantId}/admin/settings" method="POST"
                style="display:none; gap:8px; align-items:center; margin-top:10px; flex-wrap:wrap;">
                <input type="email" name="reply_email" placeholder="Nouvel email de réponse" required style="width:240px;">
                <button type="submit" class="btn" style="background:#27ae60; color:white;">Enregistrer</button>
            </form>
            ` : `
            <form action="/${merchantId}/admin/settings" method="POST" style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                <input type="email" name="reply_email" placeholder="contact@votreboutique.com" required style="width:240px;">
                <button type="submit" class="btn" style="background:#27ae60; color:white;">Enregistrer</button>
            </form>
            <p style="margin-top:8px; font-size:0.78em; color:#aaa;">Les réponses des clients arriveront à cette adresse.</p>
            `}
        </div>

        <!-- Abonnement -->
        <div class="card" style="border-left:3px solid #f39c12;">
            <h3 style="margin-bottom:8px;">💳 Abonnement</h3>
            ${merchant.last_paid_at
                ? `<p style="color:#27ae60; font-weight:bold; margin:0 0 8px;">✅ Actif — dernier paiement le ${new Date(merchant.last_paid_at).toLocaleDateString('fr-FR')}</p>`
                : `<p style="color:#e74c3c; margin:0 0 8px;">Aucun paiement enregistré.</p>`
            }
            <a href="/${merchantId}/subscribe" style="display:inline-block; background:#f39c12; color:white; padding:10px 20px; border-radius:10px; text-decoration:none; font-weight:bold;">
                ${merchant.last_paid_at ? '🔄 Gérer mon abonnement' : '💳 S\'abonner — 75€/mois'}
            </a>
        </div>

    </div><!-- /tab-settings -->

    <script>
        // --- ONGLETS ---
        function showTab(name, btn) {
            document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.getElementById('tab-' + name).classList.add('active');
            btn.classList.add('active');
        }

        // --- CLIENTS ---
        const rows = () => Array.from(document.querySelectorAll('#customerTable tbody tr'));

        function visibleRows() {
            return rows().filter(r => !r.classList.contains('hidden-row'));
        }

        function applyFilters() {
            const search    = document.getElementById('fSearch').value.toLowerCase().trim();
            const stampsMin = parseInt(document.getElementById('fStampsMin').value) || 0;
            const stampsMax = parseInt(document.getElementById('fStampsMax').value) ?? ${merchant.max_stamps};
            const scan      = document.getElementById('fScan').value;

            rows().forEach(r => {
                const name   = r.dataset.name;
                const email  = r.dataset.email;
                const stamps = parseInt(r.dataset.stamps);
                const days   = parseInt(r.dataset.days);

                const matchSearch = !search || name.includes(search) || email.includes(search);
                const matchStamps = stamps >= stampsMin && stamps <= stampsMax;
                const matchScan   =
                    scan === 'tous'      ? true :
                    scan === 'jamais'    ? days === 9999 :
                    scan === 'inactif30' ? days >= 30 :
                    scan === 'inactif7'  ? days >= 7 :
                    scan === 'actif7'    ? days <= 7 && days !== 9999 : true;

                const visible = matchSearch && matchStamps && matchScan;
                r.classList.toggle('hidden-row', !visible);
                if (!visible) {
                    const cb = r.querySelector('.row-check');
                    if (cb) cb.checked = false;
                }
            });

            updateCounts(isAnyFilterActive());
        }

        function applySort() {
            const key   = document.getElementById('fSort').value;
            const tbody = document.querySelector('#customerTable tbody');
            const sorted = rows().sort((a, b) => {
                if (key === 'name')        return a.dataset.name.localeCompare(b.dataset.name);
                if (key === 'stamps_desc') return parseInt(b.dataset.stamps) - parseInt(a.dataset.stamps);
                if (key === 'stamps_asc')  return parseInt(a.dataset.stamps) - parseInt(b.dataset.stamps);
                if (key === 'scan_desc')   return parseInt(a.dataset.days)   - parseInt(b.dataset.days);
                if (key === 'scan_asc')    return parseInt(b.dataset.days)   - parseInt(a.dataset.days);
                return 0;
            });
            sorted.forEach(r => tbody.appendChild(r));
        }

        function checkedRows() {
            return rows().filter(r => r.querySelector('.row-check')?.checked);
        }

        function updateCounts(anyFilter) {
            const visible = visibleRows().length;
            const checked = checkedRows().length;
            const total   = rows().length;
            document.getElementById('totalCount').textContent = '(' + total + ')';

            const filterActive = document.getElementById('filterActive');
            if (anyFilter) {
                filterActive.style.display = 'block';
                document.getElementById('filterCount').textContent = visible;
            } else {
                filterActive.style.display = 'none';
            }

            const label = checked > 0
                ? '— ' + checked + ' client' + (checked > 1 ? 's' : '') + ' sélectionné' + (checked > 1 ? 's' : '')
                : '— aucun sélectionné';

            const notifCount = document.getElementById('notifCount');
            notifCount.textContent = label;
            notifCount.style.color = checked > 0 ? '#5856d6' : '#aaa';

            const emailCount = document.getElementById('emailCount');
            emailCount.textContent = label;
            emailCount.style.color = checked > 0 ? '#27ae60' : '#aaa';

            const allVisibleChecked = visible > 0 && visibleRows().every(r => r.querySelector('.row-check')?.checked);
            document.getElementById('selectAllBtn').textContent = allVisibleChecked
                ? 'Tout désélectionner'
                : 'Tout sélectionner';
        }

        function toggleSelectAll() {
            const allChecked = visibleRows().every(r => r.querySelector('.row-check')?.checked);
            visibleRows().forEach(r => {
                const cb = r.querySelector('.row-check');
                if (cb) cb.checked = !allChecked;
            });
            updateCounts(isAnyFilterActive());
        }

        function isAnyFilterActive() {
            return document.getElementById('fSearch').value.trim() !== ''
                || parseInt(document.getElementById('fStampsMin').value) > 0
                || parseInt(document.getElementById('fStampsMax').value) < ${merchant.max_stamps}
                || document.getElementById('fScan').value !== 'tous';
        }

        function resetFilters() {
            document.getElementById('fSearch').value    = '';
            document.getElementById('fStampsMin').value = 0;
            document.getElementById('fStampsMax').value = ${merchant.max_stamps};
            document.getElementById('fScan').value      = 'tous';
            applyFilters();
        }

        function injectIds(containerId) {
            const checked = checkedRows();
            if (checked.length === 0) {
                alert('Aucun client sélectionné — cochez des clients dans la liste.');
                return false;
            }
            const container = document.getElementById(containerId);
            container.innerHTML = '';
            checked.forEach(r => {
                const input = document.createElement('input');
                input.type  = 'hidden';
                input.name  = 'customerIds';
                input.value = r.dataset.id;
                container.appendChild(input);
            });
            return true;
        }

        document.getElementById('customerTable').addEventListener('change', () => {
            updateCounts(isAnyFilterActive());
        });

        updateCounts(false);
    </script>
    </body></html>`);
});

app.post('/:merchantId/admin/add-customer', merchantAuth, (req, res) => {
    const { merchantId } = req.params;
    const { name, email } = req.body;
    const customerId = 'cust-' + randomUUID();
    try {
        db.prepare('INSERT INTO customers (id, name, email) VALUES (?, ?, ?)').run(customerId, name, email);
        db.prepare('INSERT INTO loyalty_cards (customer_id, merchant_id, stamps) VALUES (?, ?, 0)').run(customerId, merchantId);
        res.redirect(`/${merchantId}/admin`);
    } catch (err) {
        res.status(500).send('Erreur : ' + err.message);
    }
});

app.post('/:merchantId/admin/stamp/:customerId', merchantAuth, async (req, res) => {
    const { merchantId, customerId } = req.params;
    const data = db.prepare(`
        SELECT lc.stamps, m.max_stamps
        FROM loyalty_cards lc
        JOIN merchants m ON lc.merchant_id = m.id
        WHERE lc.customer_id = ? AND lc.merchant_id = ?
    `).get(customerId, merchantId);
    if (!data) return res.status(404).send('Client introuvable.');

    const rewardUnlocked = (data.stamps + 1) >= data.max_stamps;
    const nouveaux = rewardUnlocked ? 0 : data.stamps + 1;
    db.prepare('UPDATE loyalty_cards SET stamps = ?, last_scan = CURRENT_TIMESTAMP WHERE customer_id = ? AND merchant_id = ?').run(nouveaux, customerId, merchantId);
    logStamp(merchantId, customerId, data.stamps, nouveaux, rewardUnlocked ? 'reward' : 'add', 'admin');
    await sendPushUpdate(`${customerId}-${merchantId}`);
    syncGoogleWallet(customerId, merchantId);
    res.redirect(`/${merchantId}/admin`);
});

app.post('/:merchantId/admin/send-email', merchantAuth, async (req, res) => {
    const { merchantId } = req.params;
    const { subject, body, customerIds } = req.body;
    if (!subject || !body || !customerIds) return res.redirect(`/${merchantId}/admin`);

    const merchant = db.prepare('SELECT * FROM merchants WHERE id = ?').get(merchantId);
    const ids = Array.isArray(customerIds) ? customerIds : [customerIds];

    let sent = 0, errors = 0;
    for (const customerId of ids) {
        const customer = db.prepare(`
            SELECT c.name, c.email, lc.stamps
            FROM customers c JOIN loyalty_cards lc ON c.id = lc.customer_id
            WHERE c.id = ? AND lc.merchant_id = ?
        `).get(customerId, merchantId);
        if (!customer) continue;
        try {
            await sendEmail(merchant, customer, subject, body);
            logSend(merchantId, customerId, 'email', 'success', subject);
            sent++;
        } catch (err) {
            logSend(merchantId, customerId, 'email', 'error', err.message);
            console.error('❌ Email échoué pour', customer.email, ':', err.message);
            errors++;
        }
    }
    console.log(`📧 Emails envoyés : ${sent} ok, ${errors} erreurs`);
    res.redirect(`/${merchantId}/admin`);
});

app.post('/:merchantId/admin/settings', merchantAuth, (req, res) => {
    const { merchantId } = req.params;
    const { reply_email } = req.body;
    db.prepare('UPDATE merchants SET reply_email = ? WHERE id = ?').run(reply_email || null, merchantId);
    res.redirect(`/${merchantId}/admin`);
});

app.post('/:merchantId/admin/change-password', merchantAuth, async (req, res) => {
    const { merchantId } = req.params;
    const { new_password, confirm_password } = req.body;
    if (!new_password || new_password !== confirm_password)
        return res.status(400).send('Mots de passe invalides ou différents.');
    const hashed = await bcrypt.hash(new_password, 10);
    db.prepare('UPDATE merchants SET password = ? WHERE id = ?').run(hashed, merchantId);
    console.log(`🔐 Mot de passe changé pour ${merchantId}`);
    res.redirect(`/${merchantId}/admin`);
});

app.post('/:merchantId/admin/notify-group', merchantAuth, async (req, res) => {
    const { merchantId } = req.params;
    const { message, customerIds } = req.body;
    if (!message || !customerIds) return res.redirect(`/${merchantId}/admin`);

    const ids = Array.isArray(customerIds) ? customerIds : [customerIds];
    for (const customerId of ids) {
        try {
            await sendPushUpdate(`${customerId}-${merchantId}`);
            logSend(merchantId, customerId, 'push', 'success', message);
        } catch (err) {
            logSend(merchantId, customerId, 'push', 'error', err.message);
        }
    }
    db.prepare('UPDATE merchants SET notification_message = ? WHERE id = ?').run(message, merchantId);
    res.redirect(`/${merchantId}/admin`);
});

app.post('/:merchantId/admin/update-info', merchantAuth, async (req, res) => {
    const { merchantId } = req.params;
    const { name, reward, max_stamps } = req.body;
    const newMax = parseInt(max_stamps);

    const old = db.prepare('SELECT max_stamps FROM merchants WHERE id = ?').get(merchantId);
    db.prepare('UPDATE merchants SET name = ?, reward = ?, max_stamps = ? WHERE id = ?')
      .run(name, reward, newMax, merchantId);

    // Si max_stamps a changé, on cap les tampons et on met à jour tous les passes
    if (old && old.max_stamps !== newMax) {
        const cards = db.prepare('SELECT customer_id, stamps FROM loyalty_cards WHERE merchant_id = ?').all(merchantId);
        for (const card of cards) {
            const capped = Math.min(card.stamps, newMax - 1);
            if (capped !== card.stamps) {
                db.prepare('UPDATE loyalty_cards SET stamps = ? WHERE customer_id = ? AND merchant_id = ?')
                  .run(capped, card.customer_id, merchantId);
            }
            try { await sendPushUpdate(`${card.customer_id}-${merchantId}`); } catch (e) {}
            syncGoogleWallet(card.customer_id, merchantId);
        }
    }

    res.redirect(`/${merchantId}/admin`);
});

app.post('/:merchantId/admin/clear-history', merchantAuth, (req, res) => {
    const { merchantId } = req.params;
    db.prepare('DELETE FROM stamp_logs WHERE merchant_id = ?').run(merchantId);
    res.redirect(`/${merchantId}/admin#stats`);
});

app.get('/:merchantId/admin/history', merchantAuth, (req, res) => {
    const { merchantId } = req.params;
    const merchant = db.prepare('SELECT name FROM merchants WHERE id = ?').get(merchantId);
    const logs = db.prepare(`
        SELECT sl.*, c.name AS customer_name, c.email
        FROM stamp_logs sl
        JOIN customers c ON sl.customer_id = c.id
        WHERE sl.merchant_id = ?
        ORDER BY sl.created_at DESC
        LIMIT 200
    `).all(merchantId);

    const formatDate = (d) => new Date(d).toLocaleString('fr-FR', { day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' });

    res.send(`<!DOCTYPE html>
    <html lang="fr">
    <head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Historique — ${merchant.name}</title>
    <style>
        body { font-family:-apple-system,sans-serif; background:#f4f7f6; padding:20px; font-size:13px; }
        .card { background:white; border-radius:12px; padding:20px; box-shadow:0 3px 10px rgba(0,0,0,0.06); max-width:800px; margin:auto; }
        table { width:100%; border-collapse:collapse; }
        th { padding:9px 10px; background:#f8f9fa; text-align:left; font-size:0.82em; color:#666; }
        td { padding:9px 10px; border-bottom:1px solid #f0f0f0; }
        .badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:0.78em; font-weight:bold; }
        .add    { background:#d4edda; color:#155724; }
        .reward { background:#fff3cd; color:#856404; }
        .scan   { background:#d1ecf1; color:#0c5460; }
        .admin  { background:#e2d9f3; color:#4a235a; }
    </style>
    </head>
    <body>
    <div class="card">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
            <h2 style="margin:0;">📋 Historique des tampons — ${merchant.name}</h2>
            <a href="/${merchantId}/admin" style="font-size:0.85em; color:#007aff;">← Retour</a>
        </div>
        <table>
            <thead><tr>
                <th>Date</th><th>Client</th><th>Avant</th><th>Après</th><th>Action</th><th>Source</th>
            </tr></thead>
            <tbody>
                ${logs.map(l => `<tr>
                    <td style="white-space:nowrap; color:#888;">${formatDate(l.created_at)}</td>
                    <td><b>${l.customer_name}</b><br><span style="color:#aaa; font-size:0.85em;">${l.email}</span></td>
                    <td style="text-align:center;">${l.stamps_before}</td>
                    <td style="text-align:center; font-weight:bold;">${l.stamps_after}</td>
                    <td><span class="badge ${l.action}">${l.action === 'reward' ? '🎉 Récompense' : '➕ Tampon'}</span></td>
                    <td><span class="badge ${l.source}">${l.source === 'scan' ? '📷 Scan' : '⚙️ Admin'}</span></td>
                </tr>`).join('')}
                ${logs.length === 0 ? '<tr><td colspan="6" style="text-align:center; color:#aaa; padding:30px;">Aucun historique</td></tr>' : ''}
            </tbody>
        </table>
    </div>
    </body></html>`);
});

app.post('/:merchantId/admin/remove-customer/:customerId', merchantAuth, (req, res) => {
    const { merchantId, customerId } = req.params;
    const serial = `${customerId}-${merchantId}`;
    db.prepare('DELETE FROM registrations  WHERE serial_number = ?').run(serial);
    db.prepare('DELETE FROM loyalty_cards  WHERE customer_id = ? AND merchant_id = ?').run(customerId, merchantId);
    console.log(`🗑️ Client retiré manuellement : ${serial}`);
    res.redirect(`/${merchantId}/admin`);
});


app.get('/:merchantId/qrcode', async (req, res) => {
    const { merchantId } = req.params;
    const qrImage = await QRCode.toDataURL(`${BASE_URL}/${merchantId}/join`);
    res.send(`
        <body style="text-align:center; padding-top:50px; font-family:sans-serif;">
            <h1>QR Code d'inscription</h1>
            <img src="${qrImage}" style="width:300px; border:1px solid #eee; padding:10px;"><br><br>
            <button onclick="window.print()">IMPRIMER</button>
            <a href="/${merchantId}/admin">Retour</a>
        </body>
    `);
});

// ==========================================
// --- INSCRIPTION CLIENT ---
// ==========================================
app.get('/:merchantId/join', (req, res) => {
    const { merchantId } = req.params;
    const merchant = db.prepare('SELECT name FROM merchants WHERE id = ?').get(merchantId);
    if (!merchant) return res.status(404).send('Commerce introuvable.');
    res.send(`<!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { font-family: -apple-system, sans-serif; background: #f0f2f5; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
            .card { background: white; padding: 36px 28px; border-radius: 24px; box-shadow: 0 15px 35px rgba(0,0,0,0.1); text-align: center; width: 100%; max-width: 400px; }
            h1 { font-size: 1.5em; margin-bottom: 8px; }
            p  { color: #666; font-size: 0.95em; margin-bottom: 24px; }
            input {
                width: 100%; padding: 15px; margin-bottom: 12px;
                border-radius: 12px; border: 1px solid #ddd;
                font-size: 16px; outline: none;
                transition: border-color 0.2s;
            }
            input:focus { border-color: #007aff; }
            button { width: 100%; background: #007aff; color: white; border: none; padding: 16px; border-radius: 12px; font-size: 16px; font-weight: bold; cursor: pointer; margin-top: 4px; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>${merchant.name}</h1>
            <p>Inscrivez-vous pour obtenir votre carte de fidélité numérique.</p>
            <form action="/${merchantId}/join" method="POST">
                <input type="text"  name="name"  placeholder="Nom et Prénom" required autocomplete="name">
                <input type="email" name="email" placeholder="Votre e-mail"  required autocomplete="email">
                <button type="submit">OBTENIR MA CARTE</button>
            </form>
        </div>
    </body>
    </html>`);
});

app.post('/:merchantId/join', async (req, res) => {
    const { merchantId } = req.params;
    const { name, email } = req.body;

    if (isRateLimited(req.ip)) return res.status(429).send('Trop de tentatives, réessayez dans une minute.');

    try {
        if (!db.prepare('SELECT id FROM merchants WHERE id = ?').get(merchantId))
            return res.status(404).send('Commerce inexistant.');
        if (!fs.existsSync(getTemplatePath(merchantId)))
            return res.status(500).send('Erreur : template manquant.');

        // Email déjà inscrit → renvoyer le pass existant
        const existing = db.prepare('SELECT id, name FROM customers WHERE email = ?').get(email);
        if (existing) {
            const hasCard = db.prepare('SELECT 1 FROM loyalty_cards WHERE customer_id = ? AND merchant_id = ?').get(existing.id, merchantId);
            if (!hasCard) db.prepare('INSERT INTO loyalty_cards (customer_id, merchant_id, stamps, active) VALUES (?, ?, 0, 1)').run(existing.id, merchantId);
            else db.prepare('UPDATE loyalty_cards SET active = 1 WHERE customer_id = ? AND merchant_id = ?').run(existing.id, merchantId);
            const merchant = db.prepare('SELECT * FROM merchants WHERE id = ?').get(merchantId);
            sendEmail(merchant, { name: existing.name, email, stamps: 0 },
                `Votre carte de fidélité ${merchant.name}`,
                `Bonjour {nom},\n\nVoici votre lien pour accéder à votre carte de fidélité :\n\n${BASE_URL}/download/${existing.id}/${merchantId}\n\nÀ bientôt !`
            ).catch(err => console.error('❌ Email renvoi:', err?.message || err));
            return res.redirect(`/welcome/${existing.id}/${merchantId}`);
        }

        const customerId = 'cust-' + randomUUID();
        db.prepare('INSERT INTO customers (id, name, email) VALUES (?, ?, ?)').run(customerId, name, email);
        db.prepare('INSERT INTO loyalty_cards (customer_id, merchant_id, stamps) VALUES (?, ?, 0)').run(customerId, merchantId);

        // Email de bienvenue
        const merchant = db.prepare('SELECT * FROM merchants WHERE id = ?').get(merchantId);
        sendEmail(merchant, { name, email, stamps: 0 },
            `Bienvenue chez ${merchant.name} !`,
            `Bonjour {nom},\n\nMerci de rejoindre le programme de fidélité de ${merchant.name} !\n\nVotre carte est prête. Cliquez sur le lien ci-dessous pour l'ajouter à votre Wallet (Apple ou Google) :\n\n${BASE_URL}/download/${customerId}/${merchantId}\n\nÀ chaque visite, accumulez des tampons et obtenez : ${merchant.reward}.\n\nÀ bientôt !`
        ).catch(err => console.error('❌ Email bienvenue:', err?.message || err));

        res.redirect(`/welcome/${customerId}/${merchantId}`);
    } catch (err) {
        res.status(500).send('Erreur d\'inscription : ' + err.message);
    }
});

// ==========================================
// --- PAGE DE CONFIRMATION ---
// ==========================================
app.get('/welcome/:customerId/:merchantId', (req, res) => {
    const { customerId, merchantId } = req.params;
    const data = db.prepare(`
        SELECT c.name, m.name AS merchant_name, m.reward, m.max_stamps
        FROM customers c
        JOIN loyalty_cards lc ON c.id = lc.customer_id
        JOIN merchants m ON lc.merchant_id = m.id
        WHERE c.id = ? AND m.id = ?
    `).get(customerId, merchantId);
    if (!data) return res.status(404).send('Introuvable.');

    res.send(`<!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Bienvenue chez ${data.merchant_name}</title>
    </head>
    <body style="font-family:-apple-system,sans-serif; background:#f0f2f5; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; padding:20px; box-sizing:border-box;">
        <div style="background:white; border-radius:24px; box-shadow:0 20px 50px rgba(0,0,0,0.12); text-align:center; width:100%; max-width:380px; overflow:hidden;">
            <div style="background:#000; padding:30px 20px;">
                <div style="font-size:3em;">🎉</div>
                <h1 style="color:#d4af37; margin:10px 0 4px; font-size:1.4em;">${data.merchant_name}</h1>
                <p style="color:#aaa; margin:0; font-size:0.9em;">Carte de fidélité numérique</p>
            </div>
            <div style="padding:30px 24px;">
                <p style="font-size:1.1em; color:#333; margin:0 0 8px;">Bienvenue, <b>${data.name}</b> !</p>
                <p style="color:#777; font-size:0.9em; margin:0 0 24px;">
                    Accumulez des tampons à chaque visite.<br>
                    Récompense : <b>${data.reward}</b> après ${data.max_stamps} tampons.
                </p>
                <a href="/download/${customerId}/${merchantId}"
                    style="display:inline-block; background:#007aff; color:white; text-decoration:none; padding:14px 28px; border-radius:12px; font-weight:bold; font-size:1em; margin-bottom:12px;">
                    📲 Ajouter à mon Wallet
                </a>
                <p style="color:#bbb; font-size:0.78em; margin:12px 0 0;">
                    Compatible Apple Wallet et Google Wallet. Un email avec votre lien vous a été envoyé.
                </p>
            </div>
        </div>
    </body></html>`);
});

// ==========================================
// --- TÉLÉCHARGEMENT DU PASS ---
// ==========================================
app.get('/download/:customerId/:merchantId', async (req, res) => {
    const { customerId, merchantId } = req.params;
    const ua       = req.get('User-Agent') || '';
    const platform = req.query.platform;
    const isAndroid = platform === 'google' || (!platform && /android/i.test(ua));
    const isIOS     = platform === 'apple'  || (!platform && /iphone|ipad|ipod/i.test(ua));

    // Android → Google Wallet
    if (isAndroid && GW_ISSUER_ID) {
        try {
            const link = await generateGoogleWalletLink(customerId, merchantId);
            return res.redirect(link);
        } catch (err) {
            console.error('❌ Google Wallet:', err.message);
            return res.status(500).send('Erreur Google Wallet : ' + err.message);
        }
    }

    // iOS (ou Google Wallet non configuré) → Apple Wallet
    if (isIOS || !GW_ISSUER_ID) {
        try {
            return await sendPass(res, customerId, merchantId);
        } catch (err) {
            console.error('Erreur génération pass:', err);
            return res.status(500).send('Erreur lors de la génération.');
        }
    }

    // Device inconnu → page de choix
    const info = db.prepare(`
        SELECT c.name, m.name AS merchant
        FROM loyalty_cards lc
        JOIN customers c ON lc.customer_id = c.id
        JOIN merchants  m ON lc.merchant_id = m.id
        WHERE lc.customer_id = ? AND lc.merchant_id = ?
    `).get(customerId, merchantId);
    if (!info) return res.status(404).send('Lien invalide.');

    res.send(`<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Télécharger ma carte</title>
    <style>
        body { margin:0; padding:40px 20px; font-family:-apple-system,sans-serif; background:#f4f4f8; text-align:center; }
        h2 { color:#333; margin-bottom:4px; }
        p { color:#888; margin-bottom:30px; }
        .btn { display:block; max-width:280px; margin:10px auto; padding:16px; border-radius:14px; text-decoration:none; font-weight:bold; font-size:1em; }
        .apple  { background:#000; color:white; }
        .google { background:#4285f4; color:white; }
    </style>
</head>
<body>
    <h2>${info.merchant}</h2>
    <p>Carte de fidélité de ${info.name}</p>
    <a href="/download/${customerId}/${merchantId}?platform=apple"  class="btn apple">🍎 Ajouter à Apple Wallet</a>
    <a href="/download/${customerId}/${merchantId}?platform=google" class="btn google">🤖 Ajouter à Google Wallet</a>
</body>
</html>`);
});

// ==========================================
// --- SCAN / TAMPONS ---
// ==========================================
app.get('/scan/:customerId/:merchantId', (req, res) => {
    const { customerId, merchantId } = req.params;
    const data = db.prepare(`
        SELECT c.name AS customer, m.name AS merchant, lc.stamps, m.max_stamps
        FROM loyalty_cards lc
        JOIN customers c ON lc.customer_id = c.id
        JOIN merchants  m ON lc.merchant_id = m.id
        WHERE c.id = ? AND m.id = ?
    `).get(customerId, merchantId);
    if (!data) return res.status(404).send('Lien invalide.');
    res.send(`
        <body style="text-align:center; font-family:sans-serif; padding:50px;">
            <h1>${data.merchant}</h1>
            <p>Client : <b>${data.customer}</b></p>
            <div style="font-size:3em; border:3px solid gold; padding:20px; border-radius:15px; display:inline-block; margin:20px 0;">${data.stamps} / ${data.max_stamps}</div>
            <form action="/scan/${customerId}/${merchantId}/stamp" method="POST">
                <button style="padding:20px 40px; background:#28a745; color:white; border:none; border-radius:10px; font-size:1.2em; cursor:pointer;">+1 TAMPON</button>
            </form>
        </body>
    `);
});

app.post('/scan/:customerId/:merchantId/stamp', merchantAuth, async (req, res) => {
    const { customerId, merchantId } = req.params;
    const data = db.prepare(`
        SELECT lc.stamps, m.max_stamps, m.reward
        FROM loyalty_cards lc
        JOIN merchants m ON lc.merchant_id = m.id
        WHERE lc.customer_id = ? AND lc.merchant_id = ?
    `).get(customerId, merchantId);
    if (!data) return res.status(404).send('Erreur de base de données.');

    const rewardUnlocked = (data.stamps + 1) >= data.max_stamps;
    const nouveaux = rewardUnlocked ? 0 : data.stamps + 1;
    db.prepare('UPDATE loyalty_cards SET stamps = ?, last_scan = CURRENT_TIMESTAMP WHERE customer_id = ? AND merchant_id = ?').run(nouveaux, customerId, merchantId);
    logStamp(merchantId, customerId, data.stamps, nouveaux, rewardUnlocked ? 'reward' : 'add', 'scan');
    await sendPushUpdate(`${customerId}-${merchantId}`);
    syncGoogleWallet(customerId, merchantId);

    if (rewardUnlocked) {
        return res.send(`
            <body style="text-align:center; font-family:sans-serif; padding:50px; background:#f9f9f9;">
                <div style="font-size:4em;">🎉</div>
                <h1 style="color:#28a745;">Récompense débloquée !</h1>
                <p style="font-size:1.3em; font-weight:bold;">${data.reward}</p>
                <p style="color:#888;">La carte a été remise à zéro.</p>
                <a href="/scan/${customerId}/${merchantId}" style="display:inline-block; margin-top:20px; padding:15px 30px; background:#007aff; color:white; border-radius:10px; text-decoration:none;">Retour</a>
            </body>
        `);
    }

    res.send(`
        <body style="text-align:center; font-family:sans-serif; padding:50px; background:#f9f9f9;">
            <div style="font-size:4em;">✅</div>
            <h1>Tampon ajouté !</h1>
            <div style="font-size:2em; border:3px solid gold; padding:20px; border-radius:15px; display:inline-block; margin:20px 0;">${nouveaux} / ${data.max_stamps}</div>
            <br>
            <a href="/scan/${customerId}/${merchantId}" style="display:inline-block; margin-top:20px; padding:15px 30px; background:#007aff; color:white; border-radius:10px; text-decoration:none;">Retour</a>
        </body>
    `);
});

// ==========================================
// --- APPLE PASSKIT WEB SERVICE ---
// ==========================================

// Enregistrement d'un appareil
app.post('/v1/devices/:deviceId/registrations/:passId/:serial', (req, res) => {
    const { deviceId, serial } = req.params;
    const { pushToken } = req.body;
    const authToken = (req.get('Authorization') || '').replace('ApplePass ', '') || null;
    console.log(`📡 Enregistrement | Device: ${deviceId} | PushToken: ${pushToken ? 'OUI' : 'NON'} | Serial: ${serial}`);
    if (!pushToken) return res.sendStatus(400);
    try {
        db.prepare('INSERT OR REPLACE INTO registrations (device_id, push_token, serial_number, authentication_token) VALUES (?, ?, ?, ?)').run(deviceId, pushToken, serial, authToken);
        console.log(`✅ Enregistrement réussi pour serial=${serial}`);
        res.sendStatus(201);
    } catch (e) {
        console.error('❌ Erreur SQL Enregistrement:', e);
        res.sendStatus(500);
    }
});

// Liste des passes mis à jour pour un appareil
app.get('/v1/devices/:deviceId/registrations/:passId', (req, res) => {
    const { deviceId } = req.params;
    const since = req.query.passesUpdatedSince ? parseInt(req.query.passesUpdatedSince) : 0;
    console.log(`🔍 Route B : liste des passes pour Device: ${deviceId}`);
    try {
        const rows = db.prepare('SELECT serial_number FROM registrations WHERE device_id = ? AND (? = 0 OR updated_at > ?)').all(deviceId, since, since);
        if (rows.length === 0) return res.sendStatus(204);
        const response = { lastUpdated: String(Date.now()), serialNumbers: rows.map(r => r.serial_number) };
        console.log('✅ Serials envoyés :', response.serialNumbers);
        res.json(response);
    } catch (err) {
        console.error('❌ Erreur Route B:', err);
        res.sendStatus(500);
    }
});

// Téléchargement du pass mis à jour
app.get('/v1/passes/:passId/:serial', appleAuth, async (req, res) => {
    const { serial } = req.params;
    try {
        const card = db.prepare('SELECT customer_id, merchant_id FROM loyalty_cards WHERE customer_id || \'-\' || merchant_id = ?').get(serial);
        if (!card) { console.error(`⚠️ Serial introuvable: ${serial}`); return res.sendStatus(404); }
        console.log(`📥 Mise à jour pass : ${serial}`);
        await sendPass(res, card.customer_id, card.merchant_id);
    } catch (err) {
        console.error('❌ Erreur route mise à jour:', err);
        res.sendStatus(500);
    }
});

// Désinscription d'un appareil (pass supprimé du Wallet)
app.delete('/v1/devices/:deviceId/registrations/:passId/:serial', appleAuth, (req, res) => {
    const { deviceId, serial } = req.params;
    db.prepare('DELETE FROM registrations WHERE device_id = ? AND serial_number = ?').run(deviceId, serial);

    // Retrouver le client via les marchands connus
    const merchants = db.prepare('SELECT id FROM merchants').all();
    let removed = false;
    for (const m of merchants) {
        const suffix = `-${m.id}`;
        if (serial.endsWith(suffix)) {
            const customerId = serial.slice(0, serial.length - suffix.length);
            db.prepare('UPDATE loyalty_cards SET active = 0 WHERE customer_id = ? AND merchant_id = ?').run(customerId, m.id);
            console.log(`🗑️ Pass supprimé → client masqué : ${customerId} / ${m.id}`);
            removed = true;
            break;
        }
    }
    if (!removed) console.log(`🗑️ Désinscription Apple : device=${deviceId} serial=${serial}`);
    res.sendStatus(200);
});

// ==========================================
// ==========================================
// --- FORMULAIRE DE CONTACT ---
// ==========================================
app.post('/contact', async (req, res) => {
    const { name, business, email, phone, message } = req.body;
    try {
        await resend.emails.send({
            from:    `Fideliwallet <${process.env.MAIL_FROM || 'noreply@example.com'}>`,
            to:      process.env.CONTACT_EMAIL,
            subject: `🆕 Nouvelle demande — ${business}`,
            html:    `<h2>Nouvelle demande de démo</h2>
                      <p><b>Nom :</b> ${name}</p>
                      <p><b>Commerce :</b> ${business}</p>
                      <p><b>Email :</b> ${email}</p>
                      <p><b>Téléphone :</b> ${phone || '—'}</p>
                      <p><b>Message :</b> ${message || '—'}</p>`,
        });
    } catch (e) {
        console.error('Contact form email error:', e.message);
    }
    res.send(`<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Merci — Fideliwallet</title>
<style>body{font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f4f4f8;text-align:center;padding:20px;}
.card{background:white;border-radius:20px;padding:40px;max-width:400px;box-shadow:0 10px 30px rgba(0,0,0,0.1);}
a{color:#007aff;}</style></head>
<body><div class="card">
    <div style="font-size:3em;">🎉</div>
    <h2 style="margin:16px 0 8px;">Demande envoyée !</h2>
    <p style="color:#888;">On revient vers vous dans les 24h pour configurer votre carte de fidélité.</p>
    <p style="margin-top:20px;"><a href="/">← Retour à l'accueil</a></p>
</div></body></html>`);
});

// ==========================================
// --- LANDING PAGE ---
// ==========================================
app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Fideliwallet — Cartes de fidélité numériques</title>
    <meta name="description" content="Offrez à vos clients une carte de fidélité numérique sur Apple Wallet et Google Wallet. Sans application, sans matériel, en 5 minutes.">
    <style>
        * { box-sizing:border-box; margin:0; padding:0; }
        body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; color:#1a1a1a; background:white; }

        /* NAV */
        nav { display:flex; justify-content:space-between; align-items:center; padding:18px 6%; position:sticky; top:0; background:rgba(255,255,255,0.95); backdrop-filter:blur(10px); z-index:100; border-bottom:1px solid #f0f0f0; }
        .logo { font-weight:800; font-size:1.2em; letter-spacing:-0.5px; }
        .logo span { color:#007aff; }
        .nav-cta { background:#007aff; color:white; padding:9px 20px; border-radius:20px; text-decoration:none; font-weight:600; font-size:0.9em; }

        /* HERO */
        .hero { text-align:center; padding:90px 6% 80px; background:linear-gradient(160deg, #f0f6ff 0%, #ffffff 60%); }
        .hero-badge { display:inline-block; background:#e8f0fe; color:#007aff; padding:6px 14px; border-radius:20px; font-size:0.82em; font-weight:600; margin-bottom:20px; }
        .hero h1 { font-size:clamp(2em,5vw,3.2em); font-weight:800; line-height:1.15; letter-spacing:-1px; margin-bottom:20px; }
        .hero h1 span { color:#007aff; }
        .hero p { font-size:1.1em; color:#555; max-width:520px; margin:0 auto 36px; line-height:1.7; }
        .hero-btns { display:flex; gap:12px; justify-content:center; flex-wrap:wrap; }
        .btn-primary { background:#007aff; color:white; padding:14px 28px; border-radius:12px; text-decoration:none; font-weight:700; font-size:1em; }
        .btn-secondary { background:#f0f0f0; color:#333; padding:14px 28px; border-radius:12px; text-decoration:none; font-weight:600; font-size:1em; }

        /* WALLETS */
        .wallets { display:flex; gap:10px; justify-content:center; margin-top:40px; flex-wrap:wrap; }
        .wallet-badge { background:white; border:1px solid #e5e5e5; border-radius:10px; padding:10px 18px; font-size:0.88em; font-weight:600; color:#333; box-shadow:0 2px 8px rgba(0,0,0,0.06); }

        /* SECTION */
        section { padding:80px 6%; }
        section h2 { font-size:clamp(1.6em,3vw,2.2em); font-weight:800; text-align:center; margin-bottom:12px; letter-spacing:-0.5px; }
        .subtitle { text-align:center; color:#666; font-size:1em; margin-bottom:50px; line-height:1.6; }

        /* HOW IT WORKS */
        .steps { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:24px; }
        .step { text-align:center; padding:30px 20px; background:#f8f9fa; border-radius:16px; }
        .step-num { width:48px; height:48px; background:#007aff; color:white; border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:800; font-size:1.1em; margin:0 auto 16px; }
        .step h3 { font-size:1em; font-weight:700; margin-bottom:8px; }
        .step p { font-size:0.88em; color:#666; line-height:1.6; }

        /* FEATURES */
        .features-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:20px; }
        .feature { padding:28px; border:1px solid #f0f0f0; border-radius:16px; }
        .feature-icon { font-size:2em; margin-bottom:14px; }
        .feature h3 { font-size:1em; font-weight:700; margin-bottom:8px; }
        .feature p { font-size:0.88em; color:#666; line-height:1.6; }

        /* PRICING */
        .pricing-card { max-width:420px; margin:0 auto; background:#1a1a1a; color:white; border-radius:24px; padding:40px; text-align:center; }
        .pricing-card .price { font-size:3em; font-weight:800; margin:16px 0 4px; }
        .pricing-card .price span { font-size:0.4em; font-weight:400; color:#aaa; vertical-align:middle; }
        .pricing-card .trial { background:#007aff; border-radius:8px; padding:6px 14px; font-size:0.82em; font-weight:600; display:inline-block; margin-bottom:24px; }
        .pricing-list { list-style:none; text-align:left; margin-bottom:28px; }
        .pricing-list li { padding:8px 0; border-bottom:1px solid #333; font-size:0.9em; color:#ddd; }
        .pricing-list li::before { content:"✓ "; color:#007aff; font-weight:bold; }
        .pricing-cta { background:#007aff; color:white; padding:14px 28px; border-radius:12px; text-decoration:none; font-weight:700; display:block; }

        /* CTA FINAL */
        .cta-section { background:linear-gradient(135deg, #007aff, #5856d6); color:white; text-align:center; padding:80px 6%; }
        .cta-section h2 { color:white; margin-bottom:12px; }
        .cta-section p { color:rgba(255,255,255,0.8); margin-bottom:32px; font-size:1em; }
        .cta-section a { background:white; color:#007aff; padding:14px 32px; border-radius:12px; text-decoration:none; font-weight:700; font-size:1em; }

        /* FOOTER */
        footer { text-align:center; padding:30px 6%; color:#aaa; font-size:0.82em; border-top:1px solid #f0f0f0; }

        /* CONTACT */
        .contact-form { max-width:480px; margin:0 auto; display:grid; gap:12px; }
        .contact-form input, .contact-form textarea { padding:12px 14px; border:1px solid #e0e0e0; border-radius:10px; font-size:0.95em; font-family:inherit; }
        .contact-form textarea { height:120px; resize:none; }
        .contact-form button { background:#007aff; color:white; border:none; border-radius:10px; padding:13px; font-weight:700; font-size:1em; cursor:pointer; }
    </style>
</head>
<body>

    <!-- NAV -->
    <nav>
        <div class="logo">Fideli<span>wallet</span></div>
        <a href="#contact" class="nav-cta">Démarrer gratuitement</a>
    </nav>

    <!-- HERO -->
    <section class="hero">
        <div class="hero-badge">🍎 Apple Wallet · 🤖 Google Wallet · Sans application</div>
        <h1>La carte de fidélité<br><span>dans le téléphone</span><br>de vos clients</h1>
        <p>Finis les tickets papier perdus. Offrez à vos clients une vraie carte de fidélité numérique, toujours disponible dans leur Wallet, configurée en 24h.</p>
        <div class="hero-btns">
            <a href="#contact" class="btn-primary">Démarrer gratuitement</a>
            <a href="#comment" class="btn-secondary">Comment ça marche ?</a>
        </div>
        <div class="wallets">
            <div class="wallet-badge">🍎 Apple Wallet</div>
            <div class="wallet-badge">🤖 Google Wallet</div>
            <div class="wallet-badge">🔔 Notifications push</div>
            <div class="wallet-badge">📊 Dashboard complet</div>
        </div>
    </section>

    <!-- AVANTAGES -->
    <section style="background:#1a1a1a; color:white; padding:70px 6%;">
        <h2 style="color:white; margin-bottom:12px;">Bien plus qu'une carte de fidélité</h2>
        <p style="text-align:center; color:#aaa; margin-bottom:48px;">Fideliwallet vous donne des outils que vos concurrents n'ont pas.</p>
        <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:20px; max-width:960px; margin:0 auto;">
            <div style="background:#2a2a2a; border-radius:16px; padding:28px;">
                <div style="font-size:2em; margin-bottom:12px;">🔔</div>
                <h3 style="color:white; margin-bottom:8px;">Notifications push gratuites</h3>
                <p style="color:#aaa; font-size:0.88em; line-height:1.6;">Envoyez une promo directement sur l'écran de verrouillage iOS de vos clients. Zéro budget pub, impact immédiat.</p>
            </div>
            <div style="background:#2a2a2a; border-radius:16px; padding:28px;">
                <div style="font-size:2em; margin-bottom:12px;">🎯</div>
                <h3 style="color:white; margin-bottom:8px;">Ciblage précis</h3>
                <p style="color:#aaa; font-size:0.88em; line-height:1.6;">Filtrez vos clients par nombre de tampons ou date de dernière visite. Relancez uniquement les inactifs ou récompensez les plus fidèles.</p>
            </div>
            <div style="background:#2a2a2a; border-radius:16px; padding:28px;">
                <div style="font-size:2em; margin-bottom:12px;">📧</div>
                <h3 style="color:white; margin-bottom:8px;">Emails automatiques</h3>
                <p style="color:#aaa; font-size:0.88em; line-height:1.6;">Email de bienvenue, campagnes ciblées — communiquez avec vos clients par email directement depuis votre dashboard.</p>
            </div>
            <div style="background:#2a2a2a; border-radius:16px; padding:28px;">
                <div style="font-size:2em; margin-bottom:12px;">📊</div>
                <h3 style="color:white; margin-bottom:8px;">Statistiques & historique</h3>
                <p style="color:#aaa; font-size:0.88em; line-height:1.6;">Suivez vos clients actifs, tampons donnés, récompenses débloquées. Sachez exactement qui revient et qui vous a oublié.</p>
            </div>
        </div>
    </section>

    <!-- COMMENT ÇA MARCHE -->
    <section id="comment">
        <h2>Comment ça marche ?</h2>
        <p class="subtitle">Trois étapes simples pour fidéliser vos clients.</p>
        <div class="steps">
            <div class="step">
                <div class="step-num">1</div>
                <h3>On crée votre carte</h3>
                <p>Nous configurons votre programme de fidélité aux couleurs de votre commerce en 24h.</p>
            </div>
            <div class="step">
                <div class="step-num">2</div>
                <h3>Vos clients s'inscrivent</h3>
                <p>Ils scannent un QR Code, entrent leur email et reçoivent leur carte directement dans leur Wallet.</p>
            </div>
            <div class="step">
                <div class="step-num">3</div>
                <h3>Vous gérez tout</h3>
                <p>Ajoutez des tampons, envoyez des notifications, suivez vos stats depuis votre dashboard.</p>
            </div>
        </div>
    </section>

    <!-- FEATURES -->
    <section style="background:#f8f9fa;">
        <h2>Tout ce dont vous avez besoin</h2>
        <p class="subtitle">Une solution complète pour fidéliser vos clients.</p>
        <div class="features-grid">
            <div class="feature">
                <div class="feature-icon">📲</div>
                <h3>Apple & Google Wallet</h3>
                <p>Vos clients ajoutent leur carte en un clic. Elle apparaît automatiquement sur leur écran de verrouillage.</p>
            </div>
            <div class="feature">
                <div class="feature-icon">🔔</div>
                <h3>Notifications push</h3>
                <p>Envoyez des promotions directement sur l'écran de verrouillage de vos clients iOS en temps réel.</p>
            </div>
            <div class="feature">
                <div class="feature-icon">📊</div>
                <h3>Dashboard complet</h3>
                <p>Suivez vos clients, tampons donnés, récompenses débloquées et bien plus depuis votre espace admin.</p>
            </div>
            <div class="feature">
                <div class="feature-icon">📧</div>
                <h3>Emails automatiques</h3>
                <p>Email de bienvenue, rappels personnalisés — envoyez des campagnes ciblées à vos clients.</p>
            </div>
            <div class="feature">
                <div class="feature-icon">🖨️</div>
                <h3>QR Code d'inscription</h3>
                <p>Imprimez votre QR Code et posez-le en caisse. Vos clients s'inscrivent eux-mêmes en 30 secondes.</p>
            </div>
            <div class="feature">
                <div class="feature-icon">🔒</div>
                <h3>Sécurisé & fiable</h3>
                <p>Backups quotidiens, chiffrement des mots de passe, hébergement dédié en Europe.</p>
            </div>
        </div>
    </section>

    <!-- PRICING -->
    <section>
        <h2>Un tarif simple</h2>
        <p class="subtitle">Pas de surprise, pas d'engagement.</p>
        <div class="pricing-card">
            <div class="price">75<span>€ / mois</span></div>
            <p style="color:#aaa; font-size:0.88em; margin-bottom:24px;">Par commerce · Sans engagement</p>
            <ul class="pricing-list">
                <li>Clients illimités</li>
                <li>Apple Wallet + Google Wallet</li>
                <li>Notifications push iOS</li>
                <li>Emails automatiques</li>
                <li>Dashboard & statistiques</li>
                <li>Support inclus</li>
            </ul>
            <a href="mailto:${process.env.CONTACT_EMAIL}" class="pricing-cta">Démarrer gratuitement →</a>
        </div>
    </section>

    <!-- CONTACT -->
    <section id="contact" style="background:#f8f9fa;">
        <h2>Démarrer gratuitement</h2>
        <p class="subtitle">Sans engagement. On vous configure tout en 24h.</p>
        <form class="contact-form" action="/contact" method="POST">
            <input type="text"  name="name"    placeholder="Votre nom"              required>
            <input type="text"  name="business" placeholder="Nom de votre commerce" required>
            <input type="email" name="email"   placeholder="Votre email"            required>
            <input type="tel"   name="phone"   placeholder="Téléphone (optionnel)">
            <textarea name="message" placeholder="Dites-nous en plus sur votre commerce (type, ville…)"></textarea>
            <button type="submit">Envoyer ma demande →</button>
        </form>
    </section>

    <!-- FOOTER -->
    <footer>
        <p>© ${new Date().getFullYear()} Fideliwallet · <a href="mailto:${process.env.CONTACT_EMAIL}" style="color:#aaa;">${process.env.CONTACT_EMAIL}</a></p>
    </footer>

</body>
</html>`);
});

// ==========================================
// --- LANCEMENT ---
// ==========================================
app.listen(PORT, () => console.log(`🚀 Fideliwallet prêt sur ${BASE_URL}`));
