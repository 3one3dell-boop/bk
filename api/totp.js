// ============================================================
//  Uruk App OTP — api/totp.js
//  إدارة التحقق بخطوتين (RFC 6238) — إعداد/تأكيد/تحقق/تعطيل/إزالة إدارية
//  التحقق: Authorization: Bearer <Firebase ID Token>
//
//  ⚠️ ملاحظة أمنية حرجة محفوظة من النظام القديم: السرّ (secret) ورموز
//  الاسترداد تُخزَّن بمجموعة Firestore منفصلة (totpSecrets) — بقاعدة
//  "allow read,write: if false" (صفر وصول من أي عميل، حتى صاحب الحساب
//  نفسه). كل التحقق يصير هنا بالخادم فقط عبر Admin SDK. لا تنقل هذي
//  الحقول أبداً لمستند users العادي (اللي قاعدته "allow read: if
//  signedIn()" — أي مستخدم مسجّل يقدر يقرأه).
// ============================================================
const crypto = require("crypto");
const admin = require("firebase-admin");

const ALLOWED_ORIGINS = [
  "https://www.urukapp.store",
  "https://urukapp.store",
  "https://bk-jade-zeta.vercel.app"
];
const _hits = new Map();
function cors(req, res) {
  const origin = req.headers.origin || "";
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  }
  if (req.method === "OPTIONS") { res.status(204).end(); return true; }
  return false;
}
function rateLimit(key, maxPerWindow, windowMs) {
  const now = Date.now();
  const arr = (_hits.get(key) || []).filter((t) => now - t < windowMs);
  if (arr.length >= maxPerWindow) return { ok: false, retryAfter: Math.ceil((windowMs - (now - arr[0])) / 1000) };
  arr.push(now); _hits.set(key, arr);
  return { ok: true };
}
function getAdmin() {
  if (!admin.apps.length) {
    const svc = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({ credential: admin.credential.cert(svc) });
  }
  return admin;
}
function getBearerToken(req) {
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}
function clientIp(req) {
  return (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
}

// ---------- تشفير TOTP (RFC 6238) — منطق محفوظ حرفياً من النظام القديم ----------
const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Encode(buf) {
  let bits = "", out = "";
  for (const byte of buf) bits += byte.toString(2).padStart(8, "0");
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, "0");
    out += B32_ALPHABET[parseInt(chunk, 2)];
  }
  return out;
}
function base32Decode(str) {
  const clean = str.toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = "";
  for (const ch of clean) bits += B32_ALPHABET.indexOf(ch).toString(2).padStart(5, "0");
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}
function generateTotpSecret() { return base32Encode(crypto.randomBytes(20)); }
function totpAt(secretB32, timeStep) {
  const key = base32Decode(secretB32);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(timeStep));
  const hmac = crypto.createHmac("sha1", key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16)
    | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return String(code % 1000000).padStart(6, "0");
}
function verifyTotp(secretB32, code, window = 1) {
  if (!/^\d{6}$/.test(String(code || ""))) return false;
  const step = Math.floor(Date.now() / 1000 / 30);
  for (let w = -window; w <= window; w++) if (totpAt(secretB32, step + w) === String(code)) return true;
  return false;
}
function otpauthUrl(secretB32, accountLabel, issuer = "Uruk") {
  const label = encodeURIComponent(`${issuer}:${accountLabel}`);
  return `otpauth://totp/${label}?secret=${secretB32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}
function generateRecoveryCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const raw = crypto.randomBytes(5).toString("hex").toUpperCase();
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5)}`);
  }
  return codes;
}
function hashRecoveryCode(code) {
  const salt = process.env.OTP_HASH_SALT || "uruk-salt";
  return crypto.createHash("sha256").update(salt + ":" + code.toUpperCase()).digest("hex");
}

// ---------- الإجراءات ----------
async function handleSetup(body, res, req) {
  const limited = rateLimit("totp-setup:" + clientIp(req), 10, 15 * 60 * 1000);
  if (!limited.ok) return res.status(429).json({ ok: false, error: "محاولات كثيرة، حاول لاحقاً" });

  const idToken = getBearerToken(req);
  if (!idToken) return res.status(401).json({ ok: false, error: "توكن الدخول مفقود" });
  const fbAdmin = getAdmin();
  const decoded = await fbAdmin.auth().verifyIdToken(idToken);
  const uid = decoded.uid;

  const db = fbAdmin.firestore();
  const userDoc = await db.collection("users").doc(uid).get();
  const userData = userDoc.exists ? userDoc.data() : {};
  if (userData.totpEnabled) return res.status(409).json({ ok: false, error: "التحقق بخطوتين مفعّل أصلاً" });

  const secret = generateTotpSecret();
  const label = userData.username || userData.phone || uid.slice(0, 8);
  const url = otpauthUrl(secret, label);
  await db.collection("totpSecrets").doc(uid).set({ pendingSecret: secret }, { merge: true });
  return res.status(200).json({ ok: true, secret, otpauthUrl: url });
}

async function handleConfirm(body, res, req) {
  const idToken = getBearerToken(req);
  const { code } = body;
  if (!idToken || !code) return res.status(400).json({ ok: false, error: "بيانات ناقصة" });
  const fbAdmin = getAdmin();
  const decoded = await fbAdmin.auth().verifyIdToken(idToken);
  const uid = decoded.uid;

  const db = fbAdmin.firestore();
  const secretRef = db.collection("totpSecrets").doc(uid);
  const snap = await secretRef.get();
  const secret = snap.exists ? snap.data().pendingSecret : null;
  if (!secret) return res.status(400).json({ ok: false, error: "ماكو إعداد معلّق" });
  if (!verifyTotp(secret, code)) return res.status(400).json({ ok: false, error: "الرمز غير صحيح" });

  const recoveryCodes = generateRecoveryCodes(10);
  const hashed = recoveryCodes.map((c) => ({ hash: hashRecoveryCode(c), used: false }));
  await secretRef.set({ secret, pendingSecret: fbAdmin.firestore.FieldValue.delete(), recoveryCodes: hashed }, { merge: true });
  await db.collection("users").doc(uid).set({ totpEnabled: true, twoFactor: true }, { merge: true });
  return res.status(200).json({ ok: true, recoveryCodes });
}

async function handleVerify(body, res, req) {
  const idToken = getBearerToken(req);
  const { code } = body;
  if (!idToken || !code) return res.status(400).json({ ok: false, error: "بيانات ناقصة" });
  const fbAdmin = getAdmin();
  const decoded = await fbAdmin.auth().verifyIdToken(idToken);
  const uid = decoded.uid;

  const limUid = rateLimit("totp-verify:uid:" + uid, 5, 15 * 60 * 1000);
  const limIp = rateLimit("totp-verify:ip:" + clientIp(req), 15, 15 * 60 * 1000);
  if (!limUid.ok || !limIp.ok) return res.status(429).json({ ok: false, error: "محاولات كثيرة، حاول لاحقاً" });

  const db = fbAdmin.firestore();
  const userSnap = await db.collection("users").doc(uid).get();
  if (!userSnap.exists || !userSnap.data().totpEnabled) return res.status(400).json({ ok: false, error: "التحقق بخطوتين غير مفعّل" });
  const secretSnap = await db.collection("totpSecrets").doc(uid).get();
  const data = secretSnap.exists ? secretSnap.data() : {};

  if (/^\d{6}$/.test(String(code))) {
    if (verifyTotp(data.secret, code)) return res.status(200).json({ ok: true, method: "totp" });
    return res.status(400).json({ ok: false, error: "الرمز غير صحيح" });
  }
  const hash = hashRecoveryCode(code);
  const codes = Array.isArray(data.recoveryCodes) ? data.recoveryCodes : [];
  const idx = codes.findIndex((c) => c.hash === hash && !c.used);
  if (idx === -1) return res.status(400).json({ ok: false, error: "الرمز غير صحيح" });
  codes[idx].used = true; codes[idx].usedAt = Date.now();
  await db.collection("totpSecrets").doc(uid).update({ recoveryCodes: codes });
  return res.status(200).json({ ok: true, method: "recovery", remainingCodes: codes.filter((c) => !c.used).length });
}

async function handleDisable(body, res, req) {
  const limited = rateLimit("totp-disable:" + clientIp(req), 10, 15 * 60 * 1000);
  if (!limited.ok) return res.status(429).json({ ok: false, error: "محاولات كثيرة، حاول لاحقاً" });

  const idToken = getBearerToken(req);
  const { code } = body;
  if (!idToken || !code) return res.status(400).json({ ok: false, error: "بيانات ناقصة" });
  const fbAdmin = getAdmin();
  const decoded = await fbAdmin.auth().verifyIdToken(idToken);
  const uid = decoded.uid;

  const db = fbAdmin.firestore();
  const userRef = db.collection("users").doc(uid);
  const userSnap = await userRef.get();
  if (!userSnap.exists || !userSnap.data().totpEnabled) return res.status(400).json({ ok: false, error: "التحقق بخطوتين غير مفعّل" });
  const secretRef = db.collection("totpSecrets").doc(uid);
  const secretSnap = await secretRef.get();
  const data = secretSnap.exists ? secretSnap.data() : {};

  let valid = false;
  if (/^\d{6}$/.test(String(code))) valid = verifyTotp(data.secret, code);
  else {
    const hash = hashRecoveryCode(code);
    valid = (data.recoveryCodes || []).some((c) => c.hash === hash && !c.used);
  }
  if (!valid) return res.status(400).json({ ok: false, error: "الرمز غير صحيح" });

  await secretRef.delete();
  await userRef.update({ totpEnabled: false, twoFactor: false });
  return res.status(200).json({ ok: true });
}

async function handleAdminRemove(body, res, req) {
  const idToken = getBearerToken(req);
  const { targetUid } = body;
  if (!idToken || !targetUid) return res.status(400).json({ ok: false, error: "بيانات ناقصة" });
  const fbAdmin = getAdmin();
  const decoded = await fbAdmin.auth().verifyIdToken(idToken);
  const db = fbAdmin.firestore();
  const cfg = await db.collection("siteConfig").doc("main").get();
  const adminUid = cfg.exists ? cfg.data().adminUid : null;
  if (!adminUid || decoded.uid !== adminUid) return res.status(403).json({ ok: false, error: "ماعندك صلاحية إدارة" });

  await db.collection("totpSecrets").doc(targetUid).delete();
  await db.collection("users").doc(targetUid).update({ totpEnabled: false, twoFactor: false });
  return res.status(200).json({ ok: true });
}

module.exports = async (req, res) => {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "غير مسموح" });

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    switch (body.action) {
      case "setup": return await handleSetup(body, res, req);
      case "confirm": return await handleConfirm(body, res, req);
      case "verify": return await handleVerify(body, res, req);
      case "disable": return await handleDisable(body, res, req);
      case "admin_remove": return await handleAdminRemove(body, res, req);
      default: return res.status(400).json({ ok: false, error: "إجراء غير معروف" });
    }
  } catch (e) {
    console.error("totp:", e);
    return res.status(400).json({ ok: false, error: "تعذّر تنفيذ الإجراء" });
  }
};
