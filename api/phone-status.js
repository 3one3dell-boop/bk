// ============================================================
//  Uruk App OTP — api/phone-status.js
//  يتحقق هل رقم الهاتف مسجّل وله كلمة سر — يقرر شاشة الدخول التالية
// ============================================================
const admin = require("firebase-admin");

const ALLOWED_ORIGINS = [
  "https://www.urukapp.store",
  "https://urukapp.store",
  "https://bk-jade-zeta.vercel.app"
];
const rateLimit = new Map();
function cors(req, res) {
  const origin = req.headers.origin || "";
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }
  if (req.method === "OPTIONS") { res.status(204).end(); return true; }
  return false;
}

const PHONE_EMAIL_DOMAIN = "uruk.local"; // نفس نمط verify-otp.js بالضبط

function getAdmin() {
  if (!admin.apps.length) {
    const svc = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({ credential: admin.credential.cert(svc) });
  }
  return admin;
}

module.exports = async function handler(req, res) {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "غير مسموح" });

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const phone = String(body.phone || "").replace(/[\s-]/g, "");
    if (!/^\+9647[0-9]{9}$/.test(phone))
      return res.status(400).json({ ok: false, error: "صيغة الرقم غير صحيحة" });

    const now = Date.now();
    const rec = rateLimit.get(phone) || { count: 0, first: now };
    if (now - rec.first > 15 * 60 * 1000) { rec.count = 0; rec.first = now; }
    rec.count++;
    rateLimit.set(phone, rec);
    if (rec.count > 25)
      return res.status(429).json({ ok: false, error: "محاولات كثيرة، حاول لاحقاً" });

    const fbAdmin = getAdmin();
    // ✅ إصلاح بگة الملف القديم: كان يدوّر بـuid مصطنع "phone_..." ما
    // يطابق أبداً UID الحقيقي (عشوائي، Firebase يولّده). الصحيح: نفس
    // نمط البريد المخلّق المستخدم فعلياً بالتسجيل والتحقق.
    const syntheticEmail = phone.replace(/[^\d]/g, "") + "@" + PHONE_EMAIL_DOMAIN;
    try {
      const user = await fbAdmin.auth().getUserByEmail(syntheticEmail);
      const hasPassword = (user.providerData || []).some((p) => p.providerId === "password");
      return res.status(200).json({ ok: true, exists: true, hasPassword, authEmail: hasPassword ? user.email : null });
    } catch (e) {
      if (e.code === "auth/user-not-found") {
        return res.status(200).json({ ok: true, exists: false, hasPassword: false, authEmail: null });
      }
      throw e;
    }
  } catch (e) {
    console.error("phone-status:", e && e.stack || e);
    // JSON.parse فاشل (جسم مشوّه) يُصنَّف 400 مو 500 — خطأ بالعميل مو
    // بالخادم. أي استثناء ثاني (فايربيس، شبكة...) يبقى 500 حقيقي
    const isBadInput = e instanceof SyntaxError;
    return res.status(isBadInput ? 400 : 500).json({ ok: false, error: isBadInput ? "جسم الطلب غير صالح" : "خطأ داخلي مؤقت" });
  }
};
