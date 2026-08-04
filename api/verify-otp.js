// ============================================================
//  Uruk App OTP — api/verify-otp.js
//  تحقق آمن بـ timingSafeEqual + جلسة موقعة 7 أيام + Firebase customToken
// ============================================================
const crypto = require("crypto");
const admin = require("firebase-admin");

const ALLOWED_ORIGINS = [
  "https://www.urukapp.store",
  "https://urukapp.store",
  "https://bk-jade-zeta.vercel.app"
];
const attempts = new Map();
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

// نفس نمط البريد المخلّق بالضبط المستخدم بالعميل القديم (PHONE_EMAIL_DOMAIN
// = "uruk.local") — لازم يطابق حرفياً حتى ما نفقد بيانات المستخدمين الحاليين
const PHONE_EMAIL_DOMAIN = "uruk.local";

function getAdmin() {
  if (!admin.apps.length) {
    const svc = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({ credential: admin.credential.cert(svc) });
  }
  return admin;
}

// يرجّع UID المستخدم الصحيح — يدوّر أول على حساب موجود بنفس نمط البريد
// المخلّق (يحافظ على بيانات Firestore المرتبطة به)، ولو ماكو ينشئ حساب
// فاضي جديد (بدون بريد) — العميل نفسه يربط البريد/كلمة السر لاحقاً
// بـlinkWithCredential (نفس منطقه الحالي، صفر تغيير مطلوب هناك)
async function resolveUid(phone) {
  const fbAdmin = getAdmin();
  const syntheticEmail = phone.replace(/[^\d]/g, "") + "@" + PHONE_EMAIL_DOMAIN;
  try {
    const existing = await fbAdmin.auth().getUserByEmail(syntheticEmail);
    return existing.uid;
  } catch (e) {
    if (e.code !== "auth/user-not-found") throw e;
    const created = await fbAdmin.auth().createUser({});
    return created.uid;
  }
}

module.exports = async function handler(req, res) {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "غير مسموح" });

  // ✅ DEFENSIVE FIX: كل المنطق (تحليل الجسم وصولاً لتوليد customToken)
  // صار داخل try/catch واحد شامل — نفس منطق المقارنة الآمنة
  // (timingSafeEqual) والبحث بالبريد المخلّق محفوظان حرفياً بدون تغيير
  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const phone = String(body.phone || "").replace(/[\s-]/g, "");
    const code = String(body.code || "");
    const token = String(body.token || "");
    const expires = Number(body.expires || 0);

    if (!/^\+9647[0-9]{9}$/.test(phone) || !/^[0-9]{6}$/.test(code))
      return res.status(400).json({ ok: false, error: "بيانات غير صالحة" });
    if (Date.now() > expires)
      return res.status(401).json({ ok: false, error: "انتهت صلاحية الرمز، اطلب رمزاً جديداً" });

    const now = Date.now();
    const rec = attempts.get(phone) || { count: 0, first: now };
    if (now - rec.first > 5 * 60 * 1000) { rec.count = 0; rec.first = now; }
    rec.count++;
    attempts.set(phone, rec);
    if (rec.count > 10)
      return res.status(429).json({ ok: false, error: "محاولات كثيرة، اطلب رمزاً جديداً" });

    const expected = crypto
      .createHmac("sha256", process.env.JWT_SECRET)
      .update(`${phone}|${code}|${expires}`)
      .digest("hex");
    let valid = false;
    try {
      valid = crypto.timingSafeEqual(Buffer.from(token, "hex"), Buffer.from(expected, "hex"));
    } catch { valid = false; }
    if (!valid) return res.status(401).json({ ok: false, error: "الرمز غير صحيح" });

    attempts.delete(phone);

    const sessionExp = Date.now() + 7 * 24 * 60 * 60 * 1000;
    const session = crypto
      .createHmac("sha256", process.env.JWT_SECRET)
      .update(`session|${phone}|${sessionExp}`)
      .digest("hex");

    try {
      const uid = await resolveUid(phone);
      const customToken = await getAdmin().auth().createCustomToken(uid);
      return res.status(200).json({ ok: true, session, sessionExp, phone, customToken });
    } catch (e) {
      console.error("customToken mint failed:", e && e.stack || e);
      return res.status(500).json({ ok: false, error: "تعذّر إتمام تسجيل الدخول، حاول مرة ثانية" });
    }
  } catch (e) {
    console.error("verify-otp:", e && e.stack || e);
    const isBadInput = e instanceof SyntaxError;
    return res.status(isBadInput ? 400 : 500).json({ ok: false, error: isBadInput ? "جسم الطلب غير صالح" : "خطأ داخلي مؤقت" });
  }
};
