// ============================================================
//  Uruk App OTP — api/verify-otp.js
//  تحقق آمن بـ timingSafeEqual + جلسة موقعة 7 أيام
// ============================================================
const crypto = require("crypto");

const ALLOWED_ORIGINS = [
  "https://www.urukapp.store",
  "https://urukapp.store",
  "https://bk-jade-zeta.vercel.app"
];

// منع التخمين القسري: 10 محاولات كحد أقصى لكل رقم
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

module.exports = async function handler(req, res) {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "غير مسموح" });

  const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
  const phone = String(body.phone || "").replace(/[\s-]/g, "");
  const code = String(body.code || "");
  const token = String(body.token || "");
  const expires = Number(body.expires || 0);

  if (!/^\+9647[0-9]{9}$/.test(phone) || !/^[0-9]{6}$/.test(code))
    return res.status(400).json({ ok: false, error: "بيانات غير صالحة" });

  if (Date.now() > expires)
    return res.status(401).json({ ok: false, error: "انتهت صلاحية الرمز، اطلب رمزاً جديداً" });

  // حد محاولات التخمين
  const now = Date.now();
  const rec = attempts.get(phone) || { count: 0, first: now };
  if (now - rec.first > 5 * 60 * 1000) { rec.count = 0; rec.first = now; }
  rec.count++;
  attempts.set(phone, rec);
  if (rec.count > 10)
    return res.status(429).json({ ok: false, error: "محاولات كثيرة، اطلب رمزاً جديداً" });

  // إعادة حساب التوقيع والمقارنة الآمنة
  const expected = crypto
    .createHmac("sha256", process.env.JWT_SECRET)
    .update(`${phone}|${code}|${expires}`)
    .digest("hex");

  let valid = false;
  try {
    valid = crypto.timingSafeEqual(Buffer.from(token, "hex"), Buffer.from(expected, "hex"));
  } catch { valid = false; }

  if (!valid) return res.status(401).json({ ok: false, error: "الرمز غير صحيح" });

  // نجاح → جلسة موقعة صالحة 7 أيام
  attempts.delete(phone);
  const sessionExp = Date.now() + 7 * 24 * 60 * 60 * 1000;
  const session = crypto
    .createHmac("sha256", process.env.JWT_SECRET)
    .update(`session|${phone}|${sessionExp}`)
    .digest("hex");

  return res.status(200).json({ ok: true, session, sessionExp, phone });
};
