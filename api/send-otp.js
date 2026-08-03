// ============================================================
//  Uruk App OTP — api/send-otp.js
//  CORS مقيد بـ urukapp.store + حماية HMAC-SHA256 + Rate Limit
// ============================================================
const crypto = require("crypto");

// الدومينات المسموح لها فقط (دومينك + صفحة الاختبار)
const ALLOWED_ORIGINS = [
  "https://www.urukapp.store",
  "https://urukapp.store",
  "https://bk-jade-zeta.vercel.app"
];

// ذاكرة مؤقتة لمنع إغراق الرسائل (Rate Limit)
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

module.exports = async function handler(req, res) {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "غير مسموح" });

  const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
  const phone = String(body.phone || "").replace(/[\s-]/g, "");

  // صيغة الرقم العراقي فقط
  if (!/^\+9647[0-9]{9}$/.test(phone))
    return res.status(400).json({ ok: false, error: "صيغة الرقم غير صحيحة، مثال: +9647701234567" });

  // منع الاستنزاف: 3 رسائل كحد أقصى لكل رقم كل 10 دقائق
  const now = Date.now();
  const rec = rateLimit.get(phone) || { count: 0, first: now };
  if (now - rec.first > 10 * 60 * 1000) { rec.count = 0; rec.first = now; }
  rec.count++;
  rateLimit.set(phone, rec);
  if (rec.count > 3)
    return res.status(429).json({ ok: false, error: "تجاوزت الحد المسموح، حاول بعد 10 دقائق" });

  // رمز من 6 أرقام صالح 5 دقائق
  const code = String(crypto.randomInt(100000, 1000000));
  const expires = now + 5 * 60 * 1000;

  // توقيع مشفر — لا حاجة لقاعدة بيانات (Stateless وآمن)
  const token = crypto
    .createHmac("sha256", process.env.JWT_SECRET)
    .update(`${phone}|${code}|${expires}`)
    .digest("hex");

  try {
    // استدعاء OTPiq الرسمي: Bearer + phoneNumber بدون +
    const r = await fetch("https://api.otpiq.com/api/sms", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${process.env.OTPIQ_API_KEY}`
      },
      body: JSON.stringify({
        phoneNumber: phone.replace("+", ""),
        smsType: "verification",
        verificationCode: code,
        provider: "auto"
      })
    });

    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      return res.status(502).json({ ok: false, error: "فشل الإرسال عبر OTPiq", detail: err.message });
    }

    return res.status(200).json({ ok: true, token, expires });
  } catch (e) {
    return res.status(500).json({ ok: false, error: "خطأ داخلي مؤقت" });
  }
};
