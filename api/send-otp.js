const crypto = require("crypto");

module.exports = async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "غير مسموح" });

  const body = typeof req.body === "string" ? JSON.parse(req.body) : (req.body || {});
  const phone = String(body.phone || "").replace(/[\s-]/g, "");

  // التحقق من صيغة الرقم العراقي: +9647XXXXXXXXX
  if (!/^\+9647[0-9]{9}$/.test(phone))
    return res.status(400).json({ ok: false, error: "صيغة الرقم غير صحيحة، مثال: +9647701234567" });

  // توليد رمز من 6 أرقام
  const code = String(crypto.randomInt(100000, 1000000));
  const expires = Date.now() + 5 * 60 * 1000; // صالح 5 دقائق

  // توقيع مشفر HMAC — لا نحتاج قاعدة بيانات لتخزين الرمز (Stateless وآمن)
  const token = crypto
    .createHmac("sha256", process.env.JWT_SECRET)
    .update(`${phone}|${code}|${expires}`)
    .digest("hex");

  try {
    // ⚠️ راجع توثيق OTPiq في حسابك (docs.otpiq.com) وعدّل أسماء الحقول أو الهيدر إن اختلفت
    const r = await fetch("https://api.otpiq.com/api/sms", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${process.env.OTPIQ_API_KEY}`
      },
      body: JSON.stringify({
        to: phone,
        message: `رمز التحقق الخاص بك هو: ${code}`
      })
    });

    if (!r.ok) return res.status(502).json({ ok: false, error: "فشل الإرسال عبر OTPiq" });
    return res.status(200).json({ ok: true, token, expires });
  } catch (e) {
    return res.status(500).json({ ok: false, error: "خطأ داخلي" });
  }
};
