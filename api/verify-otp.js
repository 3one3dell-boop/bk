const crypto = require("crypto");

module.exports = async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "غير مسموح" });

  const body = typeof req.body === "string" ? JSON.parse(req.body) : (req.body || {});
  const phone = String(body.phone || "").replace(/[\s-]/g, "");
  const code = String(body.code || "");
  const token = String(body.token || "");
  const expires = Number(body.expires || 0);

  if (!/^\+9647[0-9]{9}$/.test(phone) || !/^[0-9]{6}$/.test(code))
    return res.status(400).json({ ok: false, error: "بيانات غير صالحة" });

  if (Date.now() > expires)
    return res.status(401).json({ ok: false, error: "انتهت صلاحية الرمز" });

  // إعادة حساب التوقيع والمقارنة بطريقة آمنة ضد هجمات التوقيت
  const expected = crypto
    .createHmac("sha256", process.env.JWT_SECRET)
    .update(`${phone}|${code}|${expires}`)
    .digest("hex");

  let valid = false;
  try {
    valid = crypto.timingSafeEqual(Buffer.from(token, "hex"), Buffer.from(expected, "hex"));
  } catch { valid = false; }

  if (!valid) return res.status(401).json({ ok: false, error: "الرمز غير صحيح" });

  // إصدار جلسة موقعة صالحة 7 أيام
  const sessionExp = Date.now() + 7 * 24 * 60 * 60 * 1000;
  const session = crypto
    .createHmac("sha256", process.env.JWT_SECRET)
    .update(`session|${phone}|${sessionExp}`)
    .digest("hex");

  return res.status(200).json({ ok: true, session, sessionExp, phone });
};
