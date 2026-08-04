// ============================================================
//  Uruk App OTP — api/link-approve.js
//  الجهاز الجديد يطلب توكن بعد موافقة الجهاز المسجّل
// ============================================================
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
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
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
function clientIp(req) {
  return (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
}

module.exports = async (req, res) => {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "غير مسموح" });
  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const code = body.code;
    if (!/^\d{6}$/.test(String(code || ""))) return res.status(400).json({ ok: false, error: "كود غير صحيح" });

    const rl = rateLimit("linkapprove:" + clientIp(req), 15, 15 * 60 * 1000);
    if (!rl.ok) return res.status(429).json({ ok: false, error: "محاولات كثيرة" });

    const fbAdmin = getAdmin();
    const db = fbAdmin.firestore();
    const ref = db.collection("link_requests").doc(String(code));
    const snap = await ref.get();
    if (!snap.exists) return res.status(400).json({ ok: false, error: "طلب غير موجود" });
    const rec = snap.data();

    const exp = rec.expiresAt && rec.expiresAt.toMillis ? rec.expiresAt.toMillis() : 0;
    if (Date.now() > exp) { await ref.delete().catch(() => {}); return res.status(400).json({ ok: false, error: "انتهت صلاحية الطلب" }); }
    if (!rec.approved || !rec.uid) return res.status(400).json({ ok: false, error: "لم تتم الموافقة بعد" });

    await ref.delete().catch(() => {});
    const customToken = await fbAdmin.auth().createCustomToken(rec.uid, { linkedDevice: true });
    return res.status(200).json({ ok: true, customToken, uid: rec.uid });
  } catch (e) {
    console.error("link-approve:", e);
    return res.status(500).json({ ok: false, error: "خطأ داخلي" });
  }
};
