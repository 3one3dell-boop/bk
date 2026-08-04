// ============================================================
//  Uruk App OTP — api/blob-cleanup.js
//  يحذف الملف الأصلي عالي الجودة بعد ما يشوفه طرفا المحادثة كلاهم
// ============================================================
const { del } = require("@vercel/blob");
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

module.exports = async (req, res) => {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "غير مسموح" });

  const limited = rateLimit("blob-cleanup:" + clientIp(req), 60, 15 * 60 * 1000);
  if (!limited.ok) return res.status(429).json({ ok: false, error: "طلبات كثيرة جداً" });

  try {
    const idToken = getBearerToken(req);
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const { chatId, messageId } = body;
    if (!idToken || !chatId || !messageId) return res.status(400).json({ ok: false, error: "بيانات ناقصة" });

    const fbAdmin = getAdmin();
    const decoded = await fbAdmin.auth().verifyIdToken(idToken);
    const uid = decoded.uid;

    if (!chatId.split("_").includes(uid)) return res.status(403).json({ ok: false, error: "ماعندك صلاحية" });

    const db = fbAdmin.firestore();
    const msgRef = db.collection("chats").doc(chatId).collection("messages").doc(messageId);
    const snap = await msgRef.get();
    if (!snap.exists) return res.status(404).json({ ok: false, error: "الرسالة غير موجودة" });
    const m = snap.data();

    if (m.status !== "read" && m.status !== "delivered") {
      return res.status(409).json({ ok: false, error: "لسه ما شافها الطرف الثاني" });
    }
    if (!m.mediaUrl) return res.status(200).json({ ok: true, alreadyClean: true });
    if (!["image", "video"].includes(m.type)) return res.status(400).json({ ok: false, error: "نوع غير مدعوم" });

    try { await del(m.mediaUrl); } catch (e) { console.warn("blob del:", e.message); }
    await msgRef.update({ mediaUrl: "", mediaCleaned: true });

    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error("blob-cleanup:", e);
    return res.status(400).json({ ok: false, error: "تعذّر التنظيف" });
  }
};
