// ============================================================
//  Uruk App OTP — api/send-call-push.js
//  إشعار "مكالمة واردة" فوري عبر Firebase Cloud Messaging
//
//  ✅ إصلاح أمني أثناء الترحيل: النسخة القديمة كانت تثق بـfromUid من
//  جسم الطلب مباشرة بدون أي تحقق — أي حد يقدر ينتحل هوية أي مستخدم.
//  الآن fromUid لازم يطابق صاحب التوكن الحقيقي بالضبط.
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

module.exports = async (req, res) => {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "غير مسموح" });

  try {
    const idToken = getBearerToken(req);
    if (!idToken) return res.status(401).json({ ok: false, error: "توكن الدخول مفقود" });
    const fbAdmin = getAdmin();
    const decoded = await fbAdmin.auth().verifyIdToken(idToken);

    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const { toUid, fromUid, fromName, callId, isVideo } = body;
    if (!toUid || !fromUid || !callId) return res.status(400).json({ ok: false, error: "بيانات ناقصة" });
    // ✅ يمنع انتحال الهوية — fromUid لازم يطابق صاحب التوكن الحقيقي
    if (fromUid !== decoded.uid) return res.status(403).json({ ok: false, error: "لا يمكنك الإرسال باسم مستخدم ثاني" });

    const rl = rateLimit("call-push:" + fromUid, 20, 60 * 1000);
    if (!rl.ok) return res.status(429).json({ ok: false, error: "طلبات كثيرة" });

    const db = fbAdmin.firestore();
    const toUserSnap = await db.collection("users").doc(toUid).get();
    const fcmToken = toUserSnap.exists ? toUserSnap.data().fcmToken : null;
    if (!fcmToken) return res.status(200).json({ ok: true, delivered: false, reason: "no_token" });

    await fbAdmin.messaging().send({
      token: fcmToken,
      android: { priority: "high" },
      data: {
        type: "incoming_call",
        callId: String(callId),
        fromUid: String(fromUid),
        fromName: String(fromName || "مجهول"),
        isVideo: isVideo ? "1" : "0",
      },
    });
    return res.status(200).json({ ok: true, delivered: true });
  } catch (e) {
    console.error("send-call-push:", e);
    return res.status(500).json({ ok: false, error: "خطأ داخلي" });
  }
};
