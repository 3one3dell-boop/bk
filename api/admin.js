// ============================================================
//  Uruk App OTP — api/admin.js
//  إجراءات إدارية حساسة: حذف حساب Auth حقيقي (إدارة أو ذاتي)
//  التحقق: Authorization: Bearer <Firebase ID Token>
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
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  }
  if (req.method === "OPTIONS") { res.status(204).end(); return true; }
  return false;
}

function getAdmin() {
  if (!admin.apps.length) {
    const svc = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({ credential: admin.credential.cert(svc) });
  }
  return admin;
}

// يقرأ التوكن من رأس Authorization: Bearer <token> — لا نقبله من جسم
// الطلب بعد الآن (نمط أوضح وأنظف، ومنع تكرار حمل التوكن بمكانين)
function getBearerToken(req) {
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

async function requireAdmin(req) {
  const idToken = getBearerToken(req);
  if (!idToken) { const err = new Error("missing_token"); err.httpCode = 401; throw err; }
  const fbAdmin = getAdmin();
  const decoded = await fbAdmin.auth().verifyIdToken(idToken);
  const cfg = await fbAdmin.firestore().collection("siteConfig").doc("main").get();
  const adminUid = cfg.exists ? cfg.data().adminUid : null;
  if (!adminUid || decoded.uid !== adminUid) {
    const err = new Error("caller_not_admin"); err.httpCode = 403; throw err;
  }
  return decoded.uid;
}

async function requireSelf(req) {
  const idToken = getBearerToken(req);
  if (!idToken) { const err = new Error("missing_token"); err.httpCode = 401; throw err; }
  const decoded = await getAdmin().auth().verifyIdToken(idToken);
  return decoded.uid;
}

// حذف حساب Auth فعلياً — يخلّي رجوع نفس الرقم/البريد يُنشئ حساب جديد
// كلياً بدل ما يرتبط بنفس الـuid القديم ("حساب شبح")
async function deleteAuthUser(uid) {
  try {
    await getAdmin().auth().deleteUser(uid);
  } catch (e) {
    if (e.code !== "auth/user-not-found") throw e;
  }
}



module.exports = async (req, res) => {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "غير مسموح" });

  const rl = rateLimit.get("global") || { count: 0, first: Date.now() };
  const now = Date.now();
  if (now - rl.first > 15 * 60 * 1000) { rl.count = 0; rl.first = now; }
  rl.count++;
  rateLimit.set("global", rl);
  if (rl.count > 60) return res.status(429).json({ ok: false, error: "طلبات كثيرة جداً" });

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});

    if (body.action === "delete_user_auth") {
      const { targetUid } = body;
      if (!targetUid) return res.status(400).json({ ok: false, error: "missing_fields" });
      await requireAdmin(req);
      await deleteAuthUser(targetUid);
      return res.status(200).json({ ok: true });
    }

    if (body.action === "delete_own_account") {
      // صلاحية مختلفة عن delete_user_auth: ماكو شرط isAdmin — أي
      // مستخدم يحذف حسابه هو بس. verifyIdToken يضمن التوكن أصلي، والـuid
      // المستهدف هو نفسه صاحب التوكن دايماً — صفر احتمال حذف حساب غيرك
      const uid = await requireSelf(req);
      await deleteAuthUser(uid);
      return res.status(200).json({ ok: true });
    }

    return res.status(400).json({ ok: false, error: "إجراء غير معروف" });
  } catch (e) {
    console.error("admin:", e);
    const code = e.httpCode || 400;
    const msg = e.message === "caller_not_admin" ? "ماعندك صلاحية إدارة"
      : e.message === "missing_token" ? "توكن الدخول مفقود"
      : "تعذّر تنفيذ الإجراء";
    return res.status(code).json({ ok: false, error: msg });
  }
};
