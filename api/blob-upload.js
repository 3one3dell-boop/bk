// ============================================================
//  Uruk App OTP — api/blob-upload.js
//  يُصدر توكن رفع آمن لـ Vercel Blob بعد التحقق من الهوية والمسار
//
//  ⚠️ ملاحظة مهمة: هذا الملف الوحيد اللي ما يستخدم رأس Authorization —
//  بروتوكول @vercel/blob/client الرسمي يمرّر بيانات العميل عبر
//  clientPayload (جزء من جسم طلب الرفع نفسه)، مو رأس HTTP منفصل.
//  حافظت على هذا النمط لأنه يخص مكتبة Vercel Blob، مو اختيارنا.
// ============================================================
const { handleUpload } = require("@vercel/blob/client");
const admin = require("firebase-admin");

const ALLOWED_ORIGINS = [
  "https://www.urukapp.store",
  "https://urukapp.store",
  "https://bk-jade-zeta.vercel.app"
];
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
async function readJson(req) {
  if (req.body && typeof req.body === "object") return req.body;
  return await new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => { try { resolve(JSON.parse(data || "{}")); } catch { resolve({}); } });
  });
}

// نفس منطق الصلاحيات الموجود بـ storage.rules بالضبط
function isPathAllowed(pathname, uid) {
  if (pathname.startsWith(`avatars/${uid}.jpg`) || pathname.startsWith(`avatars/${uid}`)) return true;
  if (pathname.startsWith(`status/${uid}/`)) return true;
  const m = pathname.match(/^(images|files|voice|videos)\/([^/]+)\//);
  if (m) return m[2].split("_").includes(uid);
  return false;
}
function needsOverwrite(pathname, uid) {
  return pathname.startsWith(`avatars/${uid}`);
}

module.exports = async (req, res) => {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "غير مسموح" });

  try {
    const body = await readJson(req);
    const jsonResponse = await handleUpload({
      body,
      request: req,
      onBeforeGenerateToken: async (pathname, clientPayload) => {
        let idToken = null;
        try { idToken = JSON.parse(clientPayload || "{}").idToken; } catch (e) {}
        if (!idToken) throw new Error("missing_auth_token");

        const decoded = await getAdmin().auth().verifyIdToken(idToken);
        const uid = decoded.uid;
        if (!isPathAllowed(pathname, uid)) throw new Error("forbidden_path");

        return {
          allowedContentTypes: ["image/*", "audio/*", "video/*", "application/pdf", "application/octet-stream", "application/zip", "application/msword", "application/vnd.*", "text/plain"],
          maximumSizeInBytes: 60 * 1024 * 1024,
          addRandomSuffix: false,
          allowOverwrite: needsOverwrite(pathname, uid),
          tokenPayload: JSON.stringify({ uid }),
        };
      },
      onUploadCompleted: async () => {},
    });
    return res.status(200).json(jsonResponse);
  } catch (e) {
    console.error("blob-upload:", e);
    const msg = e.message === "forbidden_path" ? "ماكو صلاحية للرفع بهذا المسار"
      : e.message === "missing_auth_token" ? "الجلسة غير صالحة، سجّل الدخول من جديد"
      : "تعذّر تجهيز الرفع";
    return res.status(400).json({ ok: false, error: msg });
  }
};
