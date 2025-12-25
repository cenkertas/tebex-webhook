const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");

const app = express();

// Render / proxy arkasında gerçek IP'yi almak için:
app.set("trust proxy", true);

// Tebex IP allowlist (dokümandaki IP'ler)
const TEBEX_IPS = new Set(["18.209.80.3", "54.87.231.232"]);

app.use(
  bodyParser.json({
    verify: (req, res, buf) => {
      req.rawBody = buf; // 🔥 imza için RAW body şart
    },
  })
);

function getClientIp(req) {
  // trust proxy açıkken req.ip genelde doğru gelir.
  // Yine de bazı durumlar için X-Forwarded-For fallback:
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.length > 0) {
    return xff.split(",")[0].trim();
  }
  return req.ip;
}

function timingSafeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const aBuf = Buffer.from(a, "hex");
  const bBuf = Buffer.from(b, "hex");
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

app.post("/webhook", (req, res) => {
  // 1) IP kontrolü (doküman önerisi: uymuyorsa 404)
  const ip = getClientIp(req);
  if (!TEBEX_IPS.has(ip)) {
    return res.status(404).send("Not Found");
  }

  // 2) Signature doğrulama (X-Signature)
  const secret = process.env.TEBEX_WEBHOOK_SECRET; // Render env var
  if (!secret) {
    // yanlış deploy / env eksikse:
    return res.status(500).json({ error: "Webhook secret not configured" });
  }

  const signatureHeader = req.header("X-Signature"); // dokümana göre bu header
  if (!signatureHeader) {
    return res.status(401).json({ error: "Missing X-Signature header" });
  }

  const bodyHash = crypto
    .createHash("sha256")
    .update(req.rawBody.toString("utf-8"))
    .digest("hex");

  const finalHash = crypto.createHmac("sha256", secret).update(bodyHash).digest("hex");

  if (!timingSafeEqualHex(finalHash, signatureHeader)) {
    return res.status(401).json({ error: "Invalid signature" });
  }

  // 3) Validation webhook handling (type === validation.webhook)
  // Dokümana göre: 200 + {"id": "<gelen id>"}
  if (req.body && req.body.type === "validation.webhook") {
    return res.status(200).json({ id: req.body.id });
  }

  // 4) Diğer webhooklar: 2XX dön, kendi işlemlerini burada yap
  // Örn: payment.completed, payment.refunded vs.
  // req.body.type ve req.body.subject içeriğine göre işlem yaparsın.
  return res.sendStatus(200);
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Listening on", port));
