const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");

const app = express();

// Render / proxy arkasında gerçek IP için önemli
app.set("trust proxy", true);

// Tebex IP allowlist (dokümandaki IP'ler)
const TEBEX_IPS = new Set(["18.209.80.3", "54.87.231.232"]);

app.use(
  bodyParser.json({
    verify: (req, res, buf) => {
      req.rawBody = buf; // Signature doğrulaması RAW body ister
    },
  })
);

function getClientIp(req) {
  // Trust proxy açıkken çoğu zaman req.ip yeterli olur.
  // Ama x-forwarded-for gelirse onun ilkini alalım.
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

app.get("/", (req, res) => res.send("OK"));

app.post("/webhook", (req, res) => {
  // ✅ DEBUG: Tebex istekleri geliyor mu?
  console.log("WEBHOOK HIT", {
    ip: getClientIp(req),
    reqIp: req.ip,
    xff: req.headers["x-forwarded-for"],
    hasSig: !!req.header("X-Signature"),
    type: req.body?.type,
    id: req.body?.id,
  });

  // 1) IP kontrolü (dokümanda önerildiği gibi: uymuyorsa 404)
  const ip = getClientIp(req);
  console.log("CLIENT IP", ip);

  if (!TEBEX_IPS.has(ip)) {
    console.log("IP BLOCKED", ip, "allowed:", Array.from(TEBEX_IPS));
    return res.status(404).send("Not Found");
  }

  // 2) Signature doğrulama (X-Signature header)
  const secret = process.env.TEBEX_WEBHOOK_SECRET;
  if (!secret) {
    console.log("ERROR: TEBEX_WEBHOOK_SECRET missing on Render");
    return res.status(500).json({ error: "Webhook secret not configured" });
  }

  const signatureHeader = req.header("X-Signature");
  if (!signatureHeader) {
    console.log("ERROR: Missing X-Signature header");
    return res.status(401).json({ error: "Missing X-Signature header" });
  }

  // RAW body hash -> HMAC-SHA256(secret, bodyHash)
  const bodyHash = crypto
    .createHash("sha256")
    .update(req.rawBody.toString("utf-8"))
    .digest("hex");

  const finalHash = crypto.createHmac("sha256", secret).update(bodyHash).digest("hex");

  if (!timingSafeEqualHex(finalHash, signatureHeader)) {
    console.log("BAD SIGNATURE", { finalHash, signatureHeader });
    return res.status(401).json({ error: "Invalid signature" });
  }

  // 3) Validation webhook (dokümana göre: 200 + {"id": "<gelen id>"})
  if (req.body && req.body.type === "validation.webhook") {
    console.log("VALIDATION OK", req.body.id);
    return res.status(200).json({ id: req.body.id });
  }

  // 4) Diğer webhooklar (payment.completed vb.) - şimdilik 200
  console.log("EVENT OK", req.body?.type);
  return res.sendStatus(200);
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Listening on", port));
