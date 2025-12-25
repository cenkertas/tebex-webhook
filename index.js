// index.js
const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");

const app = express();
app.set("trust proxy", true);

const TEBEX_IPS = new Set(["18.209.80.3", "54.87.231.232"]);

app.use(
  bodyParser.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);

function getClientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.length > 0) return xff.split(",")[0].trim();
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
  // IP allowlist
  const ip = getClientIp(req);
  if (!TEBEX_IPS.has(ip)) return res.status(404).send("Not Found");

  // Signature verify
  const secret = process.env.TEBEX_WEBHOOK_SECRET;
  if (!secret) return res.status(500).json({ error: "Webhook secret not configured" });

  const signatureHeader = req.header("X-Signature");
  if (!signatureHeader) return res.status(401).json({ error: "Missing X-Signature header" });

  const bodyHash = crypto
    .createHash("sha256")
    .update(req.rawBody.toString("utf-8"))
    .digest("hex");

  const finalHash = crypto.createHmac("sha256", secret).update(bodyHash).digest("hex");

  if (!timingSafeEqualHex(finalHash, signatureHeader)) {
    return res.status(401).json({ error: "Invalid signature" });
  }

  // Validation webhook
  if (req.body?.type === "validation.webhook") {
    return res.status(200).json({ id: req.body.id });
  }

  // Other webhooks: accept
  return res.sendStatus(200);
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Listening on", port));
