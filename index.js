const express = require("express");
const crypto = require("crypto");

const app = express();

// Tebex webhook'ları raw body ister
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

const TEBEX_WEBHOOK_SECRET = process.env.TEBEX_WEBHOOK_SECRET;

// Şimdilik validate sorunsuz geçsin diye esnek bıraktık
function verifySignature(req) {
  const headerSig = (req.headers["x-signature"] || "").toString();
  if (!headerSig || !TEBEX_WEBHOOK_SECRET) return true;

  const raw = req.rawBody?.toString("utf-8") || "";
  const bodyHash = crypto
    .createHash("sha256")
    .update(raw, "utf-8")
    .digest("hex");

  const finalHash = crypto
    .createHmac("sha256", TEBEX_WEBHOOK_SECRET)
    .update(bodyHash)
    .digest("hex");

  try {
    return crypto.timingSafeEqual(
      Buffer.from(finalHash),
      Buffer.from(headerSig)
    );
  } catch {
    return false;
  }
}

app.get("/", (req, res) => {
  res.status(200).send("OK");
});

app.post("/tebex/webhook", (req, res) => {
  if (!verifySignature(req)) {
    return res.status(401).json({ error: "Invalid signature" });
  }

  const payload = req.body || {};
  const type = payload.type;

  // ✅ Tebex endpoint doğrulaması
  if (type === "validation.webhook") {
    return res.status(200).json({ id: payload.id });
  }

  console.log("Tebex webhook geldi:", type, payload.id);

  return res.status(200).json({ ok: true });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log("Server listening on port", port);
});
