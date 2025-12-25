import express from "express";
import crypto from "crypto";

const app = express();

// RAW body lazım (Tebex imza için)
app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);

// 🔍 Tebex signature doğrulama
function verifyTebex(req) {
  const signature = req.get("X-Signature");
  if (!signature) return false;

  const hmac = crypto
    .createHmac("sha256", process.env.TEBEX_SECRET)
    .update(req.rawBody)
    .digest("hex");

  return hmac === signature;
}

// ✅ Tebex validate için (GET)
app.get("/tebex/webhook", (req, res) => {
  return res.status(200).send("OK");
});

// ✅ Tebex webhook (POST)
app.post("/tebex/webhook", (req, res) => {
  if (!verifyTebex(req)) {
    console.warn("❌ Invalid Tebex signature");
    return res.status(401).send("Invalid signature");
  }

  console.log("✅ Tebex webhook geldi:", req.body);
  return res.status(200).send("OK");
});

// Sağlık kontrolü
app.get("/", (req, res) => {
  res.status(200).send("alive");
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Listening on", port));
