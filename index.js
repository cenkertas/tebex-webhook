import express from "express";

const app = express();
app.use(express.json({ limit: "2mb" }));

// ✅ Tebex doğrulama için (tarayıcıdan açınca OK görünecek)
app.get("/tebex/webhook", (req, res) => {
  return res.status(200).send("OK");
});

// ✅ Tebex webhook buraya POST atacak
app.post("/tebex/webhook", (req, res) => {
  console.log("Tebex webhook geldi:", JSON.stringify(req.body).slice(0, 2000));
  return res.status(200).send("OK");
});

// ✅ Sağlık kontrolü (opsiyonel)
app.get("/", (req, res) => {
  return res.status(200).send("alive");
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Listening on", port));
