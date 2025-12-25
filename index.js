import express from "express";

const app = express();
app.use(express.json({ limit: "2mb" }));

// ✅ Tebex VALIDATE (GET)
app.get("/tebex/webhook", (req, res) => {
  return res.status(200).send("OK");
});

// ✅ Gerçek webhook (POST)
app.post("/tebex/webhook", (req, res) => {
  console.log("Tebex webhook geldi:", req.body);
  return res.status(200).send("OK");
});

// Sağlık kontrolü
app.get("/", (req, res) => {
  return res.status(200).send("alive");
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Listening on", port));
