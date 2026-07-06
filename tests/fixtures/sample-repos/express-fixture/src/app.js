const express = require("express");
const accountRoutes = require("./routes/account");

const app = express();
app.use("/api", accountRoutes);

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

module.exports = app;
