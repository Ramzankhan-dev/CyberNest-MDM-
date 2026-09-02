const express = require("express");
const cors = require("cors");
require("dotenv").config();

const authRoutes = require("./routes/auth");
const deviceRoutes = require("./routes/devices");
const commandRoutes = require("./routes/commands");

const app = express();
app.use(cors());
app.use(express.json());

// Health check — visit this URL to confirm the server is alive
app.get("/", (req, res) => {
  res.json({ status: "CyberNest backend is running" });
});

app.use("/api/auth", authRoutes);
app.use("/api/devices", deviceRoutes);
app.use("/api/commands", commandRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
