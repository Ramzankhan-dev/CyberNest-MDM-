const express = require("express");
const cors = require("cors");
require("dotenv").config();

const authRoutes = require("./routes/auth");
const deviceRoutes = require("./routes/devices");
const commandRoutes = require("./routes/commands");
const policyRoutes = require("./routes/policies");
const notificationRoutes = require("./routes/notifications");
const organizationRoutes = require("./routes/organizations");
const departmentRoutes = require("./routes/departments");
const employeeRoutes = require("./routes/employees");

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
app.use("/api/policies", policyRoutes);
app.use("/api/notifications", notificationRoutes);
app.use("/api/organizations", organizationRoutes);
app.use("/api/departments", departmentRoutes);
app.use("/api/employees", employeeRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
