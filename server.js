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
const dashboardRoutes = require("./routes/dashboard");
const complianceRoutes = require("./routes/compliance");
const applicationRoutes = require("./routes/applications");
const enrollmentRoutes = require("./routes/enrollment");
const auditLogRoutes = require("./routes/auditLogs");

const app = express();

// Render sits behind a reverse proxy — this tells Express to trust its
// X-Forwarded-For header, which express-rate-limit needs to correctly
// identify each client by IP (without this it throws ERR_ERL_UNEXPECTED_X_FORWARDED_FOR).
app.set("trust proxy", 1);

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
app.use("/api/dashboard", dashboardRoutes);
app.use("/api/compliance", complianceRoutes);
app.use("/api/applications", applicationRoutes);
app.use("/api/enrollment", enrollmentRoutes);
app.use("/api/audit-logs", auditLogRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
