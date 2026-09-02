const { Pool } = require("pg");
require("dotenv").config();

// This pool manages connections to your Supabase PostgreSQL database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // required for Supabase
});

pool.on("connect", () => {
  console.log("Connected to PostgreSQL (Supabase)");
});

module.exports = pool;
