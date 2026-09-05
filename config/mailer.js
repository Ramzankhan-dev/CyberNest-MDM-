require("dotenv").config();

// Uses Brevo's HTTPS REST API (not raw SMTP) — Render's free tier blocks
// outbound SMTP, so this avoids that entirely. No extra npm package
// needed since Node 18+ has fetch() built in.
//
// Setup: create a free Brevo account (brevo.com), verify a sender email
// under Senders & IP > Senders, then create an API key under
// Settings (gear icon) > SMTP & API > API Keys > Generate a new API key.
async function sendOtpEmail(toEmail, otp) {
  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "api-key": process.env.BREVO_API_KEY,
    },
    body: JSON.stringify({
      sender: { email: process.env.BREVO_FROM_EMAIL, name: "CyberNest" },
      to: [{ email: toEmail }],
      subject: "Your CyberNest password reset code",
      htmlContent: `<p>Your verification code is:</p><h2 style="letter-spacing:4px">${otp}</h2><p>This code expires in 5 minutes. If you didn't request this, you can safely ignore this email.</p>`,
    }),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Brevo email send failed: ${response.status} ${errorBody}`);
  }
}

module.exports = { sendOtpEmail };
