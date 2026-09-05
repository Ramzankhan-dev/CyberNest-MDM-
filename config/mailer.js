require("dotenv").config();

// Uses Resend's HTTPS API — same reasoning as before (Render blocks raw
// SMTP). No extra npm package needed, Node 18+ has fetch() built in.
//
// Setup: create a free Resend account (resend.com), get your API key
// from the dashboard (no domain verification needed to send to your
// OWN signup email in sandbox mode — good enough for a demo).
async function sendOtpEmail(toEmail, otp) {
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
    },
    body: JSON.stringify({
      from: process.env.RESEND_FROM_EMAIL || "CyberNest <onboarding@resend.dev>",
      to: [toEmail],
      subject: "Your CyberNest password reset code",
      html: `<p>Your verification code is:</p><h2 style="letter-spacing:4px">${otp}</h2><p>This code expires in 5 minutes. If you didn't request this, you can safely ignore this email.</p>`,
    }),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Resend email send failed: ${response.status} ${errorBody}`);
  }
}

module.exports = { sendOtpEmail };
