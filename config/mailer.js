const nodemailer = require("nodemailer");
require("dotenv").config();

// Sends real emails (OTPs, etc.) via Gmail SMTP.
// Needs EMAIL_USER (a Gmail address) and EMAIL_PASSWORD (a 16-character
// "App Password" — NOT the normal Gmail password) as environment variables.
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

async function sendOtpEmail(toEmail, otp) {
  await transporter.sendMail({
    from: `"CyberNest" <${process.env.EMAIL_USER}>`,
    to: toEmail,
    subject: "Your CyberNest password reset code",
    text: `Your verification code is ${otp}. It expires in 5 minutes. If you didn't request this, you can ignore this email.`,
    html: `<p>Your verification code is:</p><h2 style="letter-spacing:4px">${otp}</h2><p>This code expires in 5 minutes. If you didn't request this, you can safely ignore this email.</p>`,
  });
}

module.exports = { sendOtpEmail };
