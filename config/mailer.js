require("dotenv").config();

// Uses EmailJS's HTTPS API — connects to YOUR OWN Gmail account (via
// OAuth in the EmailJS dashboard), so there's no domain-verification
// requirement and no sandbox restriction on which recipients you can
// email. No extra npm package needed (Node 18+ has fetch() built in).
//
// Setup at emailjs.com:
// 1. Add an Email Service (Email Services > Add New > Gmail > connect
//    your Google account)
// 2. Create an Email Template (Email Templates > Create New) with
//    variables {{to_email}} and {{otp}} used in the template body
// 3. Get: Service ID, Template ID, Public Key (Account > General),
//    Private Key (Account > Security — needed for server-side calls)
async function sendOtpEmail(toEmail, otp) {
  const response = await fetch("https://api.emailjs.com/api/v1.0/email/send", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      service_id: process.env.EMAILJS_SERVICE_ID,
      template_id: process.env.EMAILJS_TEMPLATE_ID,
      user_id: process.env.EMAILJS_PUBLIC_KEY,
      accessToken: process.env.EMAILJS_PRIVATE_KEY,
      template_params: {
        to_email: toEmail,
        otp: otp,
      },
    }),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`EmailJS send failed: ${response.status} ${errorBody}`);
  }
}

module.exports = { sendOtpEmail };
