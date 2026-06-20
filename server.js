const express = require("express");
const cors = require("cors");
const { Resend } = require("resend");

const app = express();
app.use(express.json());
app.use(cors());

// ✅ Temporary OTP storage
let otpStore = {};

// ✅ Your Resend API key
const resend = new Resend("re_Box5mtoF_QBTuqKKhJbLXZNXBhLK8txTC");

// ✅ SEND OTP
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  const otp = Math.floor(100000 + Math.random() * 900000);
  otpStore[email] = otp;

  console.log(`OTP for ${email}: ${otp}`);

  try {
    const { data, error } = await resend.emails.send({
      from: "Process Finder <onboarding@resend.dev>",
      to: email,
      subject: "[Process Finder] Your OTP Code",
      text: `Hello,

Your verification code is:

${otp}

This code will expire in 5 minutes.

If you did not request this, please ignore this email.

Regards,
Process Finder Team`
    });

    if (error) {
      console.error("❌ Resend error:", error);
      return res.status(500).json({ error: "Email failed" });
    }

    console.log("✅ Email sent successfully via Resend");

    res.json({ success: true });

  } catch (err) {
    console.error("❌ Exception:", err);
    res.status(500).json({ error: err.message });
  }
});

// ✅ VERIFY OTP
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ error: "Missing email or OTP" });
  }

  if (otpStore[email] && otpStore[email] == otp) {
    delete otpStore[email]; // ✅ one-time use
    return res.json({
      success: true,
      message: "OTP verified successfully"
    });
  }

  res.status(400).json({
    success: false,
    message: "Invalid or expired OTP"
  });
});

// ✅ Health check
app.get("/", (req, res) => {
  res.send("✅ API running (OTP service active)");
});

// ✅ Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
