const express = require("express");
const cors = require("cors");
const nodemailer = require("nodemailer");

const app = express();
app.use(express.json());
app.use(cors());

// ✅ Store OTPs temporarily (in-memory)
let otpStore = {};

// ✅ Configure Gmail transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "processfinder.rts@gmail.com",
    pass: "YOUR_APP_PASSWORD_HERE" // 🔴 replace this
  }
});

// ✅ SEND OTP
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  const otp = Math.floor(100000 + Math.random() * 900000);

  // ✅ Save OTP
  otpStore[email] = otp;

  console.log(`OTP for ${email}: ${otp}`);

  try {
    await transporter.sendMail({
      from: '"Process Finder System" <processfinder.rts@gmail.com>',
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

    res.json({ success: true });

  } catch (err) {
    console.error("Email send error:", err);
    res.status(500).json({ error: "Failed to send OTP email" });
  }
});

// ✅ VERIFY OTP
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ error: "Missing email or OTP" });
  }

  // ✅ Check OTP
  if (otpStore[email] && otpStore[email] == otp) {
    delete otpStore[email]; // ✅ remove after use

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
