const { getUsersFromGitHub } = require("./services/github");
const express = require("express");
const cors = require("cors");
const { Resend } = require("resend");

const app = express();
app.use(express.json());
app.use(cors());

// ✅ OTP storage
let otpStore = {};

// ✅ Resend
const resend = new Resend("re_Box5mtoF_QBTuqKKhJbLXZNXBhLK8txTC");

// ✅ SEND OTP (FIXED ✅)
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  const normalizedEmail = email.trim().toLowerCase();

  try {
    // ✅ 🔥 FETCH USERS FROM GITHUB (CRITICAL FIX)
    const { users } = await getUsersFromGitHub();

    const user = users.find(
      u => u.email.toLowerCase() === normalizedEmail
    );

    if (!user || !["OL", "Manager", "Admin"].includes(user.role)) {
      console.log(`🚫 Unauthorized OTP request: ${normalizedEmail}`);

      return res.status(403).json({
        error: "Unauthorized email"
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000);
    otpStore[normalizedEmail] = otp;

    console.log(`OTP for ${normalizedEmail}: ${otp}`);

    const { error } = await resend.emails.send({
      from: "Process Finder <noreply@processfinder.xyz>",
      to: normalizedEmail,
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
      return res.status(500).json({ error: "Email failed" });
    }

    res.json({ success: true });

  } catch (err) {
    console.error("❌ Exception:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ VERIFY OTP (no change needed ✅)
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({
      error: "Missing email or OTP"
    });
  }

  const normalizedEmail = email.trim().toLowerCase();

  if (otpStore[normalizedEmail] && otpStore[normalizedEmail] == otp) {
    delete otpStore[normalizedEmail];

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

// ✅ ROOT
app.get("/", (req, res) => {
  res.send("✅ API running (OTP service active)");
});

// ✅ TEST USERS (keep for debugging ✅)
app.get("/test-users", async (req, res) => {
  try {
    const { users } = await getUsersFromGitHub();

    console.log("✅ Users from GitHub:", users);

    res.json({
      success: true,
      users
    });

  } catch (error) {
    console.error("❌ Error fetching users:", error);

    res.status(500).json({
      success: false,
      error: "Failed to fetch users"
    });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
