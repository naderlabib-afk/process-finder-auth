const express = require("express");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const otpStore = {};

app.post("/send-otp", (req, res) => {
  const { email } = req.body;

  const otp = Math.floor(100000 + Math.random() * 900000);
  otpStore[email] = otp;

  console.log(`OTP for ${email}: ${otp}`);

  res.send({ success: true });
});

app.post("/verify-otp", (req, res) => {
  const { email, code } = req.body;

  if (otpStore[email] == code) {
    res.send({ success: true });
  } else {
    res.send({ success: false });
  }
});

app.get("/", (req, res) => {
  res.send("API running ✅");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on port", PORT));
