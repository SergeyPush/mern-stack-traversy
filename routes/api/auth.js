const { Router } = require("express");
const router = Router();
const auth = require("../../middleware/auth");
const { check, validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("config");
const User = require("../../models/User");

router.get("/", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    res.json(user);
  } catch (error) {
    console.log(error);
    res.status(500).send("Server error");
  }
});

router.post(
  "/",
  [
    check("email", "Please include valid email").isEmail(),
    check("password", "Password is required")
      .not()
      .isEmpty()
      .exists()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
      let user = await User.findOne({ email });
      if (!user) {
        return res
          .status(400)
          .json({ errors: [{ msg: "Invalid credentials" }] });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res
          .status(400)
          .json({ errors: [{ msg: "Invalid credentials" }] });
      }

      const payload = { user: { id: user.id } };
      const token = await jwt.sign(payload, config.get("jwtSecret"), {
        expiresIn: 360000
      });
      return res.json({ token });
    } catch (error) {
      console.log(error.message);
      res.status(500).send("Server error");
    }
  }
);
module.exports = router;
