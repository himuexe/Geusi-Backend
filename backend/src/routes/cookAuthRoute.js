const express = require("express");
const {
  register,
  login,
  logout,
  me,
  refreshToken,
  changePassword,
  forgotPassword,
  resetPassword,
} = require("../controllers/cookAuthController");
const cookAuthMiddleware = require("../middleware/cookAuthMiddleware");

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/logout", logout);
router.get("/me", cookAuthMiddleware, me);
router.post("/refresh-token", refreshToken);
router.post("/change-password", cookAuthMiddleware, changePassword);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);

module.exports = router;


