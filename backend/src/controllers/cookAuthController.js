const Chef = require("../models/Chef");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { sendPasswordResetEmail } = require("../services/emailService");

const generateAccessToken = (chefId) => {
  return jwt.sign({ userId: chefId }, process.env.JWT_ACCESS_SECRET, {
    expiresIn: "1h",
  });
};

const generateRefreshToken = (chefId) => {
  return jwt.sign({ userId: chefId }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: "30d",
  });
};

const register = async (req, res) => {
  try {
    const { firstName, lastName, email, phone, password } = req.body;

    if (!firstName || !lastName || !email || !phone || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (password.length < 8) {
      return res.status(400).json({ message: "Password must be at least 8 characters" });
    }

    const existingChef = await Chef.findOne({
      $or: [{ email }, { phone }],
    });

    if (existingChef) {
      if (existingChef.email === email) {
        return res.status(400).json({ message: "Email already registered" });
      }
      if (existingChef.phone === phone) {
        return res.status(400).json({ message: "Phone number already registered" });
      }
    }

    const chef = new Chef({
      firstName,
      lastName,
      email,
      phone,
      password,
    });

    await chef.save();

    const accessToken = generateAccessToken(chef._id);
    const refreshToken = generateRefreshToken(chef._id);

    chef.refreshToken = refreshToken;
    await chef.save();

    const chefResponse = {
      id: chef._id,
      firstName: chef.firstName,
      lastName: chef.lastName,
      email: chef.email,
      phone: chef.phone,
      accountStatus: chef.accountStatus,
      profileImage: chef.profileImage,
      cuisineSpecialty: chef.cuisineSpecialty,
      rating: chef.rating,
      isAvailable: chef.isAvailable,
      createdAt: chef.createdAt,
    };

    res.status(201).json({
      message: "Cook registered successfully",
      cook: chefResponse,
      accessToken,
      refreshToken,
    });
  } catch (error) {
    console.error("Cook registration error:", error);
    res.status(500).json({ message: "Registration failed", error: error.message });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const chef = await Chef.findOne({ email });

    if (!chef) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    if (chef.accountStatus !== "active") {
      return res.status(403).json({ message: "Account is not active" });
    }

    const isPasswordValid = await chef.comparePassword(password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const accessToken = generateAccessToken(chef._id);
    const refreshToken = generateRefreshToken(chef._id);

    chef.refreshToken = refreshToken;
    await chef.save();

    const chefResponse = {
      id: chef._id,
      firstName: chef.firstName,
      lastName: chef.lastName,
      email: chef.email,
      phone: chef.phone,
      accountStatus: chef.accountStatus,
      profileImage: chef.profileImage,
      cuisineSpecialty: chef.cuisineSpecialty,
      rating: chef.rating,
      isAvailable: chef.isAvailable,
    };

    res.status(200).json({
      message: "Login successful",
      cook: chefResponse,
      accessToken,
      refreshToken,
    });
  } catch (error) {
    console.error("Cook login error:", error);
    res.status(500).json({ message: "Login failed", error: error.message });
  }
};

const logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ message: "Refresh token required" });
    }

    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    const chef = await Chef.findById(decoded.userId);

    if (chef) {
      chef.refreshToken = null;
      await chef.save();
    }

    res.status(200).json({ message: "Logout successful" });
  } catch (error) {
    res.status(200).json({ message: "Logout successful" });
  }
};

const me = async (req, res) => {
  try {
    const chefResponse = {
      id: req.user._id,
      firstName: req.user.firstName,
      lastName: req.user.lastName,
      email: req.user.email,
      phone: req.user.phone,
      accountStatus: req.user.accountStatus,
      profileImage: req.user.profileImage,
      cuisineSpecialty: req.user.cuisineSpecialty,
      rating: req.user.rating,
      isAvailable: req.user.isAvailable,
      createdAt: req.user.createdAt,
      updatedAt: req.user.updatedAt,
    };

    res.status(200).json({ cook: chefResponse });
  } catch (error) {
    console.error("Get cook error:", error);
    res.status(500).json({ message: "Failed to get cook data", error: error.message });
  }
};

const refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ message: "Refresh token required" });
    }

    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    const chef = await Chef.findById(decoded.userId);

    if (!chef || chef.refreshToken !== refreshToken) {
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    if (chef.accountStatus !== "active") {
      return res.status(403).json({ message: "Account is not active" });
    }

    const newAccessToken = generateAccessToken(chef._id);
    const newRefreshToken = generateRefreshToken(chef._id);

    chef.refreshToken = newRefreshToken;
    await chef.save();

    res.status(200).json({
      message: "Token refreshed successfully",
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Refresh token expired" });
    }
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ message: "Invalid refresh token" });
    }
    res.status(500).json({ message: "Token refresh failed", error: error.message });
  }
};

const changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: "Current password and new password are required" });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ message: "New password must be at least 8 characters" });
    }

    const chef = await Chef.findById(req.user._id);

    const isPasswordValid = await chef.comparePassword(currentPassword);

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Current password is incorrect" });
    }

    chef.password = newPassword;
    chef.refreshToken = null;
    await chef.save();

    res.status(200).json({ message: "Password changed successfully. Please login again." });
  } catch (error) {
    console.error("Cook change password error:", error);
    res.status(500).json({ message: "Password change failed", error: error.message });
  }
};

const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const chef = await Chef.findOne({ email });

    if (!chef) {
      return res.status(200).json({ message: "If the email exists, a reset link has been sent" });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex");

    chef.resetPasswordToken = hashedToken;
    chef.resetPasswordExpires = Date.now() + 3600000;
    await chef.save();

    const cookName = `${chef.firstName} ${chef.lastName}`;
    const emailResult = await sendPasswordResetEmail(email, resetToken, cookName);

    if (!emailResult.success) {
      chef.resetPasswordToken = null;
      chef.resetPasswordExpires = null;
      await chef.save();
      return res.status(500).json({ message: "Failed to send reset email. Please try again later." });
    }

    res.status(200).json({
      message: "Password reset link has been sent to your email",
    });
  } catch (error) {
    console.error("Cook forgot password error:", error);
    res.status(500).json({ message: "Failed to process request", error: error.message });
  }
};

const resetPassword = async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ message: "Token and new password are required" });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ message: "Password must be at least 8 characters" });
    }

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const chef = await Chef.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!chef) {
      return res.status(400).json({ message: "Invalid or expired reset token" });
    }

    chef.password = newPassword;
    chef.resetPasswordToken = null;
    chef.resetPasswordExpires = null;
    chef.refreshToken = null;
    await chef.save();

    res.status(200).json({ message: "Password reset successful. Please login with your new password." });
  } catch (error) {
    console.error("Cook reset password error:", error);
    res.status(500).json({ message: "Password reset failed", error: error.message });
  }
};

module.exports = {
  register,
  login,
  logout,
  me,
  refreshToken,
  changePassword,
  forgotPassword,
  resetPassword,
};


