const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const mongoose = require("mongoose");
const helmet = require("helmet");
const morgan = require("morgan");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 9000;

// Middleware
app.use(helmet());
app.use(morgan("combined"));
app.use(express.json());
app.use(cookieParser());
app.use(
    cors({
        credentials: true,
    })
);
app.use(express.urlencoded({ extended: true }));

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(err.status || 500).json({ message: err.message || "Something went wrong!" });
});

// Database connection
const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_CONNECTION_STRING);
        console.log("Connected to Database");
    } catch (err) {
        console.error("Database connection error:", err);
        process.exit(1);
    }
};
connectDB();

// Health Check Route
app.get("/api/health", async (req, res) => {
    try {
        await mongoose.connection.db.admin().ping();
        res.status(200).json({
            status: "healthy",
            message: "Server and database are running smoothly.",
            timestamp: new Date().toISOString(),
        });
    } catch (error) {
        console.error("Health check failed:", error);
        res.status(500).json({
            status: "unhealthy",
            message: "Server or database is not functioning properly.",
            error: error.message,
            timestamp: new Date().toISOString(),
        });
    }
});

// Routes 
const authRouter = require("./routes/authRoute");
const orderRouter = require("./routes/orderRoute");
const cookAuthRouter = require("./routes/cookAuthRoute");

app.use("/api/auth", authRouter);
app.use("/api/cook-auth", cookAuthRouter);
app.use("/api/orders", orderRouter);

const server = app.listen(PORT, () => {
    console.log(`Server running on Port: ${PORT}`);
});

const shutdown = () => {
    server.close(() => {
        console.log("Server closed");
        mongoose.connection.close(() => {
            console.log("Database connection closed");
            process.exit(0);
        });
    });
};

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);