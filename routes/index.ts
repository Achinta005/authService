import { Router } from "express";
import createAuthRoutes from "./authRoute";
import mfaRoutes from "./MfaRoute";
import userRoutes from "./userRoute";
import roleRoutes from "./rolesRoutes";
import adminRoutes from "./adminRoutes";

const router = Router();

// Health check
router.get("/health", (req, res) => {
  res.json({
    success: true,
    message: "Auth microservice is running",
    timestamp: new Date().toISOString(),
  });
});

// API routes
router.use("/auth", createAuthRoutes());
router.use("/mfa", mfaRoutes);
router.use("/users", userRoutes);
router.use("/roles", roleRoutes);
router.use("/admin", adminRoutes);

export default router;
