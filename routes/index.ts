import { Router } from "express";
import createAuthRoutes from "./authRoute";
import mfaRoutes from "./MfaRoute";
import userRoutes from "./userRoute";
import roleRoutes from "./rolesRoutes";
import adminRoutes from "./adminRoutes";

const router = Router();

// API routes
router.use("/auth", createAuthRoutes());
router.use("/mfa", mfaRoutes);
router.use("/users", userRoutes);
router.use("/roles", roleRoutes);
router.use("/admin", adminRoutes);

export default router;
