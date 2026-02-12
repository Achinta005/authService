import { Router } from "express";
import { AuthController } from "../controller/authController";
import { SupabaseAuthService } from "../services/superbaseAuthService";
import { UserProfileService } from "../services/userProfileService";
import { RoleService } from "../services/roleService";
import { LogService } from "../services/logService";
import { ApiKeyMiddleware } from "../middlewares/apiKeyMiddleware";

import {
  registerValidator,
  loginValidator,
  forgotPasswordValidator,
  resetPasswordValidator,
  magicLinkValidator,
  logRegisterPayload,
} from "../validators/authValidators";

import { validateRequest } from "../middlewares/validateRequest";
import { authLimiter, passwordResetLimiter } from "../middlewares/rateLimitter";
import { authenticate } from "../middlewares/authenticate";

export const createAuthRoutes = () => {
  const router = Router();
  const apiKeyMiddleware = new ApiKeyMiddleware();

  const authController = new AuthController(
    new SupabaseAuthService(),
    new UserProfileService(),
    new RoleService(),
    new LogService(),
  );

  router.use((req, _res, next) => {
    console.log("🔐 Entered auth routes:", req.method, req.originalUrl);
    next();
  });

  router.get(
    "/verify-token",
    apiKeyMiddleware.requirePermission("admin"),
    authController.verifyToken,
  );

  // Public routes
  router.post(
    "/register",
    apiKeyMiddleware.requirePermission("admin"),
    authLimiter,
    registerValidator,
    validateRequest,
    authController.register,
  );

  router.post(
    "/login",
    apiKeyMiddleware.requirePermission("admin"),
    authLimiter,
    loginValidator,
    validateRequest,
    authController.login,
  );

  router.get(
    "/oauth/:provider",
    apiKeyMiddleware.requirePermission("admin"),
    authController.oauthLogin,
  );

  router.post(
    "/magic-link",
    apiKeyMiddleware.requirePermission("admin"),
    authLimiter,
    magicLinkValidator,
    validateRequest,
    authController.sendMagicLink,
  );

  router.post(
    "/forgot-password",
    apiKeyMiddleware.requirePermission("admin"),
    passwordResetLimiter,
    forgotPasswordValidator,
    validateRequest,
    authController.forgotPassword,
  );

  router.post(
    "/reset-password",
    apiKeyMiddleware.requirePermission("admin"),
    passwordResetLimiter,
    resetPasswordValidator,
    validateRequest,
    authController.resetPassword,
  );

  router.post(
    "/resend-verification",
    apiKeyMiddleware.requirePermission("admin"),
    authLimiter,
    magicLinkValidator,
    validateRequest,
    authController.resendVerification,
  );

  router.post(
    "/refresh",
    apiKeyMiddleware.requirePermission("admin"),
    authController.refreshToken,
  );

  // Protected routes
  router.post(
    "/logout",
    apiKeyMiddleware.requirePermission("admin"),
    authenticate,
    authController.logout,
  );

  return router;
};

export default createAuthRoutes;
