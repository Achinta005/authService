import { Router } from "express";
import { AdminController } from "../controller/adminController";
import { authenticate } from "../middlewares/authenticate";
import { hasRole, hasPermission } from "../middlewares/authorize";
import { body, param } from "express-validator";
import { validateRequest } from "../middlewares/validateRequest";
import { SupabaseAuthService } from "../services/superbaseAuthService";
import { UserProfileService } from "../services/userProfileService";
import { RoleService } from "../services/roleService";
import { AnalyticsService } from "../services/analyticsService";
import { ApiKeyService } from "../services/apiKeyService";
import { ApiKeyMiddleware } from "../middlewares/apiKeyMiddleware";
import { LoggerService } from "../lib/activityLogger";

const router = Router();
const apiKeyMiddleware = new ApiKeyMiddleware();
const adminController = new AdminController(
  new SupabaseAuthService(),
  new UserProfileService(),
  new RoleService(),
  new LoggerService(),
  new AnalyticsService(),
  new ApiKeyService(),
);

// ============ USER MANAGEMENT ============
router.get(
  "/users",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("users.read"),
  hasRole("admin"),
  adminController.getAllUsers,
);

router.get(
  "/users/:userId",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("users.read"),
  hasRole("admin"),
  adminController.getUserById,
);

//This endpoint is for changing user profile info(Not usefull)
router.put(
  "/users/:userId",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("users.update"),
  hasRole("admin"),
  adminController.updateUser,
);

router.post(
  "/users/:userId/deactivate",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("users.manage"),
  hasRole("admin"),
  adminController.deactivateUser,
);

router.post(
  "/users/:userId/activate",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("users.manage"),
  hasRole("admin"),
  adminController.activateUser,
);

router.delete(
  "/users/:userId",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("users.delete"),
  hasRole("admin"),
  adminController.deleteUser,
);

// ============ ROLE ASSIGNMENT ============
router.post(
  "/users/:userId/roles",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("users.manage"),
  [body("roleId").isInt().withMessage("Role ID must be an integer")],
  validateRequest,
  hasRole("admin"),
  adminController.assignRole,
);

router.delete(
  "/users/:userId/roles/:roleId",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("users.manage"),
  hasRole("admin"),
  adminController.removeRole,
);

// ============ ROLE MANAGEMENT ============
router.get(
  "/roles",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("roles.read"),
  hasRole("admin"),
  adminController.getAllRoles,
);

router.post(
  "/roles",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("roles.manage"),
  [
    body("name").notEmpty().withMessage("Role name is required"),
    body("slug").notEmpty().withMessage("Role slug is required"),
  ],
  validateRequest,
  hasRole("admin"),
  adminController.createRole,
);

router.put(
  "/roles/:roleId",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("roles.manage"),
  hasRole("admin"),
  adminController.updateRole,
);

router.delete(
  "/roles/:roleId",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("roles.manage"),
  hasRole("admin"),
  adminController.deleteRole,
);

// ============ PERMISSION MANAGEMENT ============
router.get(
  "/permissions",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("roles.read"),
  hasRole("admin"),
  adminController.getAllPermissions,
);

router.post(
  "/permissions",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("create.permission"),
  hasRole("admin"),
  adminController.createPermission,
);

router.post(
  "/roles/:roleId/permissions",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("roles.manage"),
  hasRole("admin"),
  [
    body("permissionIds")
      .isArray()
      .withMessage("Permission IDs must be an array"),
  ],
  validateRequest,
  adminController.assignPermissions,
);

// ============ ANALYTICS ============
router.get(
  "/analytics/dashboard",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasRole("admin"),
  hasPermission("analytics.view"),
  adminController.getDashboardMetrics,
);

router.get(
  "/analytics/user-statistics",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasRole("admin"),
  hasPermission("analytics.view"),
  adminController.getUserStatistics,
);

router.get(
  "/analytics/user-growth",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasRole("admin"),
  hasPermission("analytics.view"),
  adminController.getUserGrowth,
);

router.get(
  "/analytics/login-analytics",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasRole("admin"),
  hasPermission("analytics.view"),
  adminController.getLoginAnalytics,
);

router.get(
  "/analytics/security-events",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasRole("admin"),
  hasPermission("analytics.view"),
  adminController.getSecurityEvents,
);

router.get(
  "/analytics/suspicious-ips",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasRole("admin"),
  hasPermission("analytics.view"),
  adminController.getSuspiciousIPs,
);

// ============ API KEY Management ============
router.get(
  "/api/keys",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("api.key.manage"),
  hasRole("admin"),
  adminController.getAllKeys,
);

router.post(
  "/api/keys/:serviceId",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("api.key.manage"),
  hasRole("admin"),
  adminController.createKey,
);

router.delete(
  "/api/keys/:serviceId/:keyId",
  authenticate,
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("api.key.manage"),
  hasRole("admin"),
  adminController.deleteKey,
);

export default router;
