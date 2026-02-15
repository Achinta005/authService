import { Router } from "express";
import { AdminController } from "../controller/adminController";
import { authenticate } from "../middlewares/authenticate";
import { hasRole, hasPermission } from "../middlewares/authorize";
import { body, param } from "express-validator";
import { validateRequest } from "../middlewares/validateRequest";
import { SupabaseAuthService } from "../services/superbaseAuthService";
import { UserProfileService } from "../services/userProfileService";
import { RoleService } from "../services/roleService";
import { LogService } from "../services/logService";
import { AnalyticsService } from "../services/analyticsService";
import { ApiKeyService } from "../services/apiKeyService";
import { ApiKeyMiddleware } from "../middlewares/apiKeyMiddleware";

const router = Router();
const apiKeyMiddleware = new ApiKeyMiddleware();
const adminController = new AdminController(
  new SupabaseAuthService(),
  new UserProfileService(),
  new RoleService(),
  new LogService(),
  new AnalyticsService(),
  new ApiKeyService(),
);

// All admin routes require authentication and admin role
router.use(authenticate);
router.use(hasRole("admin"));

// ============ USER MANAGEMENT ============
router.get(
  "/users",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("users.read"),
  adminController.getAllUsers,
);

router.get(
  "/users/:userId",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("users.read"),
  adminController.getUserById,
);

//This endpoint is for changing user profile info(Not usefull)
router.put(
  "/users/:userId",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("users.update"),
  adminController.updateUser,
);

router.post(
  "/users/:userId/deactivate",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("users.manage"),
  adminController.deactivateUser,
);

router.post(
  "/users/:userId/activate",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("users.manage"),
  adminController.activateUser,
);

router.delete(
  "/users/:userId",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("users.delete"),
  adminController.deleteUser,
);

// ============ ROLE ASSIGNMENT ============
router.post(
  "/users/:userId/roles",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("users.manage"),
  [body("roleId").isInt().withMessage("Role ID must be an integer")],
  validateRequest,
  adminController.assignRole,
);

router.delete(
  "/users/:userId/roles/:roleId",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("users.manage"),
  adminController.removeRole,
);

// ============ ROLE MANAGEMENT ============
router.get(
  "/roles",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("roles.read"),
  adminController.getAllRoles,
);

router.post(
  "/roles",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("roles.manage"),
  [
    body("name").notEmpty().withMessage("Role name is required"),
    body("slug").notEmpty().withMessage("Role slug is required"),
  ],
  validateRequest,
  adminController.createRole,
);

router.put(
  "/roles/:roleId",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("roles.manage"),
  adminController.updateRole,
);

router.delete(
  "/roles/:roleId",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("roles.manage"),
  adminController.deleteRole,
);

// ============ PERMISSION MANAGEMENT ============
router.get(
  "/permissions",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("roles.read"),
  adminController.getAllPermissions,
);

router.post(
  "/permissions",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("create.permission"),
  adminController.createPermission,
);

router.post(
  "/roles/:roleId/permissions",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("roles.manage"),
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
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("analytics.view"),
  adminController.getDashboardMetrics,
);

router.get(
  "/analytics/user-statistics",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("analytics.view"),
  adminController.getUserStatistics,
);

router.get(
  "/analytics/user-growth",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("analytics.view"),
  adminController.getUserGrowth,
);

router.get(
  "/analytics/login-analytics",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("analytics.view"),
  adminController.getLoginAnalytics,
);

router.get(
  "/analytics/security-events",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("analytics.view"),
  adminController.getSecurityEvents,
);

router.get(
  "/analytics/suspicious-ips",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("analytics.view"),
  adminController.getSuspiciousIPs,
);

// ============ API KEY Management ============
router.get(
  "/api/keys",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("api.key.manage"),
  adminController.getAllKeys,
);

router.post('/api/valid',
  apiKeyMiddleware.requirePermission("admin"),
  adminController.validateKey
)

router.post(
  "/api/keys/:serviceId",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("api.key.manage"),
  adminController.createKey,
);

router.delete(
  "/api/keys/:serviceId/:keyId",
  apiKeyMiddleware.requirePermission("admin"),
  hasPermission("api.key.manage"),
  adminController.deleteKey,
);

export default router;
