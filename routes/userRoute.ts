import { Router } from "express";
import { UserController } from "../controller/userController";
import { authenticate } from "../middlewares/authenticate";
import {
  updateProfileValidator,
  updatePreferencesValidator,
} from "../validators/authValidators";
import { validateRequest } from "../middlewares/validateRequest";
import { uploadConfig } from "../config/multerConfig";
import { ApiKeyMiddleware } from "../middlewares/apiKeyMiddleware";

const router = Router();
const userController = new UserController();
const apiKeyMiddleware = new ApiKeyMiddleware();

// All user routes require authentication
router.use(authenticate);

// Profile routes
router.post(
  "/profile/image",
  apiKeyMiddleware.requirePermission("admin"),
  uploadConfig.single("profilePic"),
  userController.updateProfilePicture,
);

router.get(
  "/profile",
  apiKeyMiddleware.requirePermission("admin"),
  userController.getProfile,
);

router.patch(
  "/profile",
  apiKeyMiddleware.requirePermission("admin"),
  updateProfileValidator,
  validateRequest,
  userController.updateProfile,
);

// Preferences routes
router.get(
  "/preferences",
  apiKeyMiddleware.requirePermission("admin"),
  userController.getPreferences,
);

router.patch(
  "/preferences",
  apiKeyMiddleware.requirePermission("admin"),
  updatePreferencesValidator,
  validateRequest,
  userController.updatePreferences,
);

// History & logs
router.get(
  "/login-history",
  apiKeyMiddleware.requirePermission("admin"),
  userController.getLoginHistory,
);
router.get(
  "/activity-logs",
  apiKeyMiddleware.requirePermission("admin"),
  userController.getActivityLogs,
);

// Engagement
router.get(
  "/engagement-score",
  apiKeyMiddleware.requirePermission("admin"),
  userController.getEngagementScore,
);

export default router;
