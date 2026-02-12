import { Router } from "express";
import { RoleController } from "../controller/roleController";
import { authenticate } from "../middlewares/authenticate";
import { ApiKeyMiddleware } from "../middlewares/apiKeyMiddleware";

const router = Router();
const roleController = new RoleController();
const apiKeyMiddleware = new ApiKeyMiddleware();

// All role routes require authentication
router.use(authenticate);

router.get("/my-roles", roleController.getUserRoles);
router.get("/my-permissions", roleController.getUserPermissions);
router.get("/check/:permission", roleController.checkPermission);

export default router;
