import { Request, Response, NextFunction } from "express";
import { SupabaseAuthService } from "../services/superbaseAuthService";
import { UserProfileService } from "../services/userProfileService";
import { RoleService } from "../services/roleService";
import { LogService } from "../services/logService";
import { AnalyticsService } from "../services/analyticsService";
import { ApiKeyService } from "../services/apiKeyService";

export class AdminController {
  constructor(
    private supabaseAuth: SupabaseAuthService,
    private userProfileService: UserProfileService,
    private roleService: RoleService,
    private logService: LogService,
    private analyticsService: AnalyticsService,
    private apiKeyService: ApiKeyService,
  ) {
    this.apiKeyService = new ApiKeyService();
  }

  // ============ USER MANAGEMENT ============
  getAllUsers = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 20;
      const filters = {
        isActive:
          req.query.isActive === "true"
            ? true
            : req.query.isActive === "false"
              ? false
              : undefined,
        search: req.query.search as string,
        role: req.query.role as string,
      };

      const result = await this.userProfileService.getAllProfiles(
        page,
        limit,
        filters,
      );

      res.json({
        success: true,
        data: result,
      });
    } catch (error: any) {
      next(error);
    }
  };

  getUserById = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { userId } = req.params;

      const profile = await this.userProfileService.getProfileById(
        userId as string,
      );

      res.json({
        success: true,
        data: profile,
      });
    } catch (error: any) {
      next(error);
    }
  };

  updateUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { userId } = req.params;
      const adminId = (req as any).user.id;
      const updates = req.body;

      const profile = await this.userProfileService.updateProfile(
        userId as string,
        updates,
      );

      // Log audit event
      await this.logService.createAuditLog({
        userId: Array.isArray(userId) ? userId[0] : userId,
        action: "user.updated_by_admin",
        resource: "user",
        resourceId: Array.isArray(userId) ? userId[0] : userId,
        performedBy: adminId,
        changes: {
          after: updates,
        },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "User updated successfully",
        data: profile,
      });
    } catch (error: any) {
      next(error);
    }
  };

  deactivateUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { userId } = req.params;
      const adminId = (req as any).user.id;

      await this.userProfileService.deactivateUser(
        Array.isArray(userId) ? userId[0] : userId,
      );

      // Log audit event
      await this.logService.createAuditLog({
        userId: Array.isArray(userId) ? userId[0] : userId,
        action: "user.deactivated",
        resource: "user",
        resourceId: Array.isArray(userId) ? userId[0] : userId,
        performedBy: adminId,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "User deactivated successfully",
      });
    } catch (error: any) {
      next(error);
    }
  };

  activateUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { userId } = req.params;
      const adminId = (req as any).user.id;

      await this.userProfileService.activateUser(
        Array.isArray(userId) ? userId[0] : userId,
      );

      // Log audit event
      await this.logService.createAuditLog({
        userId: Array.isArray(userId) ? userId[0] : userId,
        action: "user.activated",
        resource: "user",
        resourceId: Array.isArray(userId) ? userId[0] : userId,
        performedBy: adminId,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "User activated successfully",
      });
    } catch (error: any) {
      next(error);
    }
  };

  deleteUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { userId } = req.params;
      const adminId = (req as any).user.id;

      // Delete from Supabase
      await this.supabaseAuth.deleteUser(
        Array.isArray(userId) ? userId[0] : userId,
      );

      // Delete profile
      await this.userProfileService.deleteProfile(
        Array.isArray(userId) ? userId[0] : userId,
      );

      // Log audit event
      await this.logService.createAuditLog({
        userId: Array.isArray(userId) ? userId[0] : userId,
        action: "user.deleted",
        resource: "user",
        resourceId: Array.isArray(userId) ? userId[0] : userId,
        performedBy: adminId,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "User deleted successfully",
      });
    } catch (error: any) {
      next(error);
    }
  };

  // ============ ROLE MANAGEMENT ============
  assignRole = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { userId } = req.params;
      const { roleId } = req.body;
      const adminId = (req as any).user.id;

      await this.roleService.assignRoleToUser(
        Array.isArray(userId) ? userId[0] : userId,
        roleId,
        adminId,
      );

      // Log audit event
      await this.logService.createAuditLog({
        userId: Array.isArray(userId) ? userId[0] : userId,
        action: "role.assigned",
        resource: "user_role",
        resourceId: Array.isArray(userId) ? userId[0] : userId,
        performedBy: adminId,
        metadata: { roleId },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "Role assigned successfully",
      });
    } catch (error: any) {
      next(error);
    }
  };

  removeRole = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { userId, roleId } = req.params;
      const adminId = (req as any).user.id;

      await this.roleService.removeRoleFromUser(
        Array.isArray(userId) ? userId[0] : userId,
        parseInt(Array.isArray(roleId) ? roleId[0] : roleId),
      );

      // Log audit event
      await this.logService.createAuditLog({
        userId: Array.isArray(userId) ? userId[0] : userId,
        action: "role.removed",
        resource: "user_role",
        resourceId: Array.isArray(userId) ? userId[0] : userId,
        performedBy: adminId,
        metadata: { roleId },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "Role removed successfully",
      });
    } catch (error: any) {
      next(error);
    }
  };

  // ============ ANALYTICS ============
  getDashboardMetrics = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const days = parseInt(req.query.days as string) || 30;
      const endDate = new Date();
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - days);

      const metrics = await this.analyticsService.getDashboardMetrics(
        startDate,
        endDate,
      );

      res.json({
        success: true,
        data: metrics,
      });
    } catch (error: any) {
      next(error);
    }
  };

  getUserStatistics = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const stats = await this.userProfileService.getUserStatistics();

      res.json({
        success: true,
        data: stats,
      });
    } catch (error: any) {
      next(error);
    }
  };

  getUserGrowth = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const days = parseInt(req.query.days as string) || 30;

      const growth = await this.userProfileService.getUserGrowth(days);

      res.json({
        success: true,
        data: growth,
      });
    } catch (error: any) {
      next(error);
    }
  };

  getLoginAnalytics = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const days = parseInt(req.query.days as string) || 30;
      const endDate = new Date();
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - days);

      const analytics = await this.logService.getLoginAnalyticsByMethod(
        startDate,
        endDate,
      );
      res.json({
        success: true,
        data: analytics,
      });
    } catch (error: any) {
      next(error);
    }
  };

  getSecurityEvents = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const events = await this.logService.getUnresolvedSecurityEvents();

      res.json({
        success: true,
        data: events,
      });
    } catch (error: any) {
      next(error);
    }
  };

  getSuspiciousIPs = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const threshold = parseInt(req.query.threshold as string) || 5;
      const timeWindow = parseInt(req.query.timeWindow as string) || 3600000;

      const ips = await this.logService.getSuspiciousIPs(threshold, timeWindow);

      res.json({
        success: true,
        data: ips,
      });
    } catch (error: any) {
      next(error);
    }
  };

  // ============ ROLE & PERMISSION MANAGEMENT ============
  getAllRoles = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const roles = await this.roleService.getAllRoles();

      res.json({
        success: true,
        data: roles,
      });
    } catch (error: any) {
      next(error);
    }
  };

  createRole = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { name, slug, description } = req.body;
      const adminId = (req as any).user.id;

      const role = await this.roleService.createRole({
        name,
        slug,
        description,
      });

      // Log audit event
      await this.logService.createAuditLog({
        userId: adminId,
        action: "role.created",
        resource: "role",
        resourceId: role.id.toString(),
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      res.status(201).json({
        success: true,
        message: "Role created successfully",
        data: role,
      });
    } catch (error: any) {
      next(error);
    }
  };

  updateRole = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { roleId } = req.params;
      const updates = req.body;
      const adminId = (req as any).user.id;

      const role = await this.roleService.updateRole(
        parseInt(Array.isArray(roleId) ? roleId[0] : roleId),
        updates,
      );

      // Log audit event
      await this.logService.createAuditLog({
        userId: adminId,
        action: "role.updated",
        resource: "role",
        resourceId: Array.isArray(roleId) ? roleId[0] : roleId,
        changes: { after: updates },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "Role updated successfully",
        data: role,
      });
    } catch (error: any) {
      next(error);
    }
  };

  deleteRole = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { roleId } = req.params;
      const adminId = (req as any).user.id;

      await this.roleService.deleteRole(
        parseInt(Array.isArray(roleId) ? roleId[0] : roleId),
      );

      // Log audit event
      await this.logService.createAuditLog({
        userId: adminId,
        action: "role.deleted",
        resource: "role",
        resourceId: Array.isArray(roleId) ? roleId[0] : roleId,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "Role deleted successfully",
      });
    } catch (error: any) {
      next(error);
    }
  };

  getAllPermissions = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const permissions = await this.roleService.getAllPermissions();

      res.json({
        success: true,
        data: permissions,
      });
    } catch (error: any) {
      next(error);
    }
  };

  createPermission = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const { name, slug, description, resource, action } = req.body;
      const adminId = (req as any).user.id;

      const permission = await this.roleService.createPermission({
        name,
        slug,
        resource,
        action,
        description,
      });

      await this.logService.createAuditLog({
        userId: adminId,
        action: "permission.created",
        resource: "permission",
        resourceId: permission.id.toString(),
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      res.status(201).json({
        success: true,
        message: "Permission created successfully",
        data: permission,
      });
    } catch (error) {
      next(error);
    }
  };

  assignPermissions = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const { roleId } = req.params;
      const { permissionIds } = req.body;
      const adminId = (req as any).user.id;

      const role = await this.roleService.assignPermissionsToRole(
        parseInt(Array.isArray(roleId) ? roleId[0] : roleId),
        permissionIds,
      );

      // Log audit event
      await this.logService.createAuditLog({
        userId: adminId,
        action: "permissions.assigned",
        resource: "role",
        resourceId: Array.isArray(roleId) ? roleId[0] : roleId,
        metadata: { permissionIds },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "Permissions assigned successfully",
        data: role,
      });
    } catch (error: any) {
      next(error);
    }
  };

  getAllKeys = async (req: Request, res: Response) => {
    try {
      const keys = await this.apiKeyService.getAllApiKeys();
      return res.status(200).json({
        success: true,
        data: keys,
      });
    } catch (error: any) {
      console.error("❌ [getAllKeys] error:", error);
      return res.status(500).json({
        success: false,
        message: error.message,
      });
    }
  };

  createKey = async (req: Request, res: Response) => {
    try {
      const { serviceId } = req.params;
      const { name, scopes, expiresInDays, description } = req.body;

      // Validate required fields
      if (!name || !scopes || scopes.length === 0) {
        return res.status(400).json({
          success: false,
          message: "Name and scopes are required",
        });
      }

      const apiKey = await this.apiKeyService.createApiKey({
        name,
        serviceId: Array.isArray(serviceId) ? serviceId[0] : serviceId,
        scopes,
        expiresInDays: expiresInDays || 90,
        description,
      });

      return res.status(201).json({
        success: true,
        data: apiKey,
        message: "API key created successfully",
      });
    } catch (error: any) {
      return res.status(400).json({
        success: false,
        message: error.message,
      });
    }
  };

  deleteKey = async (req: Request, res: Response) => {
    try {
      const { keyId } = req.params;

      await this.apiKeyService.deleteApiKey(
        Array.isArray(keyId) ? keyId[0] : keyId,
      );

      return res.status(200).json({
        success: true,
        message: "API key deleted successfully",
      });
    } catch (error: any) {
      return res.status(400).json({
        success: false,
        message: error.message,
      });
    }
  };

  // POST /api/keys/:keyId/rotate - Rotate API key
  rotateKey = async (req: Request, res: Response) => {
    try {
      const { keyId } = req.params;

      const apiKey = await this.apiKeyService.rotateApiKey(
        Array.isArray(keyId) ? keyId[0] : keyId,
      );

      return res.status(200).json({
        success: true,
        data: apiKey,
        message: "API key rotated successfully",
      });
    } catch (error: any) {
      return res.status(400).json({
        success: false,
        message: error.message,
      });
    }
  };

  // POST /api/keys/validate - Validate API key and return permissions
  validateKey = async (req: Request, res: Response) => {
    try {
      const { apiKey } = req.body;

      if (!apiKey) {
        return res.status(400).json({
          success: false,
          message: "API key is required",
        });
      }

      const result = await this.apiKeyService.validateApiKey(apiKey);

      if (!result.valid) {
        return res.status(401).json({
          success: false,
          message: result.message,
        });
      }

      return res.status(200).json({
        success: true,
        message: "API key is valid",
        data: result.data,
      });
    } catch (error: any) {
      console.error("❌ [validateKey] error:", error);
      return res.status(500).json({
        success: false,
        message: error.message,
      });
    }
  };
}
