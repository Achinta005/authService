import { Request, Response, NextFunction } from "express";
import { SupabaseAuthService } from "../services/superbaseAuthService";
import { UserProfileService } from "../services/userProfileService";
import { RoleService } from "../services/roleService";
import { AnalyticsService } from "../services/analyticsService";
import { ApiKeyService } from "../services/apiKeyService";
import { LoggerService } from "../lib/activityLogger";

export class AdminController {
  constructor(
    private supabaseAuth: SupabaseAuthService,
    private userProfileService: UserProfileService,
    private roleService: RoleService,
    private loggerService: LoggerService,
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

      res.json({ success: true, data: result });
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
      res.json({ success: true, data: profile });
    } catch (error: any) {
      next(error);
    }
  };

  updateUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { userId } = req.params;
      const adminId = (req as any).user.id;
      const updates = req.body;
      const resolvedId = Array.isArray(userId) ? userId[0] : userId;

      const profile = await this.userProfileService.updateProfile(
        resolvedId,
        updates,
      );

      await this.loggerService.createAuditLog({
        userId: resolvedId,
        action: "user.updated_by_admin",
        resource: "user",
        resourceId: resolvedId,
        performedBy: adminId,
        changes: { after: updates },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.loggerService.createActivityLog({
        userId: adminId,
        eventType: "admin_user_updated",
        eventCategory: "admin",
        eventLabel: "User Updated",
        page: "/admin/users",
        sessionId: req.cookies?.access_token || "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: {
          action: "admin_user_updated",
          targetUserId: resolvedId,
          updatedFields: Object.keys(updates),
        },
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "User updated successfully",
        data: profile,
      });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "admin_user_update_exception",
        severity: "medium",
        description: `Error updating user: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: {
          action: "admin_user_update_exception",
          targetUserId: req.params.userId,
        },
        timestamp: new Date(),
      });
      next(error);
    }
  };

  deactivateUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { userId } = req.params;
      const adminId = (req as any).user.id;
      const resolvedId = Array.isArray(userId) ? userId[0] : userId;

      await this.userProfileService.deactivateUser(resolvedId);

      await this.loggerService.createAuditLog({
        userId: resolvedId,
        action: "user.deactivated",
        resource: "user",
        resourceId: resolvedId,
        performedBy: adminId,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.loggerService.createSecurityEvent({
        userId: resolvedId,
        eventType: "user_deactivated_by_admin",
        severity: "medium",
        description: `User account deactivated by admin`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: true,
        metadata: {
          action: "user_deactivated_by_admin",
          deactivatedBy: adminId,
        },
        timestamp: new Date(),
      });

      await this.loggerService.createActivityLog({
        userId: adminId,
        eventType: "admin_user_deactivated",
        eventCategory: "admin",
        eventLabel: "User Deactivated",
        page: "/admin/users",
        sessionId: req.cookies?.access_token || "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: {
          action: "admin_user_deactivated",
          targetUserId: resolvedId,
        },
        timestamp: new Date(),
      });

      res.json({ success: true, message: "User deactivated successfully" });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "admin_user_deactivate_exception",
        severity: "medium",
        description: `Error deactivating user: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: {
          action: "admin_user_deactivate_exception",
          targetUserId: req.params.userId,
        },
        timestamp: new Date(),
      });
      next(error);
    }
  };

  activateUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { userId } = req.params;
      const adminId = (req as any).user.id;
      const resolvedId = Array.isArray(userId) ? userId[0] : userId;

      await this.userProfileService.activateUser(resolvedId);

      await this.loggerService.createAuditLog({
        userId: resolvedId,
        action: "user.activated",
        resource: "user",
        resourceId: resolvedId,
        performedBy: adminId,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.loggerService.createActivityLog({
        userId: adminId,
        eventType: "admin_user_activated",
        eventCategory: "admin",
        eventLabel: "User Activated",
        page: "/admin/users",
        sessionId: req.cookies?.access_token || "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { action: "admin_user_activated", targetUserId: resolvedId },
        timestamp: new Date(),
      });

      res.json({ success: true, message: "User activated successfully" });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "admin_user_activate_exception",
        severity: "medium",
        description: `Error activating user: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: {
          action: "admin_user_activate_exception",
          targetUserId: req.params.userId,
        },
        timestamp: new Date(),
      });
      next(error);
    }
  };

  deleteUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { userId } = req.params;
      const adminId = (req as any).user.id;
      const resolvedId = Array.isArray(userId) ? userId[0] : userId;

      const userProfile =
        await this.userProfileService.getProfileById(resolvedId);

      await this.supabaseAuth.deleteUser(resolvedId);
      await this.userProfileService.deleteProfile(resolvedId);

      await this.loggerService.createAuditLog({
        userId: resolvedId,
        action: "user.deleted",
        resource: "user",
        resourceId: resolvedId,
        performedBy: adminId,
        changes: {
          before: {
            email: userProfile?.email,
            fullName: userProfile?.fullName,
          },
        },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.loggerService.createSecurityEvent({
        userId: resolvedId,
        eventType: "user_deleted_by_admin",
        severity: "high",
        description: `User account "${userProfile?.email}" was deleted by admin`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: true,
        metadata: {
          action: "user_deleted_by_admin",
          deletedBy: adminId,
          deletedUserEmail: userProfile?.email,
          deletedUserName: userProfile?.fullName,
        },
        timestamp: new Date(),
      });

      await this.loggerService.createActivityLog({
        userId: adminId,
        eventType: "admin_user_deleted",
        eventCategory: "admin",
        eventLabel: "User Deleted",
        page: "/admin/users",
        sessionId: req.cookies?.access_token || "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: {
          action: "admin_user_deleted",
          targetUserId: resolvedId,
          deletedEmail: userProfile?.email,
          deletedName: userProfile?.fullName,
        },
        timestamp: new Date(),
      });

      res.json({ success: true, message: "User deleted successfully" });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "admin_user_delete_exception",
        severity: "high",
        description: `Error deleting user: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: {
          action: "admin_user_delete_exception",
          targetUserId: req.params.userId,
        },
        timestamp: new Date(),
      });
      next(error);
    }
  };

  // ============ ROLE MANAGEMENT ============
  assignRole = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { userId } = req.params;
      const { roleId, projectName, projectId } = req.body;
      const adminId = (req as any).user.id;
      const resolvedId = Array.isArray(userId) ? userId[0] : userId;

      await this.roleService.assignRoleToUser(
        resolvedId,
        roleId,
        projectId,
        projectName,
        adminId,
      );

      await this.loggerService.createAuditLog({
        userId: resolvedId,
        action: "role.assigned",
        resource: "user_role",
        resourceId: resolvedId,
        performedBy: adminId,
        metadata: { roleId },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.loggerService.createActivityLog({
        userId: adminId,
        eventType: "admin_role_assigned",
        eventCategory: "admin",
        eventLabel: "Role Assigned",
        page: "/admin/roles",
        sessionId: req.cookies?.access_token || "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: {
          action: "admin_role_assigned",
          targetUserId: resolvedId,
          roleId,
          projectName,
          projectId,
        },
        timestamp: new Date(),
      });

      res.json({ success: true, message: "Role assigned successfully" });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "admin_role_assign_exception",
        severity: "medium",
        description: `Error assigning role: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: {
          action: "admin_role_assign_exception",
          targetUserId: req.params.userId,
        },
        timestamp: new Date(),
      });
      next(error);
    }
  };

  removeRole = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { userId, roleId } = req.params;
      const adminId = (req as any).user.id;
      const resolvedUserId = Array.isArray(userId) ? userId[0] : userId;
      const resolvedRoleId = parseInt(
        Array.isArray(roleId) ? roleId[0] : roleId,
      );

      await this.roleService.removeRoleFromUser(resolvedUserId, resolvedRoleId);

      await this.loggerService.createAuditLog({
        userId: resolvedUserId,
        action: "role.removed",
        resource: "user_role",
        resourceId: resolvedUserId,
        performedBy: adminId,
        metadata: { roleId },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.loggerService.createActivityLog({
        userId: adminId,
        eventType: "admin_role_removed",
        eventCategory: "admin",
        eventLabel: "Role Removed",
        page: "/admin/roles",
        sessionId: req.cookies?.access_token || "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: {
          action: "admin_role_removed",
          targetUserId: resolvedUserId,
          roleId,
        },
        timestamp: new Date(),
      });

      res.json({ success: true, message: "Role removed successfully" });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "admin_role_remove_exception",
        severity: "medium",
        description: `Error removing role: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: {
          action: "admin_role_remove_exception",
          targetUserId: req.params.userId,
        },
        timestamp: new Date(),
      });
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
      res.json({ success: true, data: metrics });
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
      res.json({ success: true, data: stats });
    } catch (error: any) {
      next(error);
    }
  };

  getUserGrowth = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const days = parseInt(req.query.days as string) || 30;
      const growth = await this.userProfileService.getUserGrowth(days);
      res.json({ success: true, data: growth });
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

      const analytics = await this.analyticsService.getLoginAnalyticsByMethod(
        startDate,
        endDate,
      );
      res.json({ success: true, data: analytics });
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
      const events = await this.analyticsService.getAllSecurityEvents();
      res.json({ success: true, data: events });
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
      const ips = await this.analyticsService.getSuspiciousIPs(
        threshold,
        timeWindow,
      );
      res.json({ success: true, data: ips });
    } catch (error: any) {
      next(error);
    }
  };

  // ============ ROLE & PERMISSION MANAGEMENT ============
  getAllRoles = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const roles = await this.roleService.getAllRoles();
      res.json({ success: true, data: roles });
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

      await this.loggerService.createAuditLog({
        userId: adminId,
        action: "role.created",
        resource: "role",
        resourceId: role.id.toString(),
        changes: { after: { name, slug, description } },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.loggerService.createActivityLog({
        userId: adminId,
        eventType: "admin_role_created",
        eventCategory: "admin",
        eventLabel: "Role Created",
        page: "/admin/roles",
        sessionId: req.cookies?.access_token || "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { action: "admin_role_created", roleId: role.id, name, slug },
        timestamp: new Date(),
      });

      res
        .status(201)
        .json({
          success: true,
          message: "Role created successfully",
          data: role,
        });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "admin_role_create_exception",
        severity: "medium",
        description: `Error creating role: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: { action: "admin_role_create_exception" },
        timestamp: new Date(),
      });
      next(error);
    }
  };

  updateRole = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { roleId } = req.params;
      const updates = req.body;
      const adminId = (req as any).user.id;
      const resolvedRoleId = parseInt(
        Array.isArray(roleId) ? roleId[0] : roleId,
      );

      const role = await this.roleService.updateRole(resolvedRoleId, updates);

      await this.loggerService.createAuditLog({
        userId: adminId,
        action: "role.updated",
        resource: "role",
        resourceId: Array.isArray(roleId) ? roleId[0] : roleId,
        changes: { after: updates },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.loggerService.createActivityLog({
        userId: adminId,
        eventType: "admin_role_updated",
        eventCategory: "admin",
        eventLabel: "Role Updated",
        page: "/admin/roles",
        sessionId: req.cookies?.access_token || "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: {
          action: "admin_role_updated",
          roleId,
          updatedFields: Object.keys(updates),
        },
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "Role updated successfully",
        data: role,
      });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "admin_role_update_exception",
        severity: "medium",
        description: `Error updating role: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: {
          action: "admin_role_update_exception",
          roleId: req.params.roleId,
        },
        timestamp: new Date(),
      });
      next(error);
    }
  };

  deleteRole = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { roleId } = req.params;
      const adminId = (req as any).user.id;
      const resolvedRoleId = parseInt(
        Array.isArray(roleId) ? roleId[0] : roleId,
      );

      await this.roleService.deleteRole(resolvedRoleId);

      await this.loggerService.createAuditLog({
        userId: adminId,
        action: "role.deleted",
        resource: "role",
        resourceId: Array.isArray(roleId) ? roleId[0] : roleId,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.loggerService.createSecurityEvent({
        userId: adminId,
        eventType: "admin_role_deleted",
        severity: "high",
        description: `Role ${roleId} was deleted by admin`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: true,
        metadata: { action: "admin_role_deleted", roleId },
        timestamp: new Date(),
      });

      await this.loggerService.createActivityLog({
        userId: adminId,
        eventType: "admin_role_deleted",
        eventCategory: "admin",
        eventLabel: "Role Deleted",
        page: "/admin/roles",
        sessionId: req.cookies?.access_token || "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { action: "admin_role_deleted", roleId },
        timestamp: new Date(),
      });

      res.json({ success: true, message: "Role deleted successfully" });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "admin_role_delete_exception",
        severity: "medium",
        description: `Error deleting role: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: {
          action: "admin_role_delete_exception",
          roleId: req.params.roleId,
        },
        timestamp: new Date(),
      });
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
      res.json({ success: true, data: permissions });
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

      await this.loggerService.createAuditLog({
        userId: adminId,
        action: "permission.created",
        resource: "permission",
        resourceId: permission.id.toString(),
        changes: { after: { name, slug, resource, action } },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.loggerService.createActivityLog({
        userId: adminId,
        eventType: "admin_permission_created",
        eventCategory: "admin",
        eventLabel: "Permission Created",
        page: "/admin/permissions",
        sessionId: req.cookies?.access_token || "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: {
          action: "admin_permission_created",
          permissionId: permission.id,
          name,
          slug,
        },
        timestamp: new Date(),
      });

      res
        .status(201)
        .json({
          success: true,
          message: "Permission created successfully",
          data: permission,
        });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "admin_permission_create_exception",
        severity: "medium",
        description: `Error creating permission: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: { action: "admin_permission_create_exception" },
        timestamp: new Date(),
      });
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
      const resolvedRoleId = parseInt(
        Array.isArray(roleId) ? roleId[0] : roleId,
      );

      const role = await this.roleService.assignPermissionsToRole(
        resolvedRoleId,
        permissionIds,
      );

      await this.loggerService.createAuditLog({
        userId: adminId,
        action: "permissions.assigned",
        resource: "role",
        resourceId: Array.isArray(roleId) ? roleId[0] : roleId,
        metadata: { permissionIds },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.loggerService.createActivityLog({
        userId: adminId,
        eventType: "admin_permissions_assigned",
        eventCategory: "admin",
        eventLabel: "Permissions Assigned",
        page: "/admin/permissions",
        sessionId: req.cookies?.access_token || "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: {
          action: "admin_permissions_assigned",
          roleId,
          permissionIds,
        },
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "Permissions assigned successfully",
        data: role,
      });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "admin_permissions_assign_exception",
        severity: "medium",
        description: `Error assigning permissions: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: {
          action: "admin_permissions_assign_exception",
          roleId: req.params.roleId,
        },
        timestamp: new Date(),
      });
      next(error);
    }
  };

  getAllKeys = async (req: Request, res: Response) => {
    try {
      const keys = await this.apiKeyService.getAllApiKeys();
      return res.status(200).json({ success: true, data: keys });
    } catch (error: any) {
      return res.status(500).json({ success: false, message: error.message });
    }
  };

  createKey = async (req: Request, res: Response) => {
    try {
      const { serviceId } = req.params;
      const { name, scopes, expiresInDays, description } = req.body;
      const adminId = (req as any).user.id;
      const resolvedServiceId = Array.isArray(serviceId)
        ? serviceId[0]
        : serviceId;

      if (!name || !scopes || scopes.length === 0) {
        return res
          .status(400)
          .json({ success: false, message: "Name and scopes are required" });
      }

      const apiKey = await this.apiKeyService.createApiKey({
        name,
        serviceId: resolvedServiceId,
        scopes,
        expiresInDays: expiresInDays || 90,
        description,
      });

      await this.loggerService.createAuditLog({
        userId: adminId,
        action: "api_key.created",
        resource: "api_key",
        resourceId: apiKey.id,
        performedBy: adminId,
        changes: { after: { name, serviceId: resolvedServiceId, scopes } },
        metadata: {
          name,
          serviceId: resolvedServiceId,
          scopes,
          expiresInDays: expiresInDays || 90,
        },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.loggerService.createSecurityEvent({
        userId: adminId,
        eventType: "api_key_created",
        severity: "medium",
        description: `API key "${name}" created for service ${resolvedServiceId}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: true,
        metadata: {
          action: "api_key_created",
          apiKeyId: apiKey.id,
          name,
          scopes,
          serviceId: resolvedServiceId,
        },
        timestamp: new Date(),
      });

      await this.loggerService.createActivityLog({
        userId: adminId,
        eventType: "admin_api_key_created",
        eventCategory: "admin",
        eventLabel: "API Key Created",
        page: "/admin/keys",
        sessionId: req.cookies?.access_token || "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: {
          action: "admin_api_key_created",
          keyId: apiKey.id,
          name,
          serviceId,
          scopes,
        },
        timestamp: new Date(),
      });

      return res
        .status(201)
        .json({
          success: true,
          data: apiKey,
          message: "API key created successfully",
        });
    } catch (error: any) {
      return res.status(400).json({ success: false, message: error.message });
    }
  };

  deleteKey = async (req: Request, res: Response) => {
    try {
      const { keyId } = req.params;
      const adminId = (req as any).user.id;
      const resolvedKeyId = Array.isArray(keyId) ? keyId[0] : keyId;

      const keyDetails = await this.apiKeyService.getApiKeyById(resolvedKeyId);
      await this.apiKeyService.deleteApiKey(resolvedKeyId);

      await this.loggerService.createAuditLog({
        userId: adminId,
        action: "api_key.deleted",
        resource: "api_key",
        resourceId: resolvedKeyId,
        performedBy: adminId,
        changes: {
          before: { name: keyDetails?.name, serviceId: keyDetails?.serviceId },
        },
        metadata: {
          keyName: keyDetails?.name,
          serviceId: keyDetails?.serviceId,
        },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.loggerService.createSecurityEvent({
        userId: adminId,
        eventType: "api_key_deleted",
        severity: "high",
        description: `API key "${keyDetails?.name}" was deleted`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: true,
        metadata: {
          action: "api_key_deleted",
          keyId: resolvedKeyId,
          keyName: keyDetails?.name,
        },
        timestamp: new Date(),
      });

      await this.loggerService.createActivityLog({
        userId: adminId,
        eventType: "admin_api_key_deleted",
        eventCategory: "admin",
        eventLabel: "API Key Deleted",
        page: "/admin/keys",
        sessionId: req.cookies?.access_token || "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: {
          action: "admin_api_key_deleted",
          keyId,
          keyName: keyDetails?.name,
          serviceId: keyDetails?.serviceId,
        },
        timestamp: new Date(),
      });

      return res
        .status(200)
        .json({ success: true, message: "API key deleted successfully" });
    } catch (error: any) {
      return res.status(400).json({ success: false, message: error.message });
    }
  };

  rotateKey = async (req: Request, res: Response) => {
    try {
      const { keyId } = req.params;
      const adminId = (req as any).user.id;
      const resolvedKeyId = Array.isArray(keyId) ? keyId[0] : keyId;

      const apiKey = await this.apiKeyService.rotateApiKey(resolvedKeyId);

      await this.loggerService.createAuditLog({
        userId: adminId,
        action: "api_key.rotated",
        resource: "api_key",
        resourceId: resolvedKeyId,
        performedBy: adminId,
        changes: {
          before: { keyId: resolvedKeyId },
          after: { keyId: apiKey.id },
        },
        metadata: {
          keyName: apiKey.name,
          oldKeyId: resolvedKeyId,
          newKeyId: apiKey.id,
        },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.loggerService.createSecurityEvent({
        userId: adminId,
        eventType: "api_key_rotated",
        severity: "medium",
        description: `API key "${apiKey.name}" was rotated`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: true,
        metadata: {
          action: "api_key_rotated",
          oldKeyId: resolvedKeyId,
          newKeyId: apiKey.id,
        },
        timestamp: new Date(),
      });

      await this.loggerService.createActivityLog({
        userId: adminId,
        eventType: "admin_api_key_rotated",
        eventCategory: "admin",
        eventLabel: "API Key Rotated",
        page: "/admin/keys",
        sessionId: req.cookies?.access_token || "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: {
          action: "admin_api_key_rotated",
          oldKeyId: keyId,
          newKeyId: apiKey.id,
          keyName: apiKey.name,
        },
        timestamp: new Date(),
      });

      return res
        .status(200)
        .json({
          success: true,
          data: apiKey,
          message: "API key rotated successfully",
        });
    } catch (error: any) {
      return res.status(400).json({ success: false, message: error.message });
    }
  };

  validateKey = async (req: Request, res: Response) => {
    try {
      const { apiKey, serviceId } = req.body;

      if (!apiKey) {
        return res
          .status(400)
          .json({ success: false, message: "API key is required" });
      }

      if (!serviceId) {
        return res
          .status(400)
          .json({ success: false, message: "serviceId is required" });
      }

      const result = await this.apiKeyService.validateApiKey(apiKey, serviceId);

      if (!result.valid) {
        await this.loggerService.createSecurityEvent({
          eventType: "api_key_validation_failed",
          severity: "medium",
          description: `Invalid API key validation attempt: ${result.message}`,
          ipAddress: req.ip || "",
          userAgent: req.get("user-agent") || "",
          resolved: true,
          metadata: {
            action: "api_key_validation_failed",
            reason: result.message,
            attemptedKey: apiKey.substring(0, 10) + "...",
          },
          timestamp: new Date(),
        });

        return res
          .status(401)
          .json({ success: false, message: result.message });
      }

      return res
        .status(200)
        .json({
          success: true,
          message: "API key is valid",
          data: result.data,
        });
    } catch (error: any) {
      return res.status(500).json({ success: false, message: error.message });
    }
  };
}
