// src/middlewares/authorize.ts
import { Request, Response, NextFunction } from "express";
import { RoleService } from "../services/roleService";

const roleService = new RoleService();

// Check if user has specific role
export const hasRole = (roles: string | string[]) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;
      const allowedRoles = Array.isArray(roles) ? roles : [roles];

      const hasRequiredRole = await roleService.hasAnyRole(
        userId,
        allowedRoles,
      );

      if (!hasRequiredRole) {
        return res.status(403).json({
          success: false,
          message: "Insufficient permissions",
        });
      }

      next();
    } catch (error: any) {
      return res.status(500).json({
        success: false,
        message: "Authorization check failed",
        error: error.message,
      });
    }
  };
};

// Check if user has specific permission
export const hasPermission = (permission: string) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;

      const hasRequiredPermission = await roleService.hasPermission(
        userId,
        permission,
      );
      if (!hasRequiredPermission) {
        return res.status(403).json({
          success: false,
          message: "Insufficient permissions",
        });
      }

      next();
    } catch (error: any) {
      return res.status(500).json({
        success: false,
        message: "Authorization check failed",
        error: error.message,
      });
    }
  };
};

// Check if user has any of the specified permissions
export const hasAnyPermission = (permissions: string[]) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;
      const userPermissions = await roleService.getUserPermissions(userId);

      const hasAny = permissions.some((perm) => userPermissions.includes(perm));

      if (!hasAny) {
        return res.status(403).json({
          success: false,
          message: "Insufficient permissions",
        });
      }

      next();
    } catch (error: any) {
      return res.status(500).json({
        success: false,
        message: "Authorization check failed",
        error: error.message,
      });
    }
  };
};
