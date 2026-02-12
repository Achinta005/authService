import { Request, Response, NextFunction } from 'express';
import { RoleService } from '../services/roleService';

export class RoleController {
  private roleService = new RoleService();

  // ============ GET USER ROLES ============
  getUserRoles = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;

      const roles = await this.roleService.getUserRoles(userId);

      res.json({
        success: true,
        data: roles,
      });
    } catch (error: any) {
      next(error);
    }
  };

  // ============ GET USER PERMISSIONS ============
  getUserPermissions = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;

      const permissions = await this.roleService.getUserPermissions(userId);

      res.json({
        success: true,
        data: permissions,
      });
    } catch (error: any) {
      next(error);
    }
  };

  // ============ CHECK PERMISSION ============
  checkPermission = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;
      const permission = Array.isArray(req.params.permission)
        ? req.params.permission[0]
        : req.params.permission;

      const hasPermission = await this.roleService.hasPermission(
        userId,
        permission
      );

      res.json({
        success: true,
        data: { hasPermission },
      });
    } catch (error: any) {
      next(error);
    }
  };
}