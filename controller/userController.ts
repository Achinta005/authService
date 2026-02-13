import { Request, Response, NextFunction } from "express";
import { UserProfileService } from "../services/userProfileService";
import { LogService } from "../services/logService";

export class UserController {
  private userProfileService = new UserProfileService();
  private logService = new LogService();

  // ============ GET PROFILE ============
  getProfile = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;

      const profile = await this.userProfileService.getProfileById(userId);

      res.json({
        success: true,
        data: profile,
      });
    } catch (error: any) {
      next(error);
    }
  };

  // ============ UPDATE PROFILE ============
  updateProfile = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;

      const updates = { ...req.body };
      const auditChanges = { ...req.body };
      if (req.body.email && req.body.email !== undefined) {
        await this.logService.createSecurityEvent({
          userId,
          eventType: "unauthorized_email_change_attempt",
          severity: "medium",
          description:
            "User attempted to change email through profile update (restricted)",
          ipAddress: req.ip || "",
          userAgent: req.get("user-agent") || "",
          resolved: true,
          metadata: { attemptedEmail: req.body.email },
          timestamp: new Date(),
        });
      }
      // Remove restricted fields
      delete updates.id;
      delete updates.email;
      delete updates.isActive;
      delete updates.isEmailVerified;
      delete updates.isMfaEnabled;
      delete updates.createdAt;
      delete updates.updatedAt;

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({
          success: false,
          message: "No valid fields to update",
        });
      }

      const profile = await this.userProfileService.updateProfile(
        userId,
        updates,
      );

      await this.logService.createAuditLog({
        userId,
        action: "profile.updated",
        resource: "user",
        resourceId: userId,
        changes: {
          after: auditChanges,
        },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "Profile updated successfully",
        data: profile,
      });
    } catch (error) {
      next(error);
    }
  };

  // ========= UPDATE PROFILE PICTURE =========
  updateProfilePicture = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const userId = (req as any).user.id;
      const file = req.file;

      if (!file) {
        return res.status(400).json({
          success: false,
          message: "No file uploaded",
        });
      }

      // Upload and update profile picture
      const result = await this.userProfileService.uploadProfilePicture(
        file,
        userId,
      );

      // Log the action
      await this.logService.createAuditLog({
        userId,
        action: "profile_picture.updated",
        resource: "user",
        resourceId: userId,
        changes: {
          after: { avatarUrl: result.imageUrl },
        },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "Profile picture updated successfully",
        imageUrl: result.imageUrl,
        changed: result.changed,
      });
    } catch (error) {
      next(error);
    }
  };

  // ============ GET PREFERENCES ============
  getPreferences = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;

      const preferences = await this.userProfileService.getPreferences(userId);

      res.json({
        success: true,
        data: preferences,
      });
    } catch (error: any) {
      next(error);
    }
  };

  // ============ UPDATE PREFERENCES ============
  updatePreferences = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const userId = (req as any).user.id;
      const updates = req.body;

      // Validate that at least one preference field is provided
      const validPreferenceFields = [
        "theme",
        "visibility",
        "pushNotifications",
        "emailNotifications",
      ];
      const hasValidField = Object.keys(updates).some((key) =>
        validPreferenceFields.includes(key),
      );

      if (!hasValidField) {
        return res.status(400).json({
          success: false,
          message: "No valid preference fields to update",
        });
      }

      const preferences = await this.userProfileService.updatePreferences(
        userId,
        updates,
      );

      // Optional: Log preference changes for audit
      await this.logService.createAuditLog({
        userId,
        action: "preferences.updated",
        resource: "user_preferences",
        resourceId: userId,
        changes: {
          after: updates,
        },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "Preferences updated successfully",
        data: preferences,
      });
    } catch (error: any) {
      next(error);
    }
  };

  // ============ GET LOGIN HISTORY ============
  getLoginHistory = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 20;

      const result = await this.logService.getUserLoginHistory(
        userId,
        page,
        limit,
      );

      res.json({
        success: true,
        data: result,
      });
    } catch (error: any) {
      next(error);
    }
  };

  // ============ GET ACTIVITY LOGS ============
  getActivityLogs = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 50;

      const result = await this.logService.getUserAuditTrail(
        userId,
        page,
        limit,
      );

      res.json({
        success: true,
        data: result,
      });
    } catch (error: any) {
      next(error);
    }
  };

  // ============ GET ENGAGEMENT SCORE ============
  getEngagementScore = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const userId = (req as any).user.id;
      const days = parseInt(req.query.days as string) || 30;

      const score = await this.logService.calculateUserEngagementScore(
        userId,
        days,
      );

      res.json({
        success: true,
        data: score,
      });
    } catch (error: any) {
      next(error);
    }
  };
}
