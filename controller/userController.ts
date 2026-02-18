import { Request, Response, NextFunction } from "express";
import { UserProfileService } from "../services/userProfileService";
import { AnalyticsService } from "../services/analyticsService";
import { LoggerService } from "../lib/activityLogger";

export class UserController {
  private userProfileService = new UserProfileService();
  private analyticService = new AnalyticsService();
  private loggerService = new LoggerService();

  getProfile = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;
      const profile = await this.userProfileService.getProfileById(userId);
      res.json({ success: true, data: profile });
    } catch (error: any) {
      next(error);
    }
  };

  updateProfile = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;
      const updates = { ...req.body };
      const auditChanges = { ...req.body };

      if (req.body.email) {
        await this.loggerService.createSecurityEvent({
          userId,
          eventType: "unauthorized_email_change_attempt",
          severity: "medium",
          description:
            "User attempted to change email through profile update (restricted)",
          ipAddress: req.ip || "",
          userAgent: req.get("user-agent") || "",
          resolved: true,
          metadata: {
            action: "unauthorized_email_change_attempt",
            attemptedEmail: req.body.email,
          },
          timestamp: new Date(),
        });
      }

      delete updates.id;
      delete updates.email;
      delete updates.isActive;
      delete updates.isEmailVerified;
      delete updates.isMfaEnabled;
      delete updates.createdAt;
      delete updates.updatedAt;

      if (Object.keys(updates).length === 0) {
        return res
          .status(400)
          .json({ success: false, message: "No valid fields to update" });
      }

      const profile = await this.userProfileService.updateProfile(
        userId,
        updates,
      );

      await this.loggerService.createAuditLog({
        userId,
        action: "profile.updated",
        resource: "user",
        resourceId: userId,
        changes: { after: auditChanges },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.loggerService.createActivityLog({
        userId,
        eventType: "profile_updated",
        eventCategory: "user",
        eventLabel: "Profile Update",
        page: "/profile",
        sessionId: req.cookies?.access_token || "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: {
          action: "profile_updated",
          updatedFields: Object.keys(updates),
        },
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "Profile updated successfully",
        data: profile,
      });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "profile_update_exception",
        severity: "medium",
        description: `Profile update error: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: { action: "profile_update_exception", errorName: error.name },
        timestamp: new Date(),
      });
      next(error);
    }
  };

  updateProfilePicture = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const userId = (req as any).user.id;
      const file = req.file;

      if (!file) {
        return res
          .status(400)
          .json({ success: false, message: "No file uploaded" });
      }

      const result = await this.userProfileService.uploadProfilePicture(
        file,
        userId,
      );

      await this.loggerService.createAuditLog({
        userId,
        action: "profile_picture.updated",
        resource: "user",
        resourceId: userId,
        changes: { after: { avatarUrl: result.imageUrl } },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.loggerService.createActivityLog({
        userId,
        eventType: "profile_picture_updated",
        eventCategory: "user",
        eventLabel: "Profile Picture Update",
        page: "/profile",
        sessionId: req.cookies?.access_token || "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: {
          action: "profile_picture_updated",
          changed: result.changed,
        },
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "Profile picture updated successfully",
        imageUrl: result.imageUrl,
        changed: result.changed,
      });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "profile_picture_update_exception",
        severity: "medium",
        description: `Profile picture update error: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: {
          action: "profile_picture_update_exception",
          errorName: error.name,
        },
        timestamp: new Date(),
      });
      next(error);
    }
  };

  getPreferences = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;
      const preferences = await this.userProfileService.getPreferences(userId);
      res.json({ success: true, data: preferences });
    } catch (error: any) {
      next(error);
    }
  };

  updatePreferences = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const userId = (req as any).user.id;
      const updates = req.body;

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
        return res
          .status(400)
          .json({
            success: false,
            message: "No valid preference fields to update",
          });
      }

      const preferences = await this.userProfileService.updatePreferences(
        userId,
        updates,
      );

      await this.loggerService.createAuditLog({
        userId,
        action: "preferences.updated",
        resource: "user_preferences",
        resourceId: userId,
        changes: { after: updates },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.loggerService.createActivityLog({
        userId,
        eventType: "preferences_updated",
        eventCategory: "user",
        eventLabel: "Preferences Update",
        page: "/profile/preferences",
        sessionId: req.cookies?.access_token || "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: {
          action: "preferences_updated",
          updatedFields: Object.keys(updates),
        },
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "Preferences updated successfully",
        data: preferences,
      });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "preferences_update_exception",
        severity: "low",
        description: `Preferences update error: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: {
          action: "preferences_update_exception",
          errorName: error.name,
        },
        timestamp: new Date(),
      });
      next(error);
    }
  };

  getLoginHistory = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 20;
      const result = await this.analyticService.getUserLoginHistory(
        userId,
        page,
        limit,
      );
      res.json({ success: true, data: result });
    } catch (error: any) {
      next(error);
    }
  };

  getActivityLogs = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 50;
      const result = await this.analyticService.getUserAuditTrail(
        userId,
        page,
        limit,
      );
      res.json({ success: true, data: result });
    } catch (error: any) {
      next(error);
    }
  };

  getEngagementScore = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const userId = (req as any).user.id;
      const days = parseInt(req.query.days as string) || 30;
      const score = await this.analyticService.calculateUserEngagementScore(
        userId,
        days,
      );
      res.json({ success: true, data: score });
    } catch (error: any) {
      next(error);
    }
  };
}
