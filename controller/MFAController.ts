import { Request, Response, NextFunction } from "express";
import { SupabaseAuthService } from "../services/superbaseAuthService";
import { UserProfileService } from "../services/userProfileService";
import { AnalyticsService } from "../services/analyticsService";
import { LoggerService } from "../lib/activityLogger";

export class MFAController {
  private supabaseAuth = new SupabaseAuthService();
  private userProfileService = new UserProfileService();
  private analyticService = new AnalyticsService();
  private loggerservice = new LoggerService();

  enrollMFA = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;
      const token = req.headers.authorization?.replace("Bearer ", "") || "";

      const profile = await this.userProfileService.getProfileById(userId);
      if (profile.isMfaEnabled) {
        return res
          .status(400)
          .json({ success: false, message: "MFA is already enabled" });
      }

      const mfaData = await this.supabaseAuth.enrollMFA(token);

      await this.loggerservice.createAuditLog({
        userId,
        action: "mfa.enroll_initiated",
        resource: "user",
        resourceId: userId,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.loggerservice.createActivityLog({
        userId,
        eventType: "mfa_enroll_initiated",
        eventCategory: "security",
        eventLabel: "MFA Enrollment Started",
        page: "/profile/security",
        sessionId: token,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { action: "mfa_enroll_initiated" },
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "MFA enrollment initiated",
        data: {
          qrCode: mfaData.totp?.qr_code,
          secret: mfaData.totp?.secret,
          factorId: mfaData.id,
        },
      });
    } catch (error: any) {
      await this.loggerservice.createSecurityEvent({
        eventType: "mfa_enroll_exception",
        severity: "medium",
        description: `MFA enrollment error: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: { action: "mfa_enroll_exception", errorName: error.name },
        timestamp: new Date(),
      });
      next(error);
    }
  };

  verifyMFA = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;
      const { factorId, code } = req.body;

      const data = await this.supabaseAuth.challengeMFA(factorId);
      const result = await this.supabaseAuth.verifyMFA(factorId, data.id, code);

      await this.userProfileService.setMfaEnabled(userId, true);

      await this.loggerservice.createAuditLog({
        userId,
        action: "mfa.enabled",
        resource: "user",
        resourceId: userId,
        changes: { after: { isMfaEnabled: true } },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.loggerservice.createSecurityEvent({
        userId,
        eventType: "mfa_enabled",
        severity: "low",
        description: "User enabled MFA",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: true,
        metadata: { action: "mfa_enabled", factorId },
        timestamp: new Date(),
      });

      await this.loggerservice.createActivityLog({
        userId,
        eventType: "mfa_enabled",
        eventCategory: "security",
        eventLabel: "MFA Enabled",
        page: "/profile/security",
        sessionId: req.cookies?.access_token || "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { action: "mfa_enabled", factorId },
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "MFA enabled successfully",
        data: result,
      });
    } catch (error: any) {
      await this.loggerservice.createSecurityEvent({
        eventType: "mfa_verify_exception",
        severity: "high",
        description: `MFA verification error: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: { action: "mfa_verify_exception", errorName: error.name },
        timestamp: new Date(),
      });
      next(error);
    }
  };

  challengeMFA = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { factorId } = req.body;
      const challenge = await this.supabaseAuth.challengeMFA(factorId);
      res.json({ success: true, data: challenge });
    } catch (error: any) {
      next(error);
    }
  };

  unenrollMFA = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;
      const { factorId } = req.body;

      await this.supabaseAuth.unenrollMFA(factorId);
      await this.userProfileService.setMfaEnabled(userId, false);

      await this.loggerservice.createAuditLog({
        userId,
        action: "mfa.disabled",
        resource: "user",
        resourceId: userId,
        changes: { after: { isMfaEnabled: false } },
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.loggerservice.createSecurityEvent({
        userId,
        eventType: "mfa_disabled",
        severity: "medium",
        description: "User disabled MFA",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: true,
        metadata: { action: "mfa_disabled", factorId },
        timestamp: new Date(),
      });

      await this.loggerservice.createActivityLog({
        userId,
        eventType: "mfa_disabled",
        eventCategory: "security",
        eventLabel: "MFA Disabled",
        page: "/profile/security",
        sessionId: req.cookies?.access_token || "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { action: "mfa_disabled", factorId },
        timestamp: new Date(),
      });

      res.json({ success: true, message: "MFA disabled successfully" });
    } catch (error: any) {
      await this.loggerservice.createSecurityEvent({
        eventType: "mfa_unenroll_exception",
        severity: "high",
        description: `MFA unenroll error: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: { action: "mfa_unenroll_exception", errorName: error.name },
        timestamp: new Date(),
      });
      next(error);
    }
  };

  listMFAFactors = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;
      const factors = await this.supabaseAuth.listMFAFactors(userId);
      res.json({ success: true, data: factors });
    } catch (error: any) {
      next(error);
    }
  };
}
