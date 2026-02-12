import { Request, Response, NextFunction } from "express";
import { SupabaseAuthService } from "../services/superbaseAuthService";
import { UserProfileService } from "../services/userProfileService";
import { LogService } from "../services/logService";

export class MFAController {
  private supabaseAuth = new SupabaseAuthService();
  private userProfileService = new UserProfileService();
  private logService = new LogService();

  // ============ ENROLL MFA (Generate QR Code) ============
  enrollMFA = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;
      const token = req.headers.authorization?.replace("Bearer ", "") || "";

      // Check if MFA is already enabled
      const profile = await this.userProfileService.getProfileById(userId);
      if (profile.isMfaEnabled) {
        return res.status(400).json({
          success: false,
          message: "MFA is already enabled",
        });
      }

      // Enroll MFA via Supabase
      const mfaData = await this.supabaseAuth.enrollMFA(token);

      // Log audit event
      await this.logService.createAuditLog({
        userId,
        action: "mfa.enroll_initiated",
        resource: "user",
        resourceId: userId,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
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
      next(error);
    }
  };

  // ============ VERIFY MFA (Complete Enrollment) ============
  verifyMFA = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;
      const { factorId, code } = req.body;

      const data = await this.supabaseAuth.challengeMFA(factorId);

      const challengeId = data.id;
      // Verify MFA code
      const result = await this.supabaseAuth.verifyMFA(
        factorId,
        challengeId,
        code,
      );

      // Update profile
      await this.userProfileService.setMfaEnabled(userId, true);

      // Log audit event
      await this.logService.createAuditLog({
        userId,
        action: "mfa.enabled",
        resource: "user",
        resourceId: userId,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      // Log security event
      await this.logService.createSecurityEvent({
        userId,
        eventType: "mfa_enabled",
        severity: "low",
        description: "User enabled MFA",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: true,
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "MFA enabled successfully",
        data: result,
      });
    } catch (error: any) {
      next(error);
    }
  };

  // ============ CHALLENGE MFA (During Login) ============
  challengeMFA = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { factorId } = req.body;

      const challenge = await this.supabaseAuth.challengeMFA(factorId);

      res.json({
        success: true,
        data: challenge,
      });
    } catch (error: any) {
      next(error);
    }
  };

  // ============ UNENROLL MFA (Disable) ============
  unenrollMFA = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;
      const { factorId } = req.body;

      await this.supabaseAuth.unenrollMFA(factorId);

      // Update profile
      await this.userProfileService.setMfaEnabled(userId, false);

      // Log audit event
      await this.logService.createAuditLog({
        userId,
        action: "mfa.disabled",
        resource: "user",
        resourceId: userId,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      // Log security event
      await this.logService.createSecurityEvent({
        userId,
        eventType: "mfa_disabled",
        severity: "medium",
        description: "User disabled MFA",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: true,
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "MFA disabled successfully",
      });
    } catch (error: any) {
      next(error);
    }
  };

  // ============ LIST MFA FACTORS ============
  listMFAFactors = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user.id;

      const factors = await this.supabaseAuth.listMFAFactors(userId);

      res.json({
        success: true,
        data: factors,
      });
    } catch (error: any) {
      next(error);
    }
  };
}
