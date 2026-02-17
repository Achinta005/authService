import { Request, Response, NextFunction } from "express";
import { SupabaseAuthService } from "../services/superbaseAuthService";
import { UserProfileService } from "../services/userProfileService";
import { RoleService } from "../services/roleService";
import { LogService } from "../services/logService";

const CLIENT_REDIRECT_MAP: Record<string, string> = {
  admin: "https://appsy-ivory.vercel.app/verified",
  web: "https://app.company.com/auth/verified",
};

export class AuthController {
  constructor(
    private supabaseAuth: SupabaseAuthService,
    private userProfileService: UserProfileService,
    private roleService: RoleService,
    private logService: LogService,
  ) {}

  // ============ REGISTER ============
  register = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const {
        email,
        password,
        fullName,
        role,
        redirectTo,
        projectName,
        projectId,
      } = req.body;

      if (!email || !password || !redirectTo || !projectName || !projectId) {
        console.warn("❌ [REGISTER] Missing required fields");
        return res.status(400).json({
          success: false,
          message:
            "Email, password, fullName, Role, Project Details are required",
        });
      }

      let userId: string;
      let isNewUser = false;
      let session: any = null;

      const existingUser = await this.supabaseAuth.getUserByEmail(email);

      if (existingUser) {
        userId = existingUser.id;

        const existingProfile =
          await this.userProfileService.getProfileByIdandProjDetails(
            userId,
            projectName,
            projectId,
          );

        if (existingProfile) {
          console.warn(
            `⚠️ [REGISTER] User ${email} already registered for project ${projectName}`,
          );
          console.warn("⚠️ [REGISTER] Existing profile:", {
            profileId: existingProfile.id,
            email: existingProfile.email,
            projectName: existingProfile.projectName,
            projectId: existingProfile.projectId,
            createdAt: existingProfile.createdAt,
          });

          return res.status(409).json({
            success: false,
            message: `User already registered for project ${projectName}`,
          });
        }
      } else {
        const { user, session: newSession } = await this.supabaseAuth.signUp(
          email,
          password,
          {
            fullName,
            projectName,
            projectId,
            emailRedirectTo: redirectTo,
          },
        );

        if (!user) {
          console.error("[REGISTER] Supabase returned no user");
          return res.status(400).json({
            success: false,
            message: "Registration failed",
          });
        }

        userId = user.id;
        session = newSession;
        isNewUser = true;
      }

      const profile = await this.userProfileService.createProfile({
        id: userId,
        email: email,
        fullName,
        projectName,
        projectId,
      });

      const defaultRole = await this.roleService.getRoleBySlug(role);

      if (defaultRole) {
        await this.roleService.assignRoleToUser(
          userId,
          defaultRole.id,
          projectId,
          projectName,
        );
      } else {
        console.warn(` [REGISTER] Role not found for slug: ${role}`);
      }

      await this.logService.createAuditLog({
        userId: userId,
        action: isNewUser ? "user.registered" : "user.registered_new_project",
        resource: "user",
        resourceId: userId,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { projectName, projectId },
        timestamp: new Date(),
      });

      await this.logService.createActivityLog({
        userId,
        eventType: isNewUser
          ? "user_registered"
          : "user_registered_new_project",
        eventCategory: "auth",
        eventLabel: isNewUser ? "New Registration" : "Project Registration",
        page: "/register",
        sessionId: session?.access_token || "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { projectName, projectId, isNewUser, role },
        timestamp: new Date(),
      });

      res.status(201).json({
        success: true,
        message: isNewUser
          ? "Registration successful. Please verify your email."
          : `Successfully registered for project ${projectName}`,
        data: {
          user: {
            id: userId,
            email: email,
            fullName: profile.fullName,
            projectName,
          },
          session,
          isNewUser,
        },
      });
    } catch (error: any) {
      console.error("❌ [REGISTER] Registration error:", error.message);
      console.error("❌ [REGISTER] Error name:", error.name);
      console.error("❌ [REGISTER] Error code:", error.code);
      console.error("❌ [REGISTER] Stack trace:", error.stack);

      // Log the full error object for debugging
      console.error(
        "❌ [REGISTER] Full error object:",
        JSON.stringify(error, null, 2),
      );

      next(error);
    }
  };

  // ============ LOGIN ============
  login = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email, password, projectName, projectId } = req.body;

      // Authenticate via Supabase
      const { user, session } = await this.supabaseAuth.signInWithPassword(
        email,
        password,
      );

      if (!user || !session) {
        console.warn("❌ Invalid credentials");

        // Log failed login
        await this.logService.createLoginLog({
          userId: "",
          email,
          loginMethod: "email",
          success: false,
          failureReason: "Invalid credentials",
          ipAddress: req.ip || "",
          userAgent: req.get("user-agent") || "",
          device: this.extractDevice(req.get("user-agent") || ""),
          browser: this.extractBrowser(req.get("user-agent") || ""),
          os: this.extractOS(req.get("user-agent") || ""),
          mfaUsed: false,
          createdAt: new Date(),
        });

        await this.logService.createActivityLog({
          userId: user.id,
          eventType: "user_login",
          eventCategory: "auth",
          eventLabel: "Email Login",
          page: "/login",
          sessionId: session.access_token,
          ipAddress: req.ip || "",
          userAgent: req.get("user-agent") || "",
          metadata: {
            projectName,
            projectId,
            loginMethod: "email",
            mfaUsed: null,
            device: this.extractDevice(req.get("user-agent") || ""),
            browser: this.extractBrowser(req.get("user-agent") || ""),
            os: this.extractOS(req.get("user-agent") || ""),
          },
          timestamp: new Date(),
        });

        const failedAttempts =
          await this.logService.getFailedLoginAttempts(3600000);
        const userFailedAttempts = failedAttempts.find((f) => f._id === email);

        if (userFailedAttempts && userFailedAttempts.attempts >= 3) {
          await this.logService.createSecurityEvent({
            userId: "",
            eventType: "brute_force_attempt",
            severity: userFailedAttempts.attempts >= 5 ? "high" : "medium",
            description: `${userFailedAttempts.attempts} failed login attempts for ${email}`,
            ipAddress: req.ip || "",
            userAgent: req.get("user-agent") || "",
            resolved: false,
            metadata: {
              email,
              attemptCount: userFailedAttempts.attempts,
              ipAddresses: userFailedAttempts.ipAddresses,
            },
            timestamp: new Date(),
          });
        }
      }

      // Get user profile
      const profile =
        await this.userProfileService.getProfileByIdandProjDetails(
          user.id,
          projectName,
          projectId,
        );
      if (!profile) {
        console.warn(" Account Not Found");
        return res.status(403).json({
          success: false,
          message: "Account not Found",
        });
      }
      // Check if account is active
      if (!profile.isActive) {
        console.warn(" Account deactivated");
        return res.status(403).json({
          success: false,
          message: "Account is deactivated",
        });
      }

      // Update last login
      await this.userProfileService.updateLastLogin(user.id, req.ip || "");

      // Log successful login
      await this.logService.createLoginLog({
        userId: user.id,
        email: user.email!,
        loginMethod: "email",
        success: true,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        device: this.extractDevice(req.get("user-agent") || ""),
        browser: this.extractBrowser(req.get("user-agent") || ""),
        os: this.extractOS(req.get("user-agent") || ""),
        mfaUsed: profile.isMfaEnabled,
        sessionId: session.access_token,
        createdAt: new Date(),
      });

      // Set httpOnly cookies
      res.cookie("access_token", session.access_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 60 * 60 * 1000, // 1 hour
      });

      res.cookie("refresh_token", session.refresh_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      res.json({
        success: true,
        message: "Login successful",
        data: {
          user: {
            id: user.id,
            email: user.email,
            fullName: profile.fullName,
            roles: profile.userRoles.map((ur) => ur.role?.slug),
          },
          session: {
            access_token: session.access_token,
            refresh_token: session.refresh_token,
            expires_at: session.expires_at,
          },
        },
      });
    } catch (error: any) {
      console.error("❌ [AUTH MICROSERVICE] Login error:", error.message);
      next(error);
    }
  };

  // ============ REFRESH TOKEN ============
  refreshToken = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const refresh_token =
        req.cookies?.refresh_token || req.body.refresh_token;

      if (!refresh_token) {
        console.warn("❌ No refresh token provided");
        return res.status(401).json({
          success: false,
          message: "No refresh token provided",
        });
      }

      const { session, user } =
        await this.supabaseAuth.refreshSession(refresh_token);

      if (!session || !user) {
        console.warn("❌ Invalid refresh token");
        return res.status(401).json({
          success: false,
          message: "Invalid refresh token",
        });
      }

      await this.logService.createLoginLog({
        userId: user.id,
        email: user.email!,
        loginMethod: "email",
        success: true,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        device: this.extractDevice(req.get("user-agent") || ""),
        browser: this.extractBrowser(req.get("user-agent") || ""),
        os: this.extractOS(req.get("user-agent") || ""),
        mfaUsed: false,
        sessionId: session.access_token,
        createdAt: new Date(),
      });
      // Update cookies
      res.cookie("access_token", session.access_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 60 * 60 * 1000,
      });

      res.cookie("refresh_token", session.refresh_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      // ✅ Fixed: Return consistent structure
      res.json({
        success: true,
        accessToken: session.access_token, // Changed from data.accessToken
        refreshToken: session.refresh_token,
        expiresIn: 3600,
        user: {
          id: user.id,
          email: user.email,
        },
        session: session, // Keep for backward compatibility
      });
    } catch (error: any) {
      console.error("❌ [AUTH MICROSERVICE] Refresh error:", error.message);
      next(error);
    }
  };

  // ============ LOGOUT ============
  logout = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const accessToken =
        req.cookies?.access_token ||
        req.headers.authorization?.replace("Bearer ", "");

      if (!accessToken) {
        console.warn("⚠️ No access token for logout");
      } else {
        const user = await this.supabaseAuth.getUserFromToken(accessToken);

        await this.supabaseAuth.logout(accessToken);

        if (user) {
          await this.logService.createAuditLog({
            userId: user.id,
            action: "user.logout",
            resource: "session",
            resourceId: user.id,
            ipAddress: req.ip || "",
            userAgent: req.get("user-agent") || "",
            timestamp: new Date(),
          });
          await this.logService.createActivityLog({
            userId: user.id,
            eventType: "user_logout",
            eventCategory: "auth",
            eventLabel: "Logout",
            page: "/logout",
            sessionId: accessToken,
            ipAddress: req.ip || "",
            userAgent: req.get("user-agent") || "",
            metadata: { manual: true },
            timestamp: new Date(),
          });
        }
      }

      // Clear cookies
      res.clearCookie("access_token");
      res.clearCookie("refresh_token");

      res.json({
        success: true,
        message: "Logout successful",
      });
    } catch (err) {
      console.error("❌ Logout error:", err);
      next(err);
    }
  };

  // ============ VERIFY TOKEN (for Main Server) ============
  verifyToken = async (req: Request, res: Response) => {
    try {
      const token =
        req.headers.authorization?.replace("Bearer ", "") ||
        req.cookies?.access_token;

      if (!token) {
        return res.status(401).json({
          success: false,
          message: "No token provided",
        });
      }

      const user = await this.supabaseAuth.getUserFromToken(token);

      return res.json({
        success: true,
        data: { user },
        message: "Token Valid",
      });
    } catch (error) {
      return res.status(401).json({
        success: false,
        message: "Invalid token",
      });
    }
  };

  // ============ OAUTH LOGIN ============
  // auth.controller.ts in auth microservice
  oauthLogin = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { provider } = req.params;
      const { client } = req.query as { client?: string };

      if (
        !["google", "github", "facebook", "apple"].includes(provider as any)
      ) {
        return res.status(400).json({ message: "Invalid OAuth provider" });
      }

      if (!client) {
        return res.status(400).json({ message: "Client URL required" });
      }

      // Ensure client URL has protocol
      const clientUrl = client.startsWith("http")
        ? client
        : `https://${client}`;
      const redirectTo = `${clientUrl}/verified`;

      console.log(`[OAUTH] Redirecting to ${redirectTo} Provider: ${provider}`);
      const { url } = await this.supabaseAuth.signInWithOAuth(
        provider as any,
        redirectTo,
      );

      // Return URL as JSON for proxy to consume
      return res.status(200).json({ url });
    } catch (err) {
      console.error("❌ OAuth Login Error:", err);
      next(err);
    }
  };

  // auth.controller.ts
  oauthCallback = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { access_token, refresh_token } = req.body;
      const { projectName, projectId } = req.query as {
        projectName?: string;
        projectId?: string;
      };

      if (!access_token || !refresh_token) {
        console.error("❌ [OAUTH_CALLBACK] Missing tokens");
        return res.status(400).json({
          success: false,
          message: "Missing tokens",
        });
      }

      if (!projectName || !projectId) {
        console.error("❌ [OAUTH_CALLBACK] Missing project details");
        return res.status(400).json({
          success: false,
          message: "Project details required",
        });
      }

      const startTime = Date.now();

      // Get user from Supabase using access token
      const user = await this.supabaseAuth.getUserFromToken(access_token);

      const verifyDuration = Date.now() - startTime;

      if (!user) {
        console.error(
          "❌ [OAUTH_CALLBACK] Invalid token - Supabase returned no user",
        );
        return res.status(401).json({
          success: false,
          message: "Invalid authentication token",
        });
      }

      const userId = user.id;
      const email = user.email!;
      const fullName =
        user.user_metadata?.full_name || user.user_metadata?.name || "";
      const avatarUrl =
        user.user_metadata?.avatar_url || user.user_metadata?.picture || "";

      const profileCheckStart = Date.now();

      // Check if profile exists for this project
      const existingProfile =
        await this.userProfileService.getProfileByIdandProjDetails(
          userId,
          projectName as string,
          parseInt(projectId as string),
        );

      const profileCheckDuration = Date.now() - profileCheckStart;

      let profile;
      let isNewProfile = false;

      if (existingProfile) {
        profile = existingProfile;
        await this.logService.createActivityLog({
          userId,
          eventType: "oauth_login",
          eventCategory: "auth",
          eventLabel: "OAuth Login - Returning User",
          sessionId: access_token,
          ipAddress: req.ip || "",
          userAgent: req.get("user-agent") || "",
          metadata: {
            provider: user.app_metadata?.provider,
            projectName,
            projectId,
            isNewProfile: false,
          },
          timestamp: new Date(),
        });
      } else {
        const createProfileStart = Date.now();

        try {
          // Create profile
          profile = await this.userProfileService.createProfile({
            id: userId,
            email: email,
            fullName,
            projectName: projectName as string,
            projectId: parseInt(projectId as string),
          });

          const createProfileDuration = Date.now() - createProfileStart;

          isNewProfile = true;

          // Assign default role
          const roleStart = Date.now();

          const defaultRole = await this.roleService.getRoleBySlug("user");
          const roleDuration = Date.now() - roleStart;

          if (defaultRole) {
            const assignRoleStart = Date.now();

            await this.roleService.assignRoleToUser(
              userId,
              defaultRole.id,
              parseInt(projectId as string),
              projectName as string,
            );

            const assignRoleDuration = Date.now() - assignRoleStart;
          } else {
            console.warn(
              '⚠️  [OAUTH_CALLBACK] Default role "user" not found in database',
            );
          }

          // Create audit log
          const auditStart = Date.now();

          await this.logService.createAuditLog({
            userId: userId,
            action: "user.oauth_registered",
            resource: "user",
            resourceId: userId,
            ipAddress: req.ip || "",
            userAgent: req.get("user-agent") || "",
            metadata: {
              projectName,
              projectId,
              provider: user.app_metadata?.provider,
            },
            timestamp: new Date(),
          });

          await this.logService.createActivityLog({
            userId,
            eventType: "oauth_registered",
            eventCategory: "auth",
            eventLabel: "OAuth Registration - New Profile",
            sessionId: access_token,
            ipAddress: req.ip || "",
            userAgent: req.get("user-agent") || "",
            metadata: {
              provider: user.app_metadata?.provider,
              projectName,
              projectId,
              isNewProfile: true,
            },
            timestamp: new Date(),
          });

          const auditDuration = Date.now() - auditStart;
        } catch (profileError: any) {
          console.error("❌ [OAUTH_CALLBACK] Profile creation failed:", {
            errorMessage: profileError.message,
            errorCode: profileError.code,
            errorName: profileError.name,
          });
          throw profileError;
        }
      }

      const totalDuration = Date.now() - startTime;

      res.status(200).json({
        success: true,
        message: isNewProfile
          ? "Profile created successfully"
          : "Welcome back!",
        data: {
          user: {
            id: userId,
            email: email,
            fullName: profile.fullName,
            avatarUrl: profile.avatarUrl,
            projectName: profile.projectName,
          },
          isNewProfile,
        },
      });
    } catch (error: any) {
      console.error(" [OAUTH_CALLBACK] FATAL ERROR");
      console.error(" [OAUTH_CALLBACK] Error message:", error.message);

      if (error.response) {
        console.error(
          " [OAUTH_CALLBACK] Error response data:",
          error.response.data,
        );
      }

      console.error("=".repeat(60));
      next(error);
    }
  };

  // ============ MAGIC LINK ============
  sendMagicLink = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email } = req.body;
      const redirectTo = CLIENT_REDIRECT_MAP[req.body.client];
      await this.supabaseAuth.signInWithMagicLink(email, redirectTo);
      await this.logService.createAuditLog({
        userId: "",
        action: "magic_link.sent",
        resource: "auth",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { email },
        timestamp: new Date(),
      });
      await this.logService.createActivityLog({
        userId: "",
        eventType: "magic_link_requested",
        eventCategory: "auth",
        eventLabel: "Magic Link Request",
        page: "/magic-link",
        sessionId: "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { email },
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "Magic link sent to your email",
      });
    } catch (error: any) {
      next(error);
    }
  };

  // ============ FORGOT PASSWORD ============
  forgotPassword = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email, redirectUrl } = req.body;

      await this.supabaseAuth.sendPasswordResetEmail(email, redirectUrl);
      await this.logService.createAuditLog({
        userId: "",
        action: "password.reset_requested",
        resource: "auth",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { email },
        timestamp: new Date(),
      });

      await this.logService.createSecurityEvent({
        eventType: "password_reset_requested",
        severity: "low",
        description: `Password reset requested for ${email}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: true,
        metadata: { email },
        timestamp: new Date(),
      });
      await this.logService.createActivityLog({
        userId: "",
        eventType: "forgot_password_requested",
        eventCategory: "auth",
        eventLabel: "Forgot Password",
        page: "/forgot-password",
        sessionId: "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { email },
        timestamp: new Date(),
      });
      res.json({
        success: true,
        message: "Password reset email sent",
      });
    } catch (error: any) {
      next(error);
    }
  };

  // ============ RESET PASSWORD ============
  resetPassword = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { token, newPassword } = req.body;
      const user = await this.supabaseAuth.getUserFromToken(token);

      await this.supabaseAuth.updatePassword(user.id, newPassword);

      await this.logService.createAuditLog({
        userId: user.id,
        action: "password.reset",
        resource: "user",
        resourceId: user.id,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.logService.createSecurityEvent({
        userId: user.id,
        eventType: "password_changed",
        severity: "medium",
        description: "User password was reset via email link",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: true,
        metadata: { resetMethod: "email_link" },
        timestamp: new Date(),
      });

      await this.logService.createActivityLog({
        userId: user.id,
        eventType: "password_reset_completed",
        eventCategory: "auth",
        eventLabel: "Password Reset",
        page: "/reset-password",
        sessionId: "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { resetMethod: "email_link" },
        timestamp: new Date(),
      });

      res.json({
        success: true,
        message: "Password reset successful",
      });
    } catch (error: any) {
      next(error);
    }
  };

  // ============ RESEND VERIFICATION EMAIL ============
  resendVerification = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const { email,redirectTo } = req.body;

      await this.supabaseAuth.resendVerificationEmail(email,redirectTo);
      await this.logService.createAuditLog({
        userId: "",
        action: "verification.resent",
        resource: "auth",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { email },
        timestamp: new Date(),
      });
      await this.logService.createActivityLog({
        userId: "",
        eventType: "verification_email_resent",
        eventCategory: "auth",
        eventLabel: "Resend Verification",
        page: "/resend-verification",
        sessionId: "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { email },
        timestamp: new Date(),
      });
      res.json({
        success: true,
        message: "Verification email sent",
      });
    } catch (error: any) {
      next(error);
    }
  };

  // Helper methods
  private extractDevice(userAgent: string): string {
    if (/mobile/i.test(userAgent)) return "mobile";
    if (/tablet/i.test(userAgent)) return "tablet";
    return "desktop";
  }

  private extractBrowser(userAgent: string): string {
    if (/chrome/i.test(userAgent)) return "Chrome";
    if (/firefox/i.test(userAgent)) return "Firefox";
    if (/safari/i.test(userAgent)) return "Safari";
    if (/edge/i.test(userAgent)) return "Edge";
    return "Unknown";
  }

  private extractOS(userAgent: string): string {
    if (/windows/i.test(userAgent)) return "Windows";
    if (/mac/i.test(userAgent)) return "macOS";
    if (/linux/i.test(userAgent)) return "Linux";
    if (/android/i.test(userAgent)) return "Android";
    if (/ios|iphone|ipad/i.test(userAgent)) return "iOS";
    return "Unknown";
  }
}
