import { Request, Response, NextFunction } from "express";
import { SupabaseAuthService } from "../services/superbaseAuthService";
import { UserProfileService } from "../services/userProfileService";
import { RoleService } from "../services/roleService";
import { AnalyticsService } from "../services/analyticsService";
import { LoggerService } from "../lib/activityLogger";

const CLIENT_REDIRECT_MAP: Record<string, string> = {
  admin: "https://appsy-ivory.vercel.app/verified",
  web: "https://app.company.com/auth/verified",
};

export class AuthController {
  constructor(
    private supabaseAuth: SupabaseAuthService,
    private userProfileService: UserProfileService,
    private roleService: RoleService,
    private analyticService: AnalyticsService,
    private loggerService: LoggerService,
  ) {}

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
          await this.loggerService.createSecurityEvent({
            userId,
            eventType: "duplicate_registration_attempt",
            severity: "low",
            description: `User ${email} attempted to re-register for project ${projectName}`,
            ipAddress: req.ip || "",
            userAgent: req.get("user-agent") || "",
            resolved: true,
            metadata: { projectName, projectId },
            timestamp: new Date(),
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
          await this.loggerService.createSecurityEvent({
            eventType: "registration_failed",
            severity: "medium",
            description: "Supabase signUp returned no user",
            ipAddress: req.ip || "",
            userAgent: req.get("user-agent") || "",
            resolved: false,
            metadata: { email, projectName, projectId },
            timestamp: new Date(),
          });

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
        email,
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
      }

      // ── Audit log ────────────────────────────────────────────────────────────
      await this.loggerService.createAuditLog({
        userId,
        action: isNewUser ? "user.registered" : "user.registered_new_project",
        resource: "user",
        resourceId: userId,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        changes: {
          after: { email, fullName, projectName, projectId, role },
        },
        metadata: { projectName, projectId },
        timestamp: new Date(),
      });

      // ── Activity log ─────────────────────────────────────────────────────────
      await this.loggerService.createActivityLog({
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
            email,
            fullName: profile.fullName,
            projectName,
          },
          session,
          isNewUser,
        },
      });
    } catch (error: any) {
      // ── Failure security event ────────────────────────────────────────────────
      await this.loggerService.createSecurityEvent({
        eventType: "registration_exception",
        severity: "high",
        description: `Unhandled error during registration: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: {
          errorName: error.name,
          errorCode: error.code,
          errorMessage: error.message,
        },
        timestamp: new Date(),
      });

      next(error);
    }
  };

  login = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email, password, projectName, projectId } = req.body;

      const { user, session } = await this.supabaseAuth.signInWithPassword(
        email,
        password,
      );

      if (!user || !session) {
        // ── Failed login log ────────────────────────────────────────────────────
        await this.loggerService.createLoginLog({
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

        // ── Failed activity log ─────────────────────────────────────────────────
        await this.loggerService.createActivityLog({
          userId: "",
          eventType: "user_login_failed",
          eventCategory: "auth",
          eventLabel: "Email Login Failed",
          page: "/login",
          sessionId: "",
          ipAddress: req.ip || "",
          userAgent: req.get("user-agent") || "",
          metadata: {
            action: "login_failed",
            projectName,
            projectId,
            loginMethod: "email",
            failureReason: "Invalid credentials",
            device: this.extractDevice(req.get("user-agent") || ""),
            browser: this.extractBrowser(req.get("user-agent") || ""),
            os: this.extractOS(req.get("user-agent") || ""),
          },
          timestamp: new Date(),
        });

        // ── Brute force detection ───────────────────────────────────────────────
        const failedAttempts =
          await this.analyticService.getFailedLoginAttempts(3600000);
        const userFailedAttempts = failedAttempts.find((f) => f._id === email);

        if (userFailedAttempts && userFailedAttempts.attempts >= 3) {
          await this.loggerService.createSecurityEvent({
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

        return res.status(401).json({
          success: false,
          message: "Invalid credentials",
        });
      }

      const profile =
        await this.userProfileService.getProfileByIdandProjDetails(
          user.id,
          projectName,
          projectId,
        );

      if (!profile) {
        await this.loggerService.createSecurityEvent({
          userId: user.id,
          eventType: "login_account_not_found",
          severity: "medium",
          description: `User ${email} authenticated but no profile found for project ${projectName}`,
          ipAddress: req.ip || "",
          userAgent: req.get("user-agent") || "",
          resolved: true,
          metadata: { projectName, projectId },
          timestamp: new Date(),
        });

        return res.status(403).json({
          success: false,
          message: "Account not Found",
        });
      }

      if (!profile.isActive) {
        await this.loggerService.createSecurityEvent({
          userId: user.id,
          eventType: "login_deactivated_account",
          severity: "medium",
          description: `Login attempt on deactivated account for ${email}`,
          ipAddress: req.ip || "",
          userAgent: req.get("user-agent") || "",
          resolved: true,
          metadata: { projectName, projectId },
          timestamp: new Date(),
        });

        return res.status(403).json({
          success: false,
          message: "Account is deactivated",
        });
      }

      await this.userProfileService.updateLastLogin(user.id, req.ip || "");

      // ── Successful login log ──────────────────────────────────────────────────
      await this.loggerService.createLoginLog({
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

      // ── Successful activity log ───────────────────────────────────────────────
      await this.loggerService.createActivityLog({
        userId: user.id,
        eventType: "user_login",
        eventCategory: "auth",
        eventLabel: "Email Login",
        page: "/login",
        sessionId: session.access_token,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: {
          action: "login_success",
          projectName,
          projectId,
          loginMethod: "email",
          mfaUsed: profile.isMfaEnabled,
          device: this.extractDevice(req.get("user-agent") || ""),
          browser: this.extractBrowser(req.get("user-agent") || ""),
          os: this.extractOS(req.get("user-agent") || ""),
        },
        timestamp: new Date(),
      });

      // ── Audit log ─────────────────────────────────────────────────────────────
      await this.loggerService.createAuditLog({
        userId: user.id,
        action: "user.login",
        resource: "user",
        resourceId: user.id,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { projectName, projectId },
        timestamp: new Date(),
      });

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
      await this.loggerService.createSecurityEvent({
        eventType: "login_exception",
        severity: "high",
        description: `Unhandled error during login: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: { errorName: error.name, errorCode: error.code },
        timestamp: new Date(),
      });

      next(error);
    }
  };

  refreshToken = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const refresh_token =
        req.cookies?.refresh_token || req.body.refresh_token;

      if (!refresh_token) {
        return res.status(401).json({
          success: false,
          message: "No refresh token provided",
        });
      }

      const { session, user } =
        await this.supabaseAuth.refreshSession(refresh_token);

      if (!session || !user) {
        await this.loggerService.createSecurityEvent({
          eventType: "token_refresh_failed",
          severity: "medium",
          description: "Invalid or expired refresh token used",
          ipAddress: req.ip || "",
          userAgent: req.get("user-agent") || "",
          resolved: true,
          metadata: { action: "token_refresh_failed" },
          timestamp: new Date(),
        });

        return res.status(401).json({
          success: false,
          message: "Invalid refresh token",
        });
      }

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

      res.json({
        success: true,
        accessToken: session.access_token,
        refreshToken: session.refresh_token,
        expiresIn: 3600,
        user: { id: user.id, email: user.email },
        session,
      });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "token_refresh_exception",
        severity: "high",
        description: `Unhandled error during token refresh: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: { action: "token_refresh_exception", errorName: error.name },
        timestamp: new Date(),
      });
      next(error);
    }
  };

  logout = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const accessToken =
        req.cookies?.access_token ||
        req.headers.authorization?.replace("Bearer ", "");

      if (accessToken) {
        const user = await this.supabaseAuth.getUserFromToken(accessToken);
        await this.supabaseAuth.logout(accessToken);

        if (user) {
          await this.loggerService.createAuditLog({
            userId: user.id,
            action: "user.logout",
            resource: "session",
            resourceId: user.id,
            ipAddress: req.ip || "",
            userAgent: req.get("user-agent") || "",
            timestamp: new Date(),
          });

          await this.loggerService.createActivityLog({
            userId: user.id,
            eventType: "user_logout",
            eventCategory: "auth",
            eventLabel: "Logout",
            page: "/logout",
            sessionId: accessToken,
            ipAddress: req.ip || "",
            userAgent: req.get("user-agent") || "",
            metadata: { action: "logout", manual: true },
            timestamp: new Date(),
          });
        }
      }

      res.clearCookie("access_token");
      res.clearCookie("refresh_token");

      res.json({ success: true, message: "Logout successful" });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "logout_exception",
        severity: "medium",
        description: `Unhandled error during logout: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: { action: "logout_exception", errorName: error.name },
        timestamp: new Date(),
      });
      next(error);
    }
  };

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

      const clientUrl = client.startsWith("http")
        ? client
        : `https://${client}`;
      const redirectTo = `${clientUrl}/verified`;

      const { url } = await this.supabaseAuth.signInWithOAuth(
        provider as any,
        redirectTo,
      );

      await this.loggerService.createActivityLog({
        userId: "",
        eventType: "oauth_login_initiated",
        eventCategory: "auth",
        eventLabel: "OAuth Login Initiated",
        page: "/oauth",
        sessionId: "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { action: "oauth_login_initiated", provider, clientUrl },
        timestamp: new Date(),
      });

      return res.status(200).json({ url });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "oauth_login_exception",
        severity: "high",
        description: `OAuth login error: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: {
          action: "oauth_login_exception",
          provider: req.params.provider,
        },
        timestamp: new Date(),
      });
      next(error);
    }
  };

  oauthCallback = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { access_token, refresh_token } = req.body;
      const { projectName, projectId } = req.query as {
        projectName?: string;
        projectId?: string;
      };

      if (!access_token || !refresh_token) {
        return res
          .status(400)
          .json({ success: false, message: "Missing tokens" });
      }

      if (!projectName || !projectId) {
        return res
          .status(400)
          .json({ success: false, message: "Project details required" });
      }

      const user = await this.supabaseAuth.getUserFromToken(access_token);

      if (!user) {
        await this.loggerService.createSecurityEvent({
          eventType: "oauth_callback_invalid_token",
          severity: "high",
          description: "OAuth callback received invalid access token",
          ipAddress: req.ip || "",
          userAgent: req.get("user-agent") || "",
          resolved: false,
          metadata: {
            action: "oauth_callback_invalid_token",
            projectName,
            projectId,
          },
          timestamp: new Date(),
        });

        return res
          .status(401)
          .json({ success: false, message: "Invalid authentication token" });
      }

      const userId = user.id;
      const email = user.email!;
      const fullName =
        user.user_metadata?.full_name || user.user_metadata?.name || "";
      const avatarUrl =
        user.user_metadata?.avatar_url || user.user_metadata?.picture || "";
      const provider = user.app_metadata?.provider;

      const existingProfile =
        await this.userProfileService.getProfileByIdandProjDetails(
          userId,
          projectName as string,
          parseInt(projectId as string),
        );

      let profile;
      let isNewProfile = false;

      if (existingProfile) {
        profile = existingProfile;

        await this.loggerService.createLoginLog({
          userId,
          email,
          loginMethod: "oauth",
          provider,
          success: true,
          ipAddress: req.ip || "",
          userAgent: req.get("user-agent") || "",
          device: this.extractDevice(req.get("user-agent") || ""),
          browser: this.extractBrowser(req.get("user-agent") || ""),
          os: this.extractOS(req.get("user-agent") || ""),
          mfaUsed: false,
          sessionId: access_token,
          createdAt: new Date(),
        });

        await this.loggerService.createActivityLog({
          userId,
          eventType: "oauth_login",
          eventCategory: "auth",
          eventLabel: "OAuth Login - Returning User",
          sessionId: access_token,
          ipAddress: req.ip || "",
          userAgent: req.get("user-agent") || "",
          metadata: {
            action: "oauth_login",
            provider,
            projectName,
            projectId,
            isNewProfile: false,
          },
          timestamp: new Date(),
        });
      } else {
        try {
          profile = await this.userProfileService.createProfile({
            id: userId,
            email,
            fullName,
            projectName: projectName as string,
            projectId: parseInt(projectId as string),
          });

          isNewProfile = true;

          const defaultRole = await this.roleService.getRoleBySlug("user");

          if (defaultRole) {
            await this.roleService.assignRoleToUser(
              userId,
              defaultRole.id,
              parseInt(projectId as string),
              projectName as string,
            );
          }

          await this.loggerService.createLoginLog({
            userId,
            email,
            loginMethod: "oauth",
            provider,
            success: true,
            ipAddress: req.ip || "",
            userAgent: req.get("user-agent") || "",
            device: this.extractDevice(req.get("user-agent") || ""),
            browser: this.extractBrowser(req.get("user-agent") || ""),
            os: this.extractOS(req.get("user-agent") || ""),
            mfaUsed: false,
            sessionId: access_token,
            createdAt: new Date(),
          });

          await this.loggerService.createAuditLog({
            userId,
            action: "user.oauth_registered",
            resource: "user",
            resourceId: userId,
            ipAddress: req.ip || "",
            userAgent: req.get("user-agent") || "",
            changes: {
              after: { email, fullName, projectName, projectId, provider },
            },
            metadata: { projectName, projectId, provider },
            timestamp: new Date(),
          });

          await this.loggerService.createActivityLog({
            userId,
            eventType: "oauth_registered",
            eventCategory: "auth",
            eventLabel: "OAuth Registration - New Profile",
            sessionId: access_token,
            ipAddress: req.ip || "",
            userAgent: req.get("user-agent") || "",
            metadata: {
              action: "oauth_registered",
              provider,
              projectName,
              projectId,
              isNewProfile: true,
            },
            timestamp: new Date(),
          });
        } catch (profileError: any) {
          await this.loggerService.createSecurityEvent({
            userId,
            eventType: "oauth_profile_creation_failed",
            severity: "high",
            description: `OAuth profile creation failed: ${profileError.message}`,
            ipAddress: req.ip || "",
            userAgent: req.get("user-agent") || "",
            resolved: false,
            metadata: {
              action: "oauth_profile_creation_failed",
              provider,
              projectName,
              projectId,
            },
            timestamp: new Date(),
          });
          throw profileError;
        }
      }

      res.status(200).json({
        success: true,
        message: isNewProfile
          ? "Profile created successfully"
          : "Welcome back!",
        data: {
          user: {
            id: userId,
            email,
            fullName: profile.fullName,
            avatarUrl: profile.avatarUrl,
            projectName: profile.projectName,
          },
          isNewProfile,
        },
      });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "oauth_callback_exception",
        severity: "critical",
        description: `Unhandled OAuth callback error: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: { action: "oauth_callback_exception", errorName: error.name },
        timestamp: new Date(),
      });
      next(error);
    }
  };

  sendMagicLink = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email } = req.body;
      const redirectTo = CLIENT_REDIRECT_MAP[req.body.client];

      await this.supabaseAuth.signInWithMagicLink(email, redirectTo);

      await this.loggerService.createAuditLog({
        userId: "",
        action: "magic_link.sent",
        resource: "auth",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { email },
        timestamp: new Date(),
      });

      await this.loggerService.createActivityLog({
        userId: "",
        eventType: "magic_link_requested",
        eventCategory: "auth",
        eventLabel: "Magic Link Request",
        page: "/magic-link",
        sessionId: "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { action: "magic_link_requested", email },
        timestamp: new Date(),
      });

      res.json({ success: true, message: "Magic link sent to your email" });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "magic_link_exception",
        severity: "medium",
        description: `Magic link send failed: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: { action: "magic_link_exception", email: req.body.email },
        timestamp: new Date(),
      });
      next(error);
    }
  };

  forgotPassword = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email, redirectUrl } = req.body;

      await this.supabaseAuth.sendPasswordResetEmail(email, redirectUrl);

      await this.loggerService.createAuditLog({
        userId: "",
        action: "password.reset_requested",
        resource: "auth",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { email },
        timestamp: new Date(),
      });

      await this.loggerService.createSecurityEvent({
        eventType: "password_reset_requested",
        severity: "low",
        description: `Password reset requested for ${email}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: true,
        metadata: { action: "password_reset_requested", email },
        timestamp: new Date(),
      });

      await this.loggerService.createActivityLog({
        userId: "",
        eventType: "forgot_password_requested",
        eventCategory: "auth",
        eventLabel: "Forgot Password",
        page: "/forgot-password",
        sessionId: "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { action: "forgot_password_requested", email },
        timestamp: new Date(),
      });

      res.json({ success: true, message: "Password reset email sent" });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "forgot_password_exception",
        severity: "medium",
        description: `Forgot password error: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: {
          action: "forgot_password_exception",
          email: req.body.email,
        },
        timestamp: new Date(),
      });
      next(error);
    }
  };

  resetPassword = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { token, newPassword } = req.body;
      const user = await this.supabaseAuth.getUserFromToken(token);

      await this.supabaseAuth.updatePassword(user.id, newPassword);

      await this.loggerService.createAuditLog({
        userId: user.id,
        action: "password.reset",
        resource: "user",
        resourceId: user.id,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      await this.loggerService.createSecurityEvent({
        userId: user.id,
        eventType: "password_changed",
        severity: "medium",
        description: "User password was reset via email link",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: true,
        metadata: {
          action: "password_reset_completed",
          resetMethod: "email_link",
        },
        timestamp: new Date(),
      });

      await this.loggerService.createActivityLog({
        userId: user.id,
        eventType: "password_reset_completed",
        eventCategory: "auth",
        eventLabel: "Password Reset",
        page: "/reset-password",
        sessionId: "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: {
          action: "password_reset_completed",
          resetMethod: "email_link",
        },
        timestamp: new Date(),
      });

      res.json({ success: true, message: "Password reset successful" });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "password_reset_exception",
        severity: "high",
        description: `Password reset error: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: { action: "password_reset_exception", errorName: error.name },
        timestamp: new Date(),
      });
      next(error);
    }
  };

  resendVerification = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const { email, redirectTo } = req.body;

      await this.supabaseAuth.resendVerificationEmail(email, redirectTo);

      await this.loggerService.createAuditLog({
        userId: "",
        action: "verification.resent",
        resource: "auth",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { email },
        timestamp: new Date(),
      });

      await this.loggerService.createActivityLog({
        userId: "",
        eventType: "verification_email_resent",
        eventCategory: "auth",
        eventLabel: "Resend Verification",
        page: "/resend-verification",
        sessionId: "",
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        metadata: { action: "verification_email_resent", email },
        timestamp: new Date(),
      });

      res.json({ success: true, message: "Verification email sent" });
    } catch (error: any) {
      await this.loggerService.createSecurityEvent({
        eventType: "resend_verification_exception",
        severity: "medium",
        description: `Resend verification error: ${error.message}`,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        resolved: false,
        metadata: {
          action: "resend_verification_exception",
          email: req.body.email,
        },
        timestamp: new Date(),
      });
      next(error);
    }
  };

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
