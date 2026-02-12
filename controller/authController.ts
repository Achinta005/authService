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
      console.log("📥 [AUTH MICROSERVICE] Registration request received");
      console.log("Body:", JSON.stringify({ ...req.body, password: "***" }));

      const { email, password, fullName, role, redirectTo } = req.body;

      if (!email || !password || !fullName) {
        console.warn("❌ Missing required fields");
        return res.status(400).json({
          success: false,
          message: "Email, password, and fullName are required",
        });
      }

      // Sign up via Supabase
      console.log("🚀 Calling Supabase signUp...");
      const { user, session } = await this.supabaseAuth.signUp(
        email,
        password,
        {
          fullName,
          emailRedirectTo: redirectTo,
        },
      );

      if (!user) {
        console.error("❌ Supabase returned no user");
        return res.status(400).json({
          success: false,
          message: "Registration failed",
        });
      }

      console.log(`✅ Supabase user created: ${user.id}`);

      // Create extended profile in PostgreSQL
      console.log("📝 Creating user profile...");
      const profile = await this.userProfileService.createProfile({
        id: user.id,
        email: user.email!,
        fullName,
      });

      // Assign default role
      console.log(`🎭 Assigning role: ${role}`);
      const defaultRole = await this.roleService.getRoleBySlug(role);
      if (defaultRole) {
        await this.roleService.assignRoleToUser(user.id, defaultRole.id);
      }

      // Log audit event
      console.log("📊 Creating audit log...");
      await this.logService.createAuditLog({
        userId: user.id,
        action: "user.registered",
        resource: "user",
        resourceId: user.id,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
        timestamp: new Date(),
      });

      console.log("✅ [AUTH MICROSERVICE] Registration completed successfully");

      res.status(201).json({
        success: true,
        message: "Registration successful. Please verify your email.",
        data: {
          user: {
            id: user.id,
            email: user.email,
            fullName: profile.fullName,
          },
          session,
        },
      });
    } catch (error: any) {
      console.error(
        "❌ [AUTH MICROSERVICE] Registration error:",
        error.message,
      );
      console.error("Stack:", error.stack);
      next(error);
    }
  };

  // ============ LOGIN ============
  login = async (req: Request, res: Response, next: NextFunction) => {
    try {
      console.log("📥 [AUTH MICROSERVICE] Login request received");
      const { email, password } = req.body;

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

        return res.status(401).json({
          success: false,
          message: "Invalid credentials",
        });
      }

      // Get user profile
      const profile = await this.userProfileService.getProfileById(user.id);

      // Check if account is active
      if (!profile.isActive) {
        console.warn("❌ Account deactivated");
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

      console.log("✅ [AUTH MICROSERVICE] Login successful");

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
      console.log("🔄 [AUTH MICROSERVICE] Token refresh requested");

      const refresh_token =
        req.cookies?.refresh_token || req.body.refresh_token;

      if (!refresh_token) {
        console.warn("❌ No refresh token provided");
        return res.status(401).json({
          success: false,
          message: "No refresh token provided",
        });
      }

      console.log("🔑 Refreshing session with Supabase...");
      const { session, user } =
        await this.supabaseAuth.refreshSession(refresh_token);

      if (!session || !user) {
        console.warn("❌ Invalid refresh token");
        return res.status(401).json({
          success: false,
          message: "Invalid refresh token",
        });
      }

      console.log("✅ Session refreshed successfully");

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
      console.log("🚪 [AUTH MICROSERVICE] Logout requested");

      const accessToken =
        req.cookies?.access_token ||
        req.headers.authorization?.replace("Bearer ", "");

      if (!accessToken) {
        console.warn("⚠️ No access token for logout");
      } else {
        await this.supabaseAuth.logout(accessToken);
        console.log("✅ Session revoked in Supabase");
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
  verifyToken = async (req: Request, res: Response, next: NextFunction) => {
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

      res.json({
        success: true,
        data: { user },
      });
    } catch (error) {
      res.status(401).json({
        success: false,
        message: "Invalid token",
      });
    }
  };

  // ============ OAUTH LOGIN ============
  oauthLogin = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { provider } = req.params;
      const { client } = req.query as { client?: string };

      if (!["google", "github", "facebook"].includes(provider as any)) {
        return res.status(400).json({ message: "Invalid OAuth provider" });
      }

      const CLIENT_REDIRECT_MAP: Record<string, string> = {
        admin: "https://appsy-ivory.vercel.app/verified",
        web: "https://app.company.com/auth/verified",
      };

      if (!client || !CLIENT_REDIRECT_MAP[client]) {
        return res.status(400).json({ message: "Invalid client" });
      }

      const redirectTo = CLIENT_REDIRECT_MAP[client];

      const { url } = await this.supabaseAuth.signInWithOAuth(
        provider as any,
        redirectTo,
      );

      res.redirect(url);
    } catch (err) {
      next(err);
    }
  };

  // ============ MAGIC LINK ============
  sendMagicLink = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email } = req.body;
      const redirectTo = CLIENT_REDIRECT_MAP[req.body.client];
      await this.supabaseAuth.signInWithMagicLink(email, redirectTo);

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

      // Log audit event

      await this.logService.createAuditLog({
        userId: user.id,
        action: "password.reset",
        resource: "user",
        resourceId: user.id,
        ipAddress: req.ip || "",
        userAgent: req.get("user-agent") || "",
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
      const { email } = req.body;

      await this.supabaseAuth.resendVerificationEmail(email);

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
