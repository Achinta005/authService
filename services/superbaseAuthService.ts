import { supabaseAdmin, supabaseClient } from "../config/superbase";
import { createClient, User } from "@supabase/supabase-js";

export class SupabaseAuthService {
  async getUserByEmail(email: string) {
    try {
      const { data, error } = await supabaseAdmin.auth.admin.listUsers();

      if (error) throw error;

      const user = data.users.find((u) => u.email === email);
      return user || null;
    } catch (error) {
      console.error("Error fetching user by email:", error);
      return null;
    }
  }

  // ✅ ALSO UPDATE: Use supabaseAdmin for signup to auto-confirm email
  async signUp(
    email: string,
    password: string,
    options?: {
      fullName?: string;
      projectName?: string;
      projectId?: number;
      emailRedirectTo?: string;
    },
  ) {
    // ✅ Use admin client to create user and auto-confirm
    const { data, error } = await supabaseAdmin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: {
        fullName: options?.fullName,
        projectName: options?.projectName,
        projectId: options?.projectId,
      },
    });

    if (error) throw error;

    return {
      user: data.user,
      session: null, // Admin createUser doesn't return session
    };
  }

  // ============ LOGIN ============
  async signInWithPassword(email: string, password: string) {
    const { data, error } = await supabaseClient.auth.signInWithPassword({
      email,
      password,
    });

    if (error) throw error;
    return data;
  }

  // ============ OAUTH LOGIN ============
  async signInWithOAuth(
    provider: "google" | "github" | "facebook",
    redirectTo: string,
  ) {
    const { data, error } = await supabaseClient.auth.signInWithOAuth({
      provider,
      options: {
        redirectTo,
      },
    });

    if (error) throw error;
    return data;
  }

  // ============ MAGIC LINK ============
  async signInWithMagicLink(email: string, redirectTo: string) {
    const { data, error } = await supabaseClient.auth.signInWithOtp({
      email,
      options: {
        emailRedirectTo: redirectTo,
      },
    });

    if (error) throw error;
    return data;
  }

  // ============ PHONE LOGIN (OTP) ============
  async signInWithPhone(phone: string) {
    const { data, error } = await supabaseClient.auth.signInWithOtp({
      phone,
    });

    if (error) throw error;
    return data;
  }

  async verifyPhoneOtp(phone: string, token: string) {
    const { data, error } = await supabaseClient.auth.verifyOtp({
      phone,
      token,
      type: "sms",
    });

    if (error) throw error;
    return data;
  }

  // ============ LOGOUT ============
  async logout(accessToken: string) {
    const adminClient = createClient(
      process.env.SUPABASE_URL!,
      process.env.SUPABASE_SERVICE_ROLE_KEY!,
    );

    // 1️⃣ Resolve user from access token
    const {
      data: { user },
      error,
    } = await adminClient.auth.getUser(accessToken);

    if (error || !user) {
      throw new Error("Invalid or expired session");
    }

    // 2️⃣ Revoke ALL sessions for this user
    await adminClient.auth.admin.signOut(user.id);
  }

  // ============ REFRESH TOKEN ============
  async refreshSession(refreshToken: string) {
    const { data, error } = await supabaseClient.auth.refreshSession({
      refresh_token: refreshToken,
    });

    if (error) throw error;
    return data;
  }

  // ============ GET USER FROM TOKEN ============
  async getUserFromToken(token: string): Promise<User> {
    const { data, error } = await supabaseClient.auth.getUser(token);

    if (error) throw error;
    return data.user;
  }

  // ============ FORGOT PASSWORD ============
  async sendPasswordResetEmail(email: string, redirectUrl: string) {
    const { data, error } = await supabaseClient.auth.resetPasswordForEmail(
      email,
      {
        redirectTo: redirectUrl,
      },
    );

    if (error) throw error;
    return data;
  }

  // ============ UPDATE PASSWORD ============
  async updatePassword(userId: string, newPassword: string) {
    const { data, error } = await supabaseAdmin.auth.admin.updateUserById(
      userId,
      {
        password: newPassword,
      },
    );

    if (error) throw error;
    return data.user;
  }

  // ============ RESEND VERIFICATION EMAIL ============
  async resendVerificationEmail(email: string,emailRedirectTo:string) {
    const { data, error } = await supabaseClient.auth.resend({
      type: "signup",
      email,
      options: {
        emailRedirectTo: emailRedirectTo,
      },
    });

    if (error) throw error;
    return data;
  }

  // ============ ENROLL MFA ============
  async enrollMFA(accessToken: string) {
    // User must be authenticated
    const { data, error } = await supabaseAdmin.auth.mfa.enroll({
      factorType: "totp",
      friendlyName: "Authenticator App",
    });

    if (error) throw error;
    return data; // Returns QR code and secret
  }

  // ============ VERIFY MFA ============
  async verifyMFA(factorId: string, challengeId: string, code: string) {
    const { data, error } = await supabaseClient.auth.mfa.verify({
      factorId,
      challengeId,
      code,
    });

    if (error) throw error;
    return data;
  }

  // ============ CHALLENGE MFA (During Login) ============
  async challengeMFA(factorId: string) {
    const { data, error } = await supabaseClient.auth.mfa.challenge({
      factorId,
    });

    if (error) throw error;
    return data;
  }

  // ============ UNENROLL MFA ============
  async unenrollMFA(factorId: string) {
    const { data, error } = await supabaseAdmin.auth.mfa.unenroll({
      factorId,
    });

    if (error) throw error;
    return data;
  }

  // ============ LIST MFA FACTORS ============
  async listMFAFactors(userId: string) {
    const { data, error } = await supabaseAdmin.auth.mfa.listFactors();

    if (error) throw error;
    return data;
  }

  // ============ ADMIN: GET USER BY ID ============
  async getUserById(userId: string) {
    const { data, error } = await supabaseAdmin.auth.admin.getUserById(userId);

    if (error) throw error;
    return data.user;
  }

  // ============ ADMIN: UPDATE USER ============
  async updateUser(userId: string, updates: any) {
    const { data, error } = await supabaseAdmin.auth.admin.updateUserById(
      userId,
      updates,
    );

    if (error) throw error;
    return data.user;
  }

  // ============ ADMIN: DELETE USER ============
  async deleteUser(userId: string) {
    const { data, error } = await supabaseAdmin.auth.admin.deleteUser(userId);

    if (error) throw error;
    return data;
  }

  // ============ ADMIN: LIST USERS ============
  async listUsers(page: number = 1, perPage: number = 50) {
    const { data, error } = await supabaseAdmin.auth.admin.listUsers({
      page,
      perPage,
    });

    if (error) throw error;
    return data;
  }

  // ============ ADMIN: INVITE USER BY EMAIL ============
  async inviteUserByEmail(email: string,emailRedirectTo:string, metadata?: Record<string, any>) {
    const { data, error } = await supabaseAdmin.auth.admin.inviteUserByEmail(
      email,
      {
        data: metadata,
        redirectTo: emailRedirectTo,
      },
    );

    if (error) throw error;
    return data.user;
  }

  // ============ ADMIN: GENERATE LINK (Magic Link, Recovery, etc.) ============
  async generateLink(type: "signup" | "magiclink" | "recovery", email: string,emailRedirectTo:string) {
    let params: any;

    if (type === "signup") {
      params = {
        type: "signup",
        email,
        options: {
          redirectTo: emailRedirectTo,
        },
      };
    } else if (type === "magiclink") {
      params = {
        type: "magiclink",
        email,
        options: {
          redirectTo: emailRedirectTo,
        },
      };
    } else if (type === "recovery") {
      params = {
        type: "recovery",
        email,
        options: {
          redirectTo: emailRedirectTo,
        },
      };
    } else {
      throw new Error("Invalid link type");
    }

    const { data, error } = await supabaseAdmin.auth.admin.generateLink(params);

    if (error) throw error;
    return data;
  }
}
