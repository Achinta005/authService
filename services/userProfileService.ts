import { AppDataSource } from "../config/db";
import { UserProfile } from "../entities/uerProfile";
import { UserPreferences } from "../entities/userPreference";
import { UserRole } from "../entities/userRole";
import { Repository } from "typeorm";
import { CloudinaryService } from "./cloudinaryServices";
import { BadRequestException, NotFoundException } from "../utils/exception";

export class UserProfileService {
  private userProfileRepo: Repository<UserProfile>;
  private userPreferencesRepo: Repository<UserPreferences>;
  private userRoleRepo: Repository<UserRole>;
  private cloudinaryService: CloudinaryService;

  constructor() {
    this.userProfileRepo = AppDataSource.getRepository(UserProfile);
    this.userPreferencesRepo = AppDataSource.getRepository(UserPreferences);
    this.userRoleRepo = AppDataSource.getRepository(UserRole);
    this.cloudinaryService = new CloudinaryService();
  }

  // ============ CREATE USER PROFILE ============
  async createProfile(data: {
    id: string;
    email: string;
    fullName?: string;
    projectName?: string;
    projectId?: number;
    metadata?: Record<string, any>;
  }) {
    const profile = this.userProfileRepo.create({
      id: data.id,
      email: data.email,
      fullName: data.fullName,
      projectName: data.projectName,
      projectId: data.projectId,
      metadata: data.metadata,
      isActive: true,
      isEmailVerified: false,
      isMfaEnabled: false,
    });

    await this.userProfileRepo.save(profile);

    // Create default preferences
    await this.createDefaultPreferences(data.id);

    return profile;
  }

  // ============ GET PROFILE BY ID ============
  async getProfileById(userId: string) {
    const profile = await this.userProfileRepo.findOne({
      where: { id: userId },
      relations: ["userRoles", "userRoles.role", "userRoles.role.permissions"],
    });

    if (!profile) {
      throw new Error("User profile not found");
    }

    return profile;
  }

  // services/userProfileService.ts

  async getProfileByIdandProjDetails(
    userId: string,
    projectName: string,
    projectId: number,
  ) {

    const start = Date.now();
    const profile = await this.userProfileRepo.findOne({
      where: {
        id: userId,
        projectName: projectName,
        projectId: projectId,
      },
      relations: ["userRoles", "userRoles.role"]
    });
    const duration = Date.now() - start;
    
    return profile || null;
  }

  // ============ GET PROFILE BY EMAIL ============
  async getProfileByEmail(email: string) {
    const profile = await this.userProfileRepo.findOne({
      where: { email },
      relations: ["userRoles", "userRoles.role"],
    });

    return profile;
  }

  // ============ UPDATE PROFILE ============
  async updateProfile(userId: string, updates: Partial<UserProfile>) {
    await this.userProfileRepo.update({ id: userId }, updates);

    return this.getProfileById(userId);
  }

  // ============ UPLOAD PROFILE PICTURE ============
  async uploadProfilePicture(file: Express.Multer.File, userId: string) {
    if (!file) {
      throw new BadRequestException("No file uploaded");
    }

    if (!userId) {
      throw new BadRequestException("userId required");
    }

    // Find user
    const user = await this.userProfileRepo.findOne({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException("[uploadProfilePicture] User not found");
    }

    // Get old avatar info for cleanup
    const oldAvatarUrl = user.avatarUrl ?? null;
    const oldPublicId = this.extractPublicIdFromUrl(oldAvatarUrl);

    // Delete old Cloudinary image if exists
    if (oldPublicId) {
      try {
        await this.cloudinaryService.delete(oldPublicId);
      } catch (err) {
        // non-blocking - log but continue
        console.error("Failed to delete old avatar:", err);
      }
    }

    // Upload new image to Cloudinary
    const uploadResult = await this.cloudinaryService.uploadBuffer(
      file.buffer,
      user.username || user.email.split("@")[0],
    );

    // Update user avatar URL
    const newAvatarUrl = (uploadResult as any).secure_url;
    const avatarChanged = oldAvatarUrl !== newAvatarUrl;

    user.avatarUrl = newAvatarUrl;
    user.updatedAt = new Date();

    // Save user
    await this.userProfileRepo.save(user);

    return {
      success: true,
      imageUrl: user.avatarUrl,
      changed: avatarChanged,
    };
  }

  // ============ HELPER: Extract Cloudinary Public ID from URL ============
  private extractPublicIdFromUrl(url: string | null): string | null {
    if (!url) return null;

    try {
      // Example URL: https://res.cloudinary.com/demo/image/upload/v123456/folder/image_name.jpg
      // Extract: folder/image_name
      const parts = url.split("/upload/");
      if (parts.length < 2) return null;

      const pathParts = parts[1].split("/");
      // Remove version (v123456) if present
      const relevantParts = pathParts.filter((p) => !p.startsWith("v"));

      // Remove file extension
      const publicIdWithExt = relevantParts.join("/");
      const publicId = publicIdWithExt.split(".")[0];

      return publicId;
    } catch (err) {
      console.error("Failed to extract public ID:", err);
      return null;
    }
  }

  // ============ UPDATE LAST LOGIN ============
  async updateLastLogin(userId: string, ipAddress: string) {
    await this.userProfileRepo.update(
      { id: userId },
      {
        lastLoginAt: new Date(),
        lastLoginIp: ipAddress,
      },
    );
  }

  // ============ SET EMAIL VERIFIED ============
  async setEmailVerified(userId: string, verified: boolean) {
    await this.userProfileRepo.update(
      { id: userId },
      { isEmailVerified: verified },
    );
  }

  // ============ SET MFA ENABLED ============
  async setMfaEnabled(userId: string, enabled: boolean) {
    await this.userProfileRepo.update(
      { id: userId },
      { isMfaEnabled: enabled },
    );
  }

  // ============ DEACTIVATE USER ============
  async deactivateUser(userId: string) {
    await this.userProfileRepo.update({ id: userId }, { isActive: false });
  }

  // ============ ACTIVATE USER ============
  async activateUser(userId: string) {
    await this.userProfileRepo.update({ id: userId }, { isActive: true });
  }

  // ============ DELETE PROFILE ============
  async deleteProfile(userId: string) {
    await AppDataSource.transaction(async (manager) => {
      await manager.delete(UserPreferences, { userId });
      await manager.delete(UserRole, { userId });
      await manager.delete(UserProfile, { id: userId });
    });
  }

  // ============ GET ALL PROFILES (ADMIN) ============
  async getAllProfiles(page: number = 1, limit: number = 20, filters?: any) {
    const skip = (page - 1) * limit;

    const queryBuilder = this.userProfileRepo
      .createQueryBuilder("profile")
      .leftJoinAndSelect("profile.userRoles", "userRoles")
      .leftJoinAndSelect("userRoles.role", "role")
      .leftJoinAndSelect("role.permissions", "permissions");

    // Apply filters
    if (filters?.isActive !== undefined) {
      queryBuilder.andWhere("profile.isActive = :isActive", {
        isActive: filters.isActive,
      });
    }

    if (filters?.search) {
      queryBuilder.andWhere(
        "(profile.email ILIKE :search OR profile.fullName ILIKE :search)",
        { search: `%${filters.search}%` },
      );
    }

    if (filters?.role) {
      queryBuilder.andWhere("role.slug = :role", { role: filters.role });
    }

    const [profiles, total] = await queryBuilder
      .skip(skip)
      .take(limit)
      .orderBy("profile.createdAt", "DESC")
      .getManyAndCount();

    return {
      profiles,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    };
  }

  // ============ SEARCH USERS ============
  async searchUsers(query: string, limit: number = 10) {
    const users = await this.userProfileRepo
      .createQueryBuilder("profile")
      .where("profile.email ILIKE :query", { query: `%${query}%` })
      .orWhere("profile.fullName ILIKE :query", { query: `%${query}%` })
      .take(limit)
      .getMany();

    return users;
  }

  // ============ USER PREFERENCES ============
  async createDefaultPreferences(userId: string) {
    const preferences = this.userPreferencesRepo.create({
      userId,
      language: "en",
      theme: "light",
      emailNotifications: true,
      pushNotifications: true,
      smsNotifications: false,
    });

    await this.userPreferencesRepo.save(preferences);
    return preferences;
  }

  async getPreferences(userId: string) {
    let preferences = await this.userPreferencesRepo.findOne({
      where: { userId },
    });

    if (!preferences) {
      preferences = await this.createDefaultPreferences(userId);
    }

    return preferences;
  }

  async updatePreferences(userId: string, updates: Partial<UserPreferences>) {
    await this.userPreferencesRepo.update({ userId }, updates);
    return this.getPreferences(userId);
  }

  // ============ STATISTICS ============
  async getUserStatistics() {
    const stats = await this.userProfileRepo
      .createQueryBuilder("profile")
      .select([
        "COUNT(*) as total",
        'COUNT(*) FILTER (WHERE "isActive" = true) as active',
        'COUNT(*) FILTER (WHERE "isActive" = false) as inactive',
        'COUNT(*) FILTER (WHERE "isEmailVerified" = true) as verified',
        'COUNT(*) FILTER (WHERE "isMfaEnabled" = true) as mfaEnabled',
      ])
      .getRawOne();

    return stats;
  }

  async getUserGrowth(days: number = 30) {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const growth = await this.userProfileRepo
      .createQueryBuilder("profile")
      .select("DATE_TRUNC('day', profile.\"createdAt\") as date")
      .addSelect("COUNT(*) as count")
      .where('profile."createdAt" >= :startDate', { startDate })
      .groupBy("DATE_TRUNC('day', profile.\"createdAt\")")
      .orderBy("date", "ASC")
      .getRawMany();

    return growth;
  }
}
