import { AppDataSource } from "../config/db";
import { Role } from "../entities/role";
import { Permission } from "../entities/permission";
import { UserRole } from "../entities/userRole";
import { Repository, In } from "typeorm";

export class RoleService {
  private roleRepo: Repository<Role>;
  private permissionRepo: Repository<Permission>;
  private userRoleRepo: Repository<UserRole>;

  constructor() {
    this.roleRepo = AppDataSource.getRepository(Role);
    this.permissionRepo = AppDataSource.getRepository(Permission);
    this.userRoleRepo = AppDataSource.getRepository(UserRole);
  }

  // ============ ROLE CRUD ============
  async createRole(data: { name: string; slug: string; description?: string }) {
    const existingRole = await this.roleRepo.findOne({
      where: { slug: data.slug },
    });

    if (existingRole) {
      throw new Error("Role with this slug already exists");
    }

    const role = this.roleRepo.create(data);
    await this.roleRepo.save(role);

    return role;
  }

  async getRoleById(roleId: number) {
    const role = await this.roleRepo.findOne({
      where: { id: roleId },
      relations: ["permissions"],
    });

    if (!role) {
      throw new Error("Role not found");
    }

    return role;
  }

  async getRoleBySlug(slug: string) {
    const role = await this.roleRepo.findOne({
      where: { slug },
      relations: ["permissions"],
    });

    return role;
  }

  async getAllRoles() {
    const roles = await this.roleRepo.find({
      relations: ["permissions"],
      order: { name: "ASC" },
    });

    return roles;
  }

  async updateRole(roleId: number, updates: Partial<Role>) {
    const role = await this.getRoleById(roleId);

    if (role.isSystem) {
      throw new Error("Cannot update system role");
    }

    await this.roleRepo.update({ id: roleId }, updates);
    return this.getRoleById(roleId);
  }

  async deleteRole(roleId: number) {
    const role = await this.getRoleById(roleId);

    if (role.isSystem) {
      throw new Error("Cannot delete system role");
    }

    // Check if role is assigned to any users
    const userCount = await this.userRoleRepo.count({
      where: { roleId },
    });

    if (userCount > 0) {
      throw new Error(
        `Cannot delete role. It is assigned to ${userCount} user(s)`,
      );
    }

    await this.roleRepo.delete({ id: roleId });
  }

  // ============ PERMISSION CRUD ============
  async createPermission(data: {
    name: string;
    slug: string;
    resource: string;
    action: string;
    description?: string;
  }) {
    const existingPermission = await this.permissionRepo.findOne({
      where: { slug: data.slug },
    });

    if (existingPermission) {
      throw new Error("Permission with this slug already exists");
    }

    const permission = this.permissionRepo.create(data);
    await this.permissionRepo.save(permission);

    return permission;
  }

  async getAllPermissions() {
    const permissions = await this.permissionRepo.find({
      order: { resource: "ASC", action: "ASC" },
    });

    return permissions;
  }

  async getPermissionsByResource(resource: string) {
    const permissions = await this.permissionRepo.find({
      where: { resource },
      order: { action: "ASC" },
    });

    return permissions;
  }

  // ============ ASSIGN PERMISSIONS TO ROLE ============
  async assignPermissionsToRole(roleId: number, permissionIds: number[]) {
    const role = await this.getRoleById(roleId);
    const permissions = await this.permissionRepo.findBy({
      id: In(permissionIds),
    });

    if (permissions.length !== permissionIds.length) {
      throw new Error("Some permissions not found");
    }

    role.permissions = permissions;
    await this.roleRepo.save(role);

    return this.getRoleById(roleId);
  }

  async removePermissionsFromRole(roleId: number, permissionIds: number[]) {
    const role = await this.getRoleById(roleId);

    role.permissions = role.permissions?.filter(
      (p) => !permissionIds.includes(p.id),
    );

    await this.roleRepo.save(role);
    return this.getRoleById(roleId);
  }

  // ============ USER ROLE ASSIGNMENT ============
  async assignRoleToUser(userId: string, roleId: number, assignedBy?: string) {
    // Check if user already has this role
    const existingUserRole = await this.userRoleRepo.findOne({
      where: { userId, roleId },
    });

    if (existingUserRole) {
      throw new Error("User already has this role");
    }

    const userRole = this.userRoleRepo.create({
      userId,
      roleId,
      assignedBy,
    });

    await this.userRoleRepo.save(userRole);

    return userRole;
  }

  async removeRoleFromUser(userId: string, roleId: number) {
    const result = await this.userRoleRepo.delete({ userId, roleId });

    if (result.affected === 0) {
      throw new Error("User role assignment not found");
    }
  }

  async getUserRoles(userId: string) {
    const userRoles = await this.userRoleRepo.find({
      where: { userId },
      relations: ["role", "role.permissions"],
    });

    return userRoles;
  }

  async getUserPermissions(userId: string): Promise<string[]> {
    const userRoles = await this.getUserRoles(userId);

    const permissions = new Set<string>();

    userRoles.forEach((userRole) => {
      userRole.role?.permissions.forEach((permission) => {
        permissions.add(permission.slug);
      });
    });

    return Array.from(permissions);
  }

  async hasPermission(
    userId: string,
    permissionSlug: string,
  ): Promise<boolean> {
    const permissions = await this.getUserPermissions(userId);
    return permissions.includes(permissionSlug);
  }

  async hasRole(userId: string, roleSlug: string): Promise<boolean> {
    const userRoles = await this.getUserRoles(userId);
    return userRoles.some((ur) => ur.role?.slug === roleSlug);
  }

  async hasAnyRole(userId: string, roleSlugs: string[]): Promise<boolean> {
    const userRoles = await this.getUserRoles(userId);
    const userRoleSlugs = userRoles.map((ur) => ur.role?.slug);

    return roleSlugs.some((slug) => userRoleSlugs.includes(slug));
  }
  
}
