import {
  Entity,
  PrimaryColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
  BeforeInsert,
  BeforeUpdate,
  Index,
  Unique,
} from "typeorm";
import { UserRole } from "./userRole";

@Entity("user_profiles")
@Unique("UQ_email_per_project", ["email", "projectName", "projectId"]) // Email unique per project
@Unique("UQ_username_per_project", ["username", "projectName", "projectId"]) // Username unique per project
@Index("IDX_user_profiles_email", ["email"]) // For faster email lookups
@Index("IDX_user_profiles_project", ["projectName", "projectId"]) // For project queries
@Index("IDX_user_profiles_id_project", ["id", "projectName", "projectId"]) // For user-project lookups
export class UserProfile {
  // ✅ COMPOSITE PRIMARY KEY - Add @PrimaryColumn to all three
  @PrimaryColumn("uuid")
  id!: string; // Supabase Auth user ID

  @PrimaryColumn() // ✅ Added - part of composite primary key
  projectName!: string;

  @PrimaryColumn() // ✅ Added - part of composite primary key
  projectId!: number;

  @Column()
  email!: string;

  @Column({ nullable: true })
  fullName?: string;

  @Column({ nullable: true })
  username?: string;

  @BeforeInsert()
  setUsernameFromEmail() {
    if (!this.username) {
      if (this.email) {
        const baseUsername = this.email.split('@')[0];
        this.username = `${baseUsername}_${this.projectName}`;
      } else if (this.fullName) {
        const baseUsername = this.fullName.trim().split(/\s+/)[0].toLowerCase();
        this.username = `${baseUsername}_${this.projectName}`;
      }
    }
  }

  @BeforeUpdate()
  updateUsernameIfMissing() {
    if (!this.username) {
      if (this.email) {
        const baseUsername = this.email.split('@')[0];
        this.username = `${baseUsername}_${this.projectName}`;
      } else if (this.fullName) {
        const baseUsername = this.fullName.trim().split(/\s+/)[0].toLowerCase();
        this.username = `${baseUsername}_${this.projectName}`;
      }
    }
  }

  @Column({ nullable: true })
  avatarUrl?: string;

  @Column({ nullable: true })
  phoneNumber?: string;

  @Column({ nullable: true })
  bio?: string;

  @Column({ nullable: true })
  company?: string;

  @Column({ nullable: true })
  position?: string;

  @Column({ nullable: true })
  location?: string;

  @Column({ nullable: true })
  timezone?: string;

  @Column({ default: true })
  isActive!: boolean;

  @Column({ default: false })
  isEmailVerified!: boolean;

  @Column({ default: false })
  isMfaEnabled!: boolean;

  @Column({ type: "jsonb", nullable: true })
  metadata?: Record<string, any>;

  @Column({ nullable: true })
  lastLoginAt?: Date;

  @Column({ nullable: true })
  lastLoginIp?: string;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;

  @OneToMany(() => UserRole, (userRole) => userRole.user)
  userRoles!: UserRole[];
}