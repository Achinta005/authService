import {
  Entity,
  PrimaryColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
  BeforeInsert,
  BeforeUpdate,
} from "typeorm";
import { UserRole } from "./userRole";

@Entity("user_profiles")
export class UserProfile {
  @PrimaryColumn("uuid")
  id!: string;

  @Column({ unique: true })
  email!: string;

  @Column({ nullable: true })
  fullName?: string;

  @Column({ nullable: true, unique: true })
  username?: string;

  @BeforeInsert()
  setUsernameFromEmail() {
    if (!this.username) {
      // Generate username from email if not provided
      if (this.email) {
        this.username = this.email.split('@')[0];
      } else if (this.fullName) {
        this.username = this.fullName.trim().split(/\s+/)[0].toLowerCase();
      }
    }
  }

  @BeforeUpdate()
  updateUsernameIfMissing() {
    if (!this.username) {
      if (this.email) {
        this.username = this.email.split('@')[0];
      } else if (this.fullName) {
        this.username = this.fullName.trim().split(/\s+/)[0].toLowerCase();
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