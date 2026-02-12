import {
  Entity,
  PrimaryColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
} from "typeorm";

@Entity("user_preferences")
export class UserPreferences {
  @PrimaryColumn("uuid")
  userId!: string;

  @Column({ default: "en" })
  language!: string;

  @Column({ default: "light" })
  theme?: string;

  @Column({ default: true })
  emailNotifications?: boolean;

  @Column({ default: true })
  pushNotifications?: boolean;

  @Column({ default: false })
  smsNotifications?: boolean;

  @Column({ default: "public" })
  visibility?: string;

  @Column({ type: "jsonb", nullable: true })
  notificationPreferences?: Record<string, boolean>;

  @Column({ type: "jsonb", nullable: true })
  customSettings?: Record<string, any>;

  @CreateDateColumn()
  createdAt?: Date;

  @UpdateDateColumn()
  updatedAt?: Date;
}
