import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToMany,
} from "typeorm";
import { Role } from "./role";

@Entity("permissions")
export class Permission {
  @PrimaryGeneratedColumn()
  id!: number;

  @Column({ unique: true })
  name!: string; // users.read, courses.create, etc.

  @Column({ unique: true })
  slug!: string;

  @Column({ nullable: true })
  description?: string;

  @Column()
  resource?: string; // users, courses, payments, etc.

  @Column()
  action!: string; // read, create, update, delete, manage

  @ManyToMany(() => Role, (role) => role.permissions)
  roles!: Role[];

  @CreateDateColumn()
  createdAt?: Date;
}
