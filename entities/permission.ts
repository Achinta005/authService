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
  name!: string;

  @Column({ unique: true })
  slug!: string;

  @Column({ nullable: true })
  description?: string;

  @Column()
  resource?: string;

  @Column()
  action!: string;

  @ManyToMany(() => Role, (role) => role.permissions)
  roles!: Role[];

  @CreateDateColumn()
  createdAt?: Date;
}
