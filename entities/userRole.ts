import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { UserProfile } from './uerProfile';
import { Role } from './role';

@Entity('user_roles')
export class UserRole {
  @PrimaryGeneratedColumn()
  id!: number;

  @Column('uuid')
  userId!: string;

  @Column()
  roleId!: number;

  @Column({ nullable: true })
  assignedBy?: string;

  @CreateDateColumn()
  assignedAt?: Date;

  @ManyToOne(() => UserProfile, (user) => user.userRoles)
  @JoinColumn({ name: 'userId' })
  user?: UserProfile;

  @ManyToOne(() => Role, (role) => role.userRoles)
  @JoinColumn({ name: 'roleId' })
  role?: Role;
}