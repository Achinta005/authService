import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
  Unique,
} from 'typeorm';
import { UserProfile } from './uerProfile';
import { Role } from './role';

@Entity('user_roles')
@Unique('UQ_user_role_per_project', ['userId', 'roleId', 'projectName', 'projectId'])
@Index('IDX_user_roles_user_project', ['userId', 'projectName', 'projectId'])
export class UserRole {
  @PrimaryGeneratedColumn()
  id!: number;

  @Column('uuid')
  userId!: string;

  @Column()
  projectName!: string;

  @Column()
  projectId!: number;

  @Column()
  roleId!: number;

  @Column({ nullable: true })
  assignedBy?: string;

  @CreateDateColumn()
  assignedAt?: Date;

  @ManyToOne(() => UserProfile, (user) => user.userRoles, {
    onDelete: 'CASCADE',
  })
  @JoinColumn([
    { name: 'userId', referencedColumnName: 'id' },
    { name: 'projectName', referencedColumnName: 'projectName' },
    { name: 'projectId', referencedColumnName: 'projectId' },
  ])
  user?: UserProfile;

  @ManyToOne(() => Role, (role) => role.userRoles)
  @JoinColumn({ name: 'roleId' })
  role?: Role;
}