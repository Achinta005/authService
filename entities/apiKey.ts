import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('api_keys')
export class ApiKey {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column()
  name!: string;

  @Column({ unique: true })
  serviceId!: string;

  @Column({ unique: true })
  key!: string;

  @Column({ nullable: true })
  description?: string;

  @Column({ type: 'jsonb', default: [] })
  scopes!: string[];

  @Column({ nullable: true })
  lastUsedAt?: Date;

  @Column()
  expiresAt!: Date;

  @Column({ default: true })
  isActive!: boolean;

  @CreateDateColumn()
  createdAt?: Date;

  @UpdateDateColumn()
  updatedAt?: Date;
}