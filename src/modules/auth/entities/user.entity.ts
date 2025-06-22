import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToOne,
  Index,
} from 'typeorm';
import { Exclude } from 'class-transformer';
import { UserRole } from '../../../common/types';
import { Driver } from '../../drivers/entities/driver.entity';

@Entity('users')
@Index(['email'], { unique: true })
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 255, unique: true })
  email: string;

  @Column({ type: 'varchar', length: 255 })
  @Exclude({ toPlainOnly: true })
  password: string;

  @Column({ type: 'varchar', length: 100 })
  firstName: string;

  @Column({ type: 'varchar', length: 100 })
  lastName: string;

  @Column({ type: 'varchar', length: 15, unique: true })
  phoneNumber: string;

  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.DRIVER,
  })
  role: UserRole;

  @Column({ type: 'boolean', default: true })
  isActive: boolean;

  @Column({ type: 'timestamp', nullable: true })
  lastLoginAt: Date;

  @Column({ type: 'inet', nullable: true })
  lastLoginIp: string;

  @Column({ type: 'timestamp', nullable: true })
  emailVerifiedAt: Date;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // Relations
  @OneToOne(() => Driver, (driver) => driver.user)
  driver: Driver;

  // Virtual properties
  get fullName(): string {
    return `${this.firstName} ${this.lastName}`;
  }

  get isEmailVerified(): boolean {
    return !!this.emailVerifiedAt;
  }

  get isDriver(): boolean {
    return this.role === UserRole.DRIVER;
  }

  get isAdmin(): boolean {
    return this.role === UserRole.ADMIN;
  }
  }
