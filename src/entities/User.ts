import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, BeforeInsert, BeforeUpdate } from 'typeorm';
import { IsEmail, IsString, MinLength, IsEnum, IsOptional, IsBoolean } from 'class-validator';
import { AuthMiddleware } from '../middleware/AuthMiddleware';

export enum UserRole {
  USER = 'user',
  ADMIN = 'admin',
  SUPER_ADMIN = 'super_admin',
}

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  @IsEmail({}, { message: 'Invalid email format' })
  email: string;

  @Column({ select: false })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  password: string;

  @Column({ nullable: true })
  @IsString()
  @IsOptional()
  firstName?: string;

  @Column({ nullable: true })
  @IsString()
  @IsOptional()
  lastName?: string;

  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.USER,
  })
  @IsEnum(UserRole)
  role: UserRole;

  @Column({ default: false })
  @IsBoolean()
  isEmailVerified: boolean;

  @Column({ nullable: true })
  @IsString()
  @IsOptional()
  resetPasswordToken?: string;

  @Column({ nullable: true })
  @IsOptional()
  resetPasswordExpires?: Date;

  @Column({ type: 'timestamp', nullable: true })
  @IsOptional()
  lastLoginAt?: Date;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // Hooks
  @BeforeInsert()
  @BeforeUpdate()
  async hashPassword() {
    if (this.password) {
      this.password = await AuthMiddleware.hashPassword(this.password);
    }
  }

  // Methods
  async validatePassword(password: string): Promise<boolean> {
    return AuthMiddleware.comparePassword(password, this.password);
  }

  generateAuthToken(): string {
    return AuthMiddleware.generateToken(this);
  }

  generateRefreshToken(): string {
    return AuthMiddleware.generateRefreshToken(this);
  }

  // Serialization
  toJSON() {
    const { password, resetPasswordToken, resetPasswordExpires, ...user } = this;
    return user;
  }
}
