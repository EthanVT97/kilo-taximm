import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { User } from '../entities/user.entity';
import { RegisterDriverDto, LoginDto, ChangePasswordDto, UpdateProfileDto, AuthResponseDto } from '../dto';
import { JwtPayload } from '../../../common/types';
import { sanitizePhoneNumber } from '../../../common/utils';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private jwtService: JwtService,
  ) {}

  async register(registerDto: RegisterDriverDto): Promise<AuthResponseDto> {
    const { email, password, phoneNumber, ...userData } = registerDto;

    // Check if user already exists
    const existingUser = await this.userRepository.findOne({
      where: [{ email }, { phoneNumber: sanitizePhoneNumber(phoneNumber) }],
    });

    if (existingUser) {
      if (existingUser.email === email) {
        throw new ConflictException('Email already exists');
      }
      throw new ConflictException('Phone number already exists');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const user = this.userRepository.create({
      email,
      password: hashedPassword,
      phoneNumber: sanitizePhoneNumber(phoneNumber),
      ...userData,
    });

    const savedUser = await this.userRepository.save(user);

    // Generate tokens
    return this.generateAuthResponse(savedUser);
  }

  async login(loginDto: LoginDto, userAgent?: string, ip?: string): Promise<AuthResponseDto> {
    const { email, password } = loginDto;

    const user = await this.validateUser(email, password);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Update login tracking
    await this.userRepository.update(user.id, {
      lastLoginAt: new Date(),
      lastLoginIp: ip,
    });

    return this.generateAuthResponse(user);
  }

  async validateUser(email: string, password: string): Promise<User | null> {
    const user = await this.userRepository.findOne({
      where: { email },
      select: ['id', 'email', 'password', 'firstName', 'lastName', 'phoneNumber', 'role', 'isActive'],
    });

    if (user && user.isActive && (await bcrypt.compare(password, user.password))) {
      return user;
    }

    return null;
  }

  async validateUserById(userId: string): Promise<User | null> {
    return this.userRepository.findOne({
      where: { id: userId, isActive: true },
      relations: ['driver'],
    });
  }

  async changePassword(userId: string, changePasswordDto: ChangePasswordDto): Promise<void> {
    const { currentPassword, newPassword } = changePasswordDto;

    const user = await this.userRepository.findOne({
      where: { id: userId },
      select: ['id', 'password'],
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isCurrentPasswordValid) {
      throw new BadRequestException('Current password is incorrect');
    }

    // Hash new password
    const hashedNewPassword = await bcrypt.hash(newPassword, 12);

    // Update password
    await this.userRepository.update(userId, {
      password: hashedNewPassword,
    });
  }

  async updateProfile(userId: string, updateProfileDto: UpdateProfileDto): Promise<User> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Sanitize phone number if provided
    if (updateProfileDto.phoneNumber) {
      updateProfileDto.phoneNumber = sanitizePhoneNumber(updateProfileDto.phoneNumber);
      
      // Check if phone number is already taken
      const existingUser = await this.userRepository.findOne({
        where: { phoneNumber: updateProfileDto.phoneNumber },
      });
      
      if (existingUser && existingUser.id !== userId) {
        throw new ConflictException('Phone number already exists');
      }
    }

    Object.assign(user, updateProfileDto);
    return this.userRepository.save(user);
  }

  async getProfile(userId: string): Promise<User> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
      relations: ['driver'],
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  private async generateAuthResponse(user: User): Promise<AuthResponseDto> {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
    };

    const access_token = this.jwtService.sign(payload);
    const decoded = this.jwtService.decode(access_token) as any;

    return {
      access_token,
      token_type: 'Bearer',
      expires_in: decoded.exp - decoded.iat,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        fullName: user.fullName,
        phoneNumber: user.phoneNumber,
        role: user.role,
        isActive: user.isActive,
        isEmailVerified: user.isEmailVerified,
        createdAt: user.createdAt,
        lastLoginAt: user.lastLoginAt,
      },
    };
  }
  }
