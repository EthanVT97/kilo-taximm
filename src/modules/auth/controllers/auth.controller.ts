import {
  Controller,
  Post,
  Body,
  Get,
  Patch,
  Delete,
  Req,
  Res,
  UseGuards,
  HttpCode,
  HttpStatus,
  Query,
  UseInterceptors,
  ClassSerializerInterceptor,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiBody,
  ApiQuery,
} from '@nestjs/swagger';
import { Request, Response } from 'express';
import { Throttle } from '@nestjs/throttler';
import { AuthService } from '../services/auth.service';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { LocalAuthGuard } from '../guards/local-auth.guard';
import { RefreshTokenGuard } from '../guards/refresh-token.guard';
import { Public, GetUser, GetUserId, Roles } from '../decorators';
import {
  RegisterDriverDto,
  LoginDto,
  ChangePasswordDto,
  UpdateProfileDto,
  AuthResponseDto,
  UserProfileDto,
  RefreshTokenDto,
  ForgotPasswordDto,
  ResetPasswordDto,
  VerifyEmailDto,
  ResendVerificationDto,
  LogoutDto,
} from '../dto';
import { User } from '../entities/user.entity';
import { UserRole } from '../enums/user-role.enum';

@ApiTags('Auth')
@Controller('auth')
@UseInterceptors(ClassSerializerInterceptor)
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('register-driver')
  @HttpCode(HttpStatus.CREATED)
  @Throttle({ default: { limit: 3, ttl: 300000 } }) // 3 attempts per 5 minutes
  @ApiOperation({ summary: 'Register a new driver account' })
  @ApiResponse({ status: 201, description: 'Driver registered successfully', type: AuthResponseDto })
  @ApiResponse({ status: 409, description: 'Email or phone number already exists' })
  @ApiResponse({ status: 429, description: 'Too many registration attempts' })
  @ApiBody({ type: RegisterDriverDto })
  async registerDriver(
    @Body() registerDto: RegisterDriverDto,
    @Req() req: Request,
  ): Promise<AuthResponseDto> {
    const userAgent = req.headers['user-agent'];
    const ip = req.ip || req.connection.remoteAddress;
    const fingerprint = req.headers['x-fingerprint'] as string;
    
    return this.authService.register(registerDto, userAgent, ip, fingerprint);
  }

  @Public()
  @UseGuards(LocalAuthGuard)
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 900000 } }) // 5 attempts per 15 minutes
  @ApiOperation({ summary: 'Login with email and password' })
  @ApiResponse({ status: 200, description: 'Login successful', type: AuthResponseDto })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  @ApiResponse({ status: 423, description: 'Account locked due to multiple failed attempts' })
  @ApiResponse({ status: 429, description: 'Too many login attempts' })
  @ApiBody({ type: LoginDto })
  async login(
    @Body() loginDto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthResponseDto> {
    const userAgent = req.headers['user-agent'];
    const ip = req.ip || req.connection.remoteAddress;
    const fingerprint = req.headers['x-fingerprint'] as string;
    
    const authResponse = await this.authService.login(loginDto, userAgent, ip, fingerprint);
    
    // Set HTTP-only refresh token cookie
    res.cookie('refreshToken', authResponse.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/auth/refresh',
    });

    // Remove refresh token from response body for security
    delete authResponse.refreshToken;
    
    return authResponse;
  }

  @Public()
  @Post('refresh')
  @UseGuards(RefreshTokenGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refresh access token using refresh token' })
  @ApiResponse({ status: 200, description: 'Token refreshed successfully', type: AuthResponseDto })
  @ApiResponse({ status: 401, description: 'Invalid or expired refresh token' })
  async refreshToken(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<Omit<AuthResponseDto, 'refreshToken'>> {
    const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
    const userAgent = req.headers['user-agent'];
    const ip = req.ip || req.connection.remoteAddress;
    
    const authResponse = await this.authService.refreshToken(refreshToken, userAgent, ip);
    
    // Set new refresh token cookie
    res.cookie('refreshToken', authResponse.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/auth/refresh',
    });

    // Remove refresh token from response body
    delete authResponse.refreshToken;
    
    return authResponse;
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Logout user and invalidate tokens' })
  @ApiResponse({ status: 204, description: 'Logout successful' })
  @ApiBearerAuth('JWT-auth')
  async logout(
    @GetUserId() userId: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    const refreshToken = req.cookies?.refreshToken;
    const accessToken = req.headers.authorization?.replace('Bearer ', '');
    
    await this.authService.logout(userId, accessToken, refreshToken);
    
    // Clear refresh token cookie
    res.clearCookie('refreshToken', { path: '/auth/refresh' });
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout-all')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Logout from all devices' })
  @ApiResponse({ status: 204, description: 'Logged out from all devices successfully' })
  @ApiBearerAuth('JWT-auth')
  async logoutAll(
    @GetUserId() userId: string,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    await this.authService.logoutAll(userId);
    res.clearCookie('refreshToken', { path: '/auth/refresh' });
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  @ApiOperation({ summary: 'Get current user profile' })
  @ApiResponse({ status: 200, description: 'Profile retrieved successfully', type: UserProfileDto })
  @ApiBearerAuth('JWT-auth')
  async getProfile(@GetUserId() userId: string): Promise<User> {
    return this.authService.getProfile(userId);
  }

  @UseGuards(JwtAuthGuard)
  @Patch('profile')
  @ApiOperation({ summary: 'Update user profile' })
  @ApiResponse({ status: 200, description: 'Profile updated successfully', type: UserProfileDto })
  @ApiResponse({ status: 409, description: 'Phone number already exists' })
  @ApiBearerAuth('JWT-auth')
  async updateProfile(
    @GetUserId() userId: string,
    @Body() updateProfileDto: UpdateProfileDto,
  ): Promise<User> {
    return this.authService.updateProfile(userId, updateProfileDto);
  }

  @UseGuards(JwtAuthGuard)
  @Post('change-password')
  @HttpCode(HttpStatus.NO_CONTENT)
  @Throttle({ default: { limit: 3, ttl: 3600000 } }) // 3 attempts per hour
  @ApiOperation({ summary: 'Change user password' })
  @ApiResponse({ status: 204, description: 'Password changed successfully' })
  @ApiResponse({ status: 400, description: 'Current password is incorrect' })
  @ApiResponse({ status: 429, description: 'Too many password change attempts' })
  @ApiBearerAuth('JWT-auth')
  async changePassword(
    @GetUserId() userId: string,
    @Body() changePasswordDto: ChangePasswordDto,
  ): Promise<void> {
    return this.authService.changePassword(userId, changePasswordDto);
  }

  @Public()
  @Post('forgot-password')
  @HttpCode(HttpStatus.NO_CONTENT)
  @Throttle({ default: { limit: 3, ttl: 3600000 } }) // 3 attempts per hour
  @ApiOperation({ summary: 'Request password reset' })
  @ApiResponse({ status: 204, description: 'Password reset email sent if account exists' })
  @ApiResponse({ status: 429, description: 'Too many password reset attempts' })
  @ApiBody({ type: ForgotPasswordDto })
  async forgotPassword(
    @Body() forgotPasswordDto: ForgotPasswordDto,
    @Req() req: Request,
  ): Promise<void> {
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];
    
    return this.authService.forgotPassword(forgotPasswordDto.email, ip, userAgent);
  }

  @Public()
  @Post('reset-password')
  @HttpCode(HttpStatus.NO_CONTENT)
  @Throttle({ default: { limit: 5, ttl: 3600000 } }) // 5 attempts per hour
  @ApiOperation({ summary: 'Reset password using reset token' })
  @ApiResponse({ status: 204, description: 'Password reset successfully' })
  @ApiResponse({ status: 400, description: 'Invalid or expired reset token' })
  @ApiResponse({ status: 429, description: 'Too many reset attempts' })
  @ApiBody({ type: ResetPasswordDto })
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
    @Req() req: Request,
  ): Promise<void> {
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];
    
    return this.authService.resetPassword(resetPasswordDto, ip, userAgent);
  }

  @Public()
  @Post('verify-email')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Verify email address' })
  @ApiResponse({ status: 204, description: 'Email verified successfully' })
  @ApiResponse({ status: 400, description: 'Invalid or expired verification token' })
  @ApiBody({ type: VerifyEmailDto })
  async verifyEmail(@Body() verifyEmailDto: VerifyEmailDto): Promise<void> {
    return this.authService.verifyEmail(verifyEmailDto.token);
  }

  @Public()
  @Post('resend-verification')
  @HttpCode(HttpStatus.NO_CONTENT)
  @Throttle({ default: { limit: 3, ttl: 3600000 } }) // 3 attempts per hour
  @ApiOperation({ summary: 'Resend email verification' })
  @ApiResponse({ status: 204, description: 'Verification email sent if account exists' })
  @ApiResponse({ status: 429, description: 'Too many verification attempts' })
  @ApiBody({ type: ResendVerificationDto })
  async resendVerification(@Body() resendVerificationDto: ResendVerificationDto): Promise<void> {
    return this.authService.resendVerification(resendVerificationDto.email);
  }

  @UseGuards(JwtAuthGuard)
  @Get('sessions')
  @ApiOperation({ summary: 'Get active user sessions' })
  @ApiResponse({ status: 200, description: 'Active sessions retrieved successfully' })
  @ApiBearerAuth('JWT-auth')
  async getActiveSessions(@GetUserId() userId: string) {
    return this.authService.getActiveSessions(userId);
  }

  @UseGuards(JwtAuthGuard)
  @Delete('sessions/:sessionId')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Revoke specific session' })
  @ApiResponse({ status: 204, description: 'Session revoked successfully' })
  @ApiResponse({ status: 404, description: 'Session not found' })
  @ApiBearerAuth('JWT-auth')
  async revokeSession(
    @GetUserId() userId: string,
    @Query('sessionId') sessionId: string,
  ): Promise<void> {
    return this.authService.revokeSession(userId, sessionId);
  }

  @UseGuards(JwtAuthGuard)
  @Get('security-events')
  @ApiOperation({ summary: 'Get user security events' })
  @ApiResponse({ status: 200, description: 'Security events retrieved successfully' })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  @ApiQuery({ name: 'offset', required: false, type: Number })
  @ApiBearerAuth('JWT-auth')
  async getSecurityEvents(
    @GetUserId() userId: string,
    @Query('limit') limit: number = 50,
    @Query('offset') offset: number = 0,
  ) {
    return this.authService.getSecurityEvents(userId, limit, offset);
  }

  @UseGuards(JwtAuthGuard)
  @Post('enable-2fa')
  @ApiOperation({ summary: 'Enable two-factor authentication' })
  @ApiResponse({ status: 200, description: '2FA setup initiated' })
  @ApiBearerAuth('JWT-auth')
  async enable2FA(@GetUserId() userId: string) {
    return this.authService.enable2FA(userId);
  }

  @UseGuards(JwtAuthGuard)
  @Post('verify-2fa')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Verify and activate 2FA' })
  @ApiResponse({ status: 204, description: '2FA activated successfully' })
  @ApiResponse({ status: 400, description: 'Invalid 2FA code' })
  @ApiBearerAuth('JWT-auth')
  async verify2FA(
    @GetUserId() userId: string,
    @Body('code') code: string,
  ): Promise<void> {
    return this.authService.verify2FA(userId, code);
  }

  @UseGuards(JwtAuthGuard)
  @Post('disable-2fa')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Disable two-factor authentication' })
  @ApiResponse({ status: 204, description: '2FA disabled successfully' })
  @ApiResponse({ status: 400, description: 'Invalid password or 2FA code' })
  @ApiBearerAuth('JWT-auth')
  async disable2FA(
    @GetUserId() userId: string,
    @Body('password') password: string,
    @Body('code') code: string,
  ): Promise<void> {
    return this.authService.disable2FA(userId, password, code);
  }

  @UseGuards(JwtAuthGuard)
  @Get('backup-codes')
  @ApiOperation({ summary: 'Generate 2FA backup codes' })
  @ApiResponse({ status: 200, description: 'Backup codes generated successfully' })
  @ApiBearerAuth('JWT-auth')
  async generateBackupCodes(@GetUserId() userId: string) {
    return this.authService.generateBackupCodes(userId);
  }

  // Admin-only endpoints
  @UseGuards(JwtAuthGuard)
  @Roles(UserRole.ADMIN)
  @Get('admin/users')
  @ApiOperation({ summary: 'Get all users (Admin only)' })
  @ApiResponse({ status: 200, description: 'Users retrieved successfully' })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  @ApiBearerAuth('JWT-auth')
  async getAllUsers(
    @Query('page') page: number = 1,
    @Query('limit') limit: number = 20,
    @Query('search') search?: string,
    @Query('role') role?: UserRole,
    @Query('status') status?: string,
  ) {
    return this.authService.getAllUsers(page, limit, search, role, status);
  }

  @UseGuards(JwtAuthGuard)
  @Roles(UserRole.ADMIN)
  @Patch('admin/users/:userId/status')
  @ApiOperation({ summary: 'Update user status (Admin only)' })
  @ApiResponse({ status: 200, description: 'User status updated successfully' })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  @ApiBearerAuth('JWT-auth')
  async updateUserStatus(
    @Query('userId') targetUserId: string,
    @Body('status') status: string,
    @Body('reason') reason?: string,
  ) {
    return this.authService.updateUserStatus(targetUserId, status, reason);
  }

  @UseGuards(JwtAuthGuard)
  @Roles(UserRole.ADMIN)
  @Post('admin/users/:userId/reset-password')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Force password reset for user (Admin only)' })
  @ApiResponse({ status: 204, description: 'Password reset initiated' })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  @ApiBearerAuth('JWT-auth')
  async adminResetPassword(
    @Query('userId') targetUserId: string,
    @GetUserId() adminId: string,
  ): Promise<void> {
    return this.authService.adminResetPassword(targetUserId, adminId);
  }
}
