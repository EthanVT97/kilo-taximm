import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtModuleOptions, JwtOptionsFactory } from '@nestjs/jwt';

@Injectable()
export class JwtConfig implements JwtOptionsFactory {
  constructor(private configService: ConfigService) {}

  createJwtOptions(): JwtModuleOptions {
    return {
      secret: this.configService.get('JWT_SECRET', 'your-super-secret-jwt-key'),
      signOptions: {
        expiresIn: this.configService.get('JWT_EXPIRES_IN', '7d'),
        issuer: 'yangon-kilo-taxi',
        audience: 'yangon-kilo-taxi-app',
      },
      verifyOptions: {
        issuer: 'yangon-kilo-taxi',
        audience: 'yangon-kilo-taxi-app',
      },
    };
  }
}
