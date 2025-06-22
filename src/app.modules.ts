import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

// Configuration
import { DatabaseConfig } from './config/database.config';
import { JwtConfig } from './config/jwt.config';

// Modules
import { AuthModule } from './modules/auth/auth.module';
import { DriversModule } from './modules/drivers/drivers.module';
import { TripsModule } from './modules/trips/trips.module';
import { EmergencyModule } from './modules/emergency/emergency.module';
import { AdminModule } from './modules/admin/admin.module';
import { AnalyticsModule } from './modules/analytics/analytics.module';
import { RealtimeModule } from './modules/realtime/realtime.module';

// Controllers
import { AppController } from './app.controller';

// Services
import { AppService } from './app.service';

@Module({
  imports: [
    // Configuration
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env.local', '.env'],
      cache: true,
    }),

    // Database
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useClass: DatabaseConfig,
    }),

    // JWT Global Configuration
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useClass: JwtConfig,
      global: true,
    }),

    // Passport
    PassportModule.register({ defaultStrategy: 'jwt' }),

    // Feature Modules
    AuthModule,
    DriversModule,
    TripsModule,
    EmergencyModule,
    AdminModule,
    AnalyticsModule,
    RealtimeModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
