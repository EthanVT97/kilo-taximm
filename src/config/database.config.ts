import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { TypeOrmModuleOptions, TypeOrmOptionsFactory } from '@nestjs/typeorm';
import { DataSource, DataSourceOptions } from 'typeorm';

// Entities
import { User } from '../modules/auth/entities/user.entity';
import { Driver } from '../modules/drivers/entities/driver.entity';
import { Vehicle } from '../modules/drivers/entities/vehicle.entity';
import { Trip } from '../modules/trips/entities/trip.entity';
import { Emergency } from '../modules/emergency/entities/emergency.entity';
import { Earnings } from '../modules/analytics/entities/earnings.entity';

@Injectable()
export class DatabaseConfig implements TypeOrmOptionsFactory {
  constructor(private configService: ConfigService) {}

  createTypeOrmOptions(): TypeOrmModuleOptions {
    return {
      type: 'postgres',
      host: this.configService.get('DB_HOST', 'localhost'),
      port: this.configService.get('DB_PORT', 5432),
      username: this.configService.get('DB_USERNAME', 'postgres'),
      password: this.configService.get('DB_PASSWORD', 'password'),
      database: this.configService.get('DB_NAME', 'yangon_kilo_taxi'),
      url: this.configService.get('DATABASE_URL'),
      entities: [User, Driver, Vehicle, Trip, Emergency, Earnings],
      migrations: ['dist/database/migrations/*.js'],
      migrationsTableName: 'migration_table',
      synchronize: this.configService.get('NODE_ENV') === 'development',
      logging: this.configService.get('NODE_ENV') === 'development',
      ssl: this.configService.get('NODE_ENV') === 'production' ? {
        rejectUnauthorized: false,
      } : false,
      extra: {
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 2000,
      },
    };
  }
}

// DataSource for migrations
const configService = new ConfigService();

export const AppDataSource = new DataSource({
  type: 'postgres',
  host: configService.get('DB_HOST', 'localhost'),
  port: configService.get('DB_PORT', 5432),
  username: configService.get('DB_USERNAME', 'postgres'),
  password: configService.get('DB_PASSWORD', 'password'),
  database: configService.get('DB_NAME', 'yangon_kilo_taxi'),
  url: configService.get('DATABASE_URL'),
  entities: ['src/**/*.entity.ts'],
  migrations: ['src/database/migrations/*.ts'],
  migrationsTableName: 'migration_table',
  synchronize: false,
  logging: configService.get('NODE_ENV') === 'development',
  ssl: configService.get('NODE_ENV') === 'production' ? {
    rejectUnauthorized: false,
  } : false,
} as DataSourceOptions);
