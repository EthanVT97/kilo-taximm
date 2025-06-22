import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AppService {
  constructor(private readonly configService: ConfigService) {}

  getHealth(): { message: string; timestamp: string; uptime: number } {
    return {
      message: 'Yangon Kilo Taxi Management System is running',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    };
  }

  getStatus(): {
    status: string;
    version: string;
    environment: string;
    database: string;
    timestamp: string;
    uptime: number;
  } {
    return {
      status: 'healthy',
      version: '1.0.0',
      environment: this.configService.get('NODE_ENV', 'development'),
      database: 'connected',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    };
  }
}
