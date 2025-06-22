import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AppService } from './app.service';

@ApiTags('Health')
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @ApiOperation({ summary: 'Health check endpoint' })
  @ApiResponse({ status: 200, description: 'Application is running' })
  getHealth(): { message: string; timestamp: string; uptime: number } {
    return this.appService.getHealth();
  }

  @Get('status')
  @ApiOperation({ summary: 'Detailed application status' })
  @ApiResponse({ status: 200, description: 'Detailed application status' })
  getStatus(): {
    status: string;
    version: string;
    environment: string;
    database: string;
    timestamp: string;
    uptime: number;
  } {
    return this.appService.getStatus();
  }
}
