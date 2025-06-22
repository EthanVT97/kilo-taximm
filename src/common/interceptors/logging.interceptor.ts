import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { Request, Response } from 'express';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger(LoggingInterceptor.name);

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const ctx = context.switchToHttp();
    const request = ctx.getRequest<Request>();
    const response = ctx.getResponse<Response>();
    
    const { method, url, ip, headers } = request;
    const userAgent = headers['user-agent'] || '';
    const startTime = Date.now();

    // Log request
    this.logger.log(`→ ${method} ${url} - ${ip} - ${userAgent}`);

    return next.handle().pipe(
      tap(() => {
        const { statusCode } = response;
        const responseTime = Date.now() - startTime;
        
        // Log response
        this.logger.log(
          `← ${method} ${url} - ${statusCode} - ${responseTime}ms - ${ip}`,
        );
      }),
    );
  }
}
