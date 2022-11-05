import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus } from '@nestjs/common';
import { Request, Response } from 'express';

// https://docs.nestjs.com/exception-filters

@Catch()
export class AllExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const req = ctx.getRequest<Request>();
    const res = ctx.getResponse<Response>();

    const isHttpException = exception instanceof HttpException;

    const statusCode = isHttpException
      ? exception.getStatus()
      : HttpStatus.INTERNAL_SERVER_ERROR;
    const response = isHttpException
      ? exception.getResponse()
      : 'Internal Server Error' as any;

    res.status(statusCode).json({
      statusCode,
      message: typeof response === 'object' && response.message ? response.message : response,
      time: new Date().toISOString(),
      path: req.url,
    });
  }
}