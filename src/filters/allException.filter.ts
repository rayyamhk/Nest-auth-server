import { ArgumentsHost, Catch, ExceptionFilter, ForbiddenException, HttpException, HttpStatus } from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';

// https://docs.nestjs.com/exception-filters

@Catch()
export class AllExceptionFilter implements ExceptionFilter {
  constructor(private readonly httpAdapterHost: HttpAdapterHost) {}

  catch(exception: unknown, host: ArgumentsHost) {
    const { httpAdapter } = this.httpAdapterHost;

    const ctx = host.switchToHttp();
    const req = ctx.getRequest();
    const res = ctx.getResponse();

    const isHttpException = exception instanceof HttpException;

    const statusCode = isHttpException
      ? exception.getStatus()
      : HttpStatus.INTERNAL_SERVER_ERROR;
    const response = isHttpException
      ? exception.getResponse()
      : 'Internal Server Error' as any;

    httpAdapter.reply(res, {
      statusCode,
      message: typeof response === 'object' && response.message ? response.message : response,
      time: new Date().toISOString(),
      path: httpAdapter.getRequestUrl(req),
    });
  }
}