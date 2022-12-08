import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';
import { COOKIE_REFRESH_TOKEN } from '../../../constants';

export const RefreshToken = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const req = ctx.switchToHttp().getRequest<Request>();
    const refreshToken = req.cookies[COOKIE_REFRESH_TOKEN] as string;
    return refreshToken;
  },
);
