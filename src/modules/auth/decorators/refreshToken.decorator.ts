import {
  BadRequestException,
  createParamDecorator,
  ExecutionContext,
} from '@nestjs/common';
import { Request } from 'express';

export const RefreshToken = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const req = ctx.switchToHttp().getRequest<Request>();
    const refreshToken = req.body.refreshToken as string;
    if (!refreshToken)
      throw new BadRequestException(
        'Refresh token is missing in the request body.',
      );
    const tokenParts = refreshToken.split(' ');
    if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer')
      throw new BadRequestException('Invalid Bearer token.');
    return tokenParts[1];
  },
);
