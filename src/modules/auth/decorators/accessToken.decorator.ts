import {
  BadRequestException,
  createParamDecorator,
  ExecutionContext,
} from '@nestjs/common';
import { Request } from 'express';

export const AccessToken = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const req = ctx.switchToHttp().getRequest<Request>();
    const accessToken = req.get('authorization');
    if (!accessToken)
      throw new BadRequestException(
        'Access Token is missing in the request header.',
      );
    const tokenParts = accessToken.split(' ');
    if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer')
      throw new BadRequestException('Invalid Bearer token.');
    return tokenParts[1];
  },
);
