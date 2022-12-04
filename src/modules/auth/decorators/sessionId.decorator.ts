import {
  createParamDecorator,
  ExecutionContext,
} from '@nestjs/common';
import { Request } from 'express';
import { COOKIE_SESSION_ID } from 'src/constants';

export const SessionId = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const req = ctx.switchToHttp().getRequest<Request>();
    const sessionId = req.cookies[COOKIE_SESSION_ID];
    return sessionId;
  },
);
