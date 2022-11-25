import {
  BadRequestException,
  createParamDecorator,
  ExecutionContext,
} from '@nestjs/common';
import { Request } from 'express';

export const AgentIdentifier = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const req = ctx.switchToHttp().getRequest<Request>();
    const identifier = req.get('x-agent-identifier') as string;
    if (!identifier)
      throw new BadRequestException(
        'x-agent-identifier is missing in the request header.',
      );
    return identifier;
  },
);
