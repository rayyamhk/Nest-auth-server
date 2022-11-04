import { HttpException, HttpStatus } from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';

export function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const apiKey = req.get('x-api-key');
  if (!apiKey || !process.env.API_KEY || apiKey !== process.env.API_KEY) {
    throw new HttpException('Unauthorized request.', HttpStatus.FORBIDDEN);
  }
  next();
}
