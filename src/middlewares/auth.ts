import { NextFunction, Request, Response } from 'express';

export function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const apiKey = req.get('x-api-key');
  if (!apiKey || !process.env.API_KEY || apiKey !== process.env.API_KEY) {
    res.status(403).json({
      status: 'fail',
      message: 'Unauthorized request.',
    });
    return;
  }
  next();
}
