import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { Observable } from 'rxjs';

@Injectable()
export class AuthGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
    const req = context.switchToHttp().getRequest();
    const apiKey = req.get('x-api-key');
    if (!process.env.API_KEY || process.env.API_KEY !== apiKey) {
      throw new ForbiddenException('Unauthorized request.');
    }
    return true;
  }
}
