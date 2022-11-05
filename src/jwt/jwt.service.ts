import { sign, verify } from 'jsonwebtoken';
import { BadRequestException, ForbiddenException, Injectable } from '@nestjs/common';

@Injectable()
export class JWTService {
  private readonly ACCESS_TOKEN_EXPIRATION = process.env.JWT_ACCESS_TOKEN_EXPIRATION || '10m';
  private readonly REFRESH_TOKEN_EXPIRATION = process.env.JWT_REFRESH_TOKEN_EXPIRATION || '7d';

  generateTokens(payload: string | object) {
    try {
      const accessToken = sign(payload, process.env.JWT_ACCESS_TOKEN_KEY, {
        expiresIn: this.ACCESS_TOKEN_EXPIRATION,
      });
      const refreshToken = sign(payload, process.env.JWT_REFRESH_TOKEN_KEY, {
        expiresIn: this.REFRESH_TOKEN_EXPIRATION,
      });
      return {
        accessToken,
        refreshToken,
      };
    } catch (err) {
      console.error('[JWT Service] generateTokens: ', err);
      throw err;
    }
  }

  verifyAccessToken(token: string) {
    try {
      return verify(token, process.env.JWT_ACCESS_TOKEN_KEY);
    } catch (err) {
      throw new ForbiddenException(err.message);
    }
  }

  verifyRefreshToken(token: string) {
    try {
      return verify(token, process.env.JWT_REFRESH_TOKEN_KEY);
    } catch (err) {
      throw new BadRequestException(err.message);
    }
  }

  getTokenFromAuthHeader(authHeader: string) {
    let token: string;
    if (authHeader) {
      const split = authHeader.split(' ');
      if (split[0] === 'Bearer') {
        token = split[1];
      }
    }
    return token;
  }
}
