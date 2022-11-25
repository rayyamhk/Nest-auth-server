import { ForbiddenException, Injectable } from '@nestjs/common';
import { sign, verify } from 'jsonwebtoken';

@Injectable()
export class JWTService {
  private readonly ACCESS_TOKEN_EXPIRATION =
    process.env.JWT_ACCESS_TOKEN_EXPIRATION || '10m';
  private readonly REFRESH_TOKEN_EXPIRATION =
    process.env.JWT_REFRESH_TOKEN_EXPIRATION || '7d';

  generateTokens(payload: string | object) {
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
  }

  verifyAccessToken(token: string) {
    try {
      return verify(token, process.env.JWT_ACCESS_TOKEN_KEY);
    } catch (err) {
      throw new ForbiddenException(err);
    }
  }

  verifyRefreshToken(token: string) {
    try {
      return verify(token, process.env.JWT_REFRESH_TOKEN_KEY);
    } catch (err) {
      throw new ForbiddenException(err);
    }
  }
}
