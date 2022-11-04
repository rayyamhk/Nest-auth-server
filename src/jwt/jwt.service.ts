import { sign, verify } from 'jsonwebtoken';
import { HttpException, HttpStatus, Injectable } from '@nestjs/common';

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
      throw new HttpException(err.message, HttpStatus.BAD_REQUEST);
    }
  }

  verifyRefreshToken(token: string) {
    try {
      return verify(token, process.env.JWT_REFRESH_TOKEN_KEY);
    } catch (err) {
      throw new HttpException(err.message, HttpStatus.BAD_REQUEST);
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
