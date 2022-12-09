import { Injectable } from '@nestjs/common';
import { JwtPayload, sign, verify } from 'jsonwebtoken';
import { JWT_ACCESS_TOKEN_EXP, JWT_REFRESH_TOKEN_EXP } from '../../constants';

@Injectable()
export class JWTService {
  // expiresIn treats numeric string as millisecond, number as second.
  private readonly ACCESS_TOKEN_EXPIRATION = JWT_ACCESS_TOKEN_EXP.toString();
  private readonly REFRESH_TOKEN_EXPIRATION = JWT_REFRESH_TOKEN_EXP.toString();

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

  verifyAccessToken<T = JwtPayload>(token: string): T | 'expired' | 'invalid' {
    try {
      return verify(token, process.env.JWT_ACCESS_TOKEN_KEY) as T;
    } catch (err) {
      if (err.name === 'TokenExpiredError') return 'expired';
      return 'invalid';
    }
  }

  verifyRefreshToken<T = JwtPayload>(token: string): T | 'expired' | 'invalid' {
    try {
      return verify(token, process.env.JWT_REFRESH_TOKEN_KEY) as T;
    } catch (err) {
      if (err.name === 'TokenExpiredError') return 'expired';
      return 'invalid';
    }
  }
}
