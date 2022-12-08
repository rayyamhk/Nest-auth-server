import { Response } from 'express';
import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Res,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { UtilsService } from '../utils/utils.service';
import { AccessToken } from './decorators/accessToken.decorator';
import { RefreshToken } from './decorators/refreshToken.decorator';
import { SessionId } from './decorators/sessionId.decorator';
import { SignInDTO, SignUpDTO } from './dto/user.dto';
import {
  COOKIE_SESSION_ID,
  COOKIE_REFRESH_TOKEN,
  JWT_REFRESH_TOKEN_EXP,
} from '../../constants';

@Controller()
export class AuthController {
  private readonly COOKIE_OPTIONS = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    domain: process.env.CLIENT_DOMAIN,
    sameSite: 'strict' as const,
  };

  constructor(
    private readonly authService: AuthService,
    private readonly utilsService: UtilsService,
  ) {}

  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  async signUp(@Body() body: SignUpDTO) {
    const user = await this.authService.signUp(body);
    return this.utilsService.formatResponse(null, user);
  }

  @Post('signin')
  @HttpCode(HttpStatus.OK)
  async signIn(
    @Body() { email, password, keepSession }: SignInDTO,
    @SessionId() sessionId: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    const payload = await this.authService.signIn(
      email,
      password,
      sessionId,
      keepSession,
    );
    if (keepSession && payload.refreshToken && payload.sessionId) {
      res.cookie(COOKIE_REFRESH_TOKEN, payload.refreshToken, {
        ...this.COOKIE_OPTIONS,
        maxAge: JWT_REFRESH_TOKEN_EXP,
      });
      res.cookie(COOKIE_SESSION_ID, payload.sessionId, this.COOKIE_OPTIONS);
    }
    return this.utilsService.formatResponse('User signed in.', {
      user: payload.user,
      accessToken: payload.accessToken,
    });
  }

  @Post('signout')
  @HttpCode(HttpStatus.ACCEPTED)
  async signOut(
    @RefreshToken() refreshToken: string,
    @SessionId() sessionId: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    if (refreshToken && sessionId) {
      res.cookie(COOKIE_REFRESH_TOKEN, '', {
        ...this.COOKIE_OPTIONS,
        maxAge: 0,
      });
      res.cookie(COOKIE_SESSION_ID, '', this.COOKIE_OPTIONS);
      await this.authService.signOut(refreshToken, sessionId);
    }
    return this.utilsService.formatResponse('Signed out.');
  }

  @Post('authorize')
  @HttpCode(HttpStatus.OK)
  async authorize(
    @AccessToken() accessToken: string,
    @RefreshToken() refreshToken: string,
    @SessionId() sessionId: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    const payload = await this.authService.authorize(
      accessToken,
      refreshToken,
      sessionId,
    );
    if (payload.refreshToken) {
      res.cookie(
        COOKIE_REFRESH_TOKEN,
        payload.refreshToken,
        this.COOKIE_OPTIONS,
      );
    }
    return this.utilsService.formatResponse(null, {
      user: payload.user,
      accessToken: payload.accessToken,
    });
  }
}
