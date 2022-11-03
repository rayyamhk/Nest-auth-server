import { Body, Controller, Headers, Post, Res } from '@nestjs/common';
import { Response } from 'express';
import { JWTService } from '../jwt/jwt.service';
import { UserService } from '../user/user.service';
import { AuthService } from './auth.service';
import { PublicUser } from '../user/interface/user';
import { CreateUserDTO, SignInUserDTO } from './dto/user';

@Controller('auth')
export class AuthController {
  private readonly JWT_ERROR_LIST = [
    'TokenExpiredError',
    'JsonWebTokenError',
    'NotBeforeError',
  ];

  constructor(
    private jwtService: JWTService,
    private authService: AuthService,
    private userService: UserService,
  ) {}

  @Post('signup')
  async signUp(@Body() createUserDTO: CreateUserDTO, @Res() res: Response) {
    const { email, password } = createUserDTO;

    if (!email || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Email and password are required.',
      });
    }

    if (!this.authService.isValidEmail(email)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid email format.',
      });
    }

    if (!this.authService.isValidPassword(password)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid password.',
      });
    }

    try {
      const user = await this.userService.getUserByEmail(email);
      if (user) {
        return res.status(400).json({
          status: 'fail',
          message: `User with email ${email} already exists.`,
        });
      }

      const userObj = await this.authService.createUserObj(email, password);
      await this.userService.createUser(userObj);
      res.status(201).json({
        status: 'success',
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({
        status: 'error',
        message: 'Internal Server Error',
      });
    }
  }

  @Post('signin')
  async signIn(@Body() signInUserDTO: SignInUserDTO, @Res() res: Response) {
    const { email, password } = signInUserDTO;

    if (!email || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Email and password are required.',
      });
    }

    try {
      const user = await this.userService.getUserByEmail(email);
      if (!user) {
        return res.status(401).json({
          status: 'fail',
          message: 'Incorrect email or password.',
        });
      }

      const hashedPassword = await this.authService.hash(password, user.salt);
      if (hashedPassword !== user.hashedPassword) {
        return res.status(401).json({
          status: 'fail',
          message: 'Incorrect email or password.',
        });
      }

      const publicUser = this.userService.getPublicUser(user);
      const jwtTokens = this.jwtService.generateTokens(publicUser);
      const hashedRefreshToken = await this.authService.hash(
        jwtTokens.refreshToken,
        user.salt,
      );

      await this.userService.updateUserByEmail(user.email, { hashedRefreshToken });

      res.status(200).json({
        status: 'success',
        data: {
          accessToken: jwtTokens.accessToken,
          refreshToken: jwtTokens.refreshToken,
        },
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({
        status: 'error',
        message: 'Internal Server Error',
      });
    }
  }

  @Post('signout')
  async signOut(@Headers('authorization') authHeader: string, @Res() res: Response) {
    const accessToken: string = this.jwtService.getTokenFromAuthHeader(authHeader);
    if (!accessToken) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid Authorization header.',
      });
    }

    try {
      const tokenPayload = this.jwtService.verifyAccessToken(accessToken) as PublicUser;
      const user = await this.userService.getUserByEmail(tokenPayload.email);
      await this.userService.updateUserByEmail(user.email, {
        hashedRefreshToken: null,
      });
      res.status(200).json({
        status: 'success',
      });
    } catch (err) {
      if (this.JWT_ERROR_LIST.includes(err.name)) {
        return res.status(400).json({
          status: 'fail',
          message: err.message,
        });
      }
      console.error(err);
      res.status(500).json({
        status: 'error',
        message: 'Internal Server Error',
      });
    }
  }

  @Post('authorize')
  authorize(@Headers('authorization') authHeader: string, @Res() res: Response) {
    const accessToken: string = this.jwtService.getTokenFromAuthHeader(authHeader);
    if (!accessToken) {
      return res.status(403).json({
        status: 'fail',
        message: 'Invalid authorization header.',
      });
    }

    try {
      const tokenPayload = this.jwtService.verifyAccessToken(accessToken) as PublicUser;
      res.status(200).json({
        status: 'success',
        data: {
          user: tokenPayload,
        },
      });
    } catch (err) {
      if (this.JWT_ERROR_LIST.includes(err.name)) {
        return res.status(403).json({
          status: 'fail',
          message: err.message,
        });
      }
      console.error(err);
      res.status(500).json({
        status: 'error',
        message: 'Internal Server Error',
      });
    }
  }

  @Post('refresh')
  async refresh(@Headers('authorization') authHeader: string, @Res() res: Response) {
    const refreshToken: string = this.jwtService.getTokenFromAuthHeader(authHeader);
    if (!refreshToken) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid Authorization header.',
      });
    }

    try {
      const tokenPayload = this.jwtService.verifyRefreshToken(refreshToken) as PublicUser;
      const user = await this.userService.getUserByEmail(tokenPayload.email);
      const hashedRefreshToken = await this.authService.hash(
        refreshToken,
        user.salt,
      );
      if (!user.hashedRefreshToken) {
        return res.status(400).json({
          status: 'fail',
          message: 'User signed out.',
        });
      }
      if (user.hashedRefreshToken !== hashedRefreshToken) {
        return res.status(400).json({
          status: 'fail',
          message: 'Refresh token reused.',
        });
      }

      const publicUser = this.userService.getPublicUser(user);
      const jwtTokens = this.jwtService.generateTokens(publicUser);
      const newHashedRefreshToken = await this.authService.hash(
        jwtTokens.refreshToken,
        user.salt,
      );
      await this.userService.updateUserByEmail(user.email, {
        hashedRefreshToken: newHashedRefreshToken,
      });
      res.status(200).json({
        status: 'success',
        data: {
          accessToken: jwtTokens.accessToken,
          refreshToken: jwtTokens.refreshToken,
        },
      });
    } catch (err) {
      if (this.JWT_ERROR_LIST.includes(err.name)) {
        return res.status(400).json({
          status: 'fail',
          message: err.message,
        });
      }
      console.error(err);
      res.status(500).json({
        status: 'error',
        message: 'Internal Server Error',
      });
    }
  }
}
