import { Body, Controller, Headers, HttpException, HttpStatus, Post } from '@nestjs/common';
import { JWTService } from '../jwt/jwt.service';
import { UserService } from '../user/user.service';
import { AuthService } from './auth.service';
import { PublicUser } from '../user/interface/user';
import { CreateUserDTO, SignInUserDTO } from './dto/user';

@Controller('auth')
export class AuthController {
  constructor(
    private jwtService: JWTService,
    private authService: AuthService,
    private userService: UserService,
  ) {}

  @Post('signup')
  async signUp(@Body() createUserDTO: CreateUserDTO) {
    const { email, password } = createUserDTO;

    if (!email || !password) {
      throw new HttpException('Email and password are required.', HttpStatus.BAD_REQUEST);
    }

    if (!this.authService.isValidEmail(email)) {
      throw new HttpException('Invalid email format', HttpStatus.BAD_REQUEST);
    }

    if (!this.authService.isValidPassword(password)) {
      throw new HttpException('Invalid password.', HttpStatus.BAD_REQUEST);
    }

    const user = await this.userService.getUserByEmail(email);
    if (user) {
      throw new HttpException(`User with email ${email} already exists.`, HttpStatus.BAD_REQUEST);
    }

    const userObj = await this.authService.createUserObj(email, password);
    await this.userService.createUser(userObj);
    return {
      statusCode: 200,
    };
  }
  @Post('signin')
  async signIn(@Body() signInUserDTO: SignInUserDTO) {
    const { email, password } = signInUserDTO;

    if (!email || !password) {
      throw new HttpException('Email and password are required.', HttpStatus.BAD_REQUEST);
    }

    const user = await this.userService.getUserByEmail(email);
    if (!user) {
      throw new HttpException('Incorrect email or password.', HttpStatus.UNAUTHORIZED);
    }

    const hashedPassword = await this.authService.hash(password, user.salt);
    if (hashedPassword !== user.hashedPassword) {
      throw new HttpException('Incorrect email or password.', HttpStatus.UNAUTHORIZED);
    }

    const publicUser = this.userService.getPublicUser(user);
    const jwtTokens = this.jwtService.generateTokens(publicUser);
    const hashedRefreshToken = await this.authService.hash(jwtTokens.refreshToken, user.salt);
    await this.userService.updateUserByEmail(user.email, { hashedRefreshToken });
    return {
      statusCode: 200,
      data: {
        accessToken: jwtTokens.accessToken,
        refreshToken: jwtTokens.refreshToken,
      },
    };
  }

  @Post('signout')
  async signOut(@Headers('authorization') authHeader: string) {
    const accessToken: string = this.jwtService.getTokenFromAuthHeader(authHeader);
    if (!accessToken) {
      throw new HttpException('Invalid authorization header.', HttpStatus.BAD_REQUEST);
    }

    const tokenPayload = this.jwtService.verifyAccessToken(accessToken) as PublicUser;
    const user = await this.userService.getUserByEmail(tokenPayload.email);
    await this.userService.updateUserByEmail(user.email, { hashedRefreshToken: null });
    return {
      statusCode: 200,
    };
  }

  @Post('authorize')
  authorize(@Headers('authorization') authHeader: string) {
    const accessToken: string = this.jwtService.getTokenFromAuthHeader(authHeader);
    if (!accessToken) {
      throw new HttpException('Invalid authorization header.', HttpStatus.FORBIDDEN);
    }

    const tokenPayload = this.jwtService.verifyAccessToken(accessToken) as PublicUser;
    return {
      statusCode: 200,
      data: {
        user: tokenPayload,
      },
    };
  }

  @Post('refresh')
  async refresh(@Headers('authorization') authHeader: string) {
    const refreshToken: string = this.jwtService.getTokenFromAuthHeader(authHeader);
    if (!refreshToken) {
      throw new HttpException('Invalid authorization header.', HttpStatus.BAD_REQUEST);
    }

    const tokenPayload = this.jwtService.verifyRefreshToken(refreshToken) as PublicUser;
    const user = await this.userService.getUserByEmail(tokenPayload.email);
    const hashedRefreshToken = await this.authService.hash(refreshToken, user.salt);

    if (!user.hashedRefreshToken) {
      throw new HttpException('User signed out.', HttpStatus.BAD_REQUEST);
    }

    if (user.hashedRefreshToken !== hashedRefreshToken) {
      throw new HttpException('Refresh token reused.', HttpStatus.BAD_REQUEST);
    }

    const publicUser = this.userService.getPublicUser(user);
    const jwtTokens = this.jwtService.generateTokens(publicUser);
    const newHashedRefreshToken = await this.authService.hash(jwtTokens.refreshToken, user.salt);
    await this.userService.updateUserByEmail(user.email, { hashedRefreshToken: newHashedRefreshToken });

    return {
      statusCode: 200,
      data: {
        accessToken: jwtTokens.accessToken,
        refreshToken: jwtTokens.refreshToken,
      },
    };
  }
}
