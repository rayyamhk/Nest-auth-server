import {
  BadRequestException,
  Body,
  Controller,
  ForbiddenException,
  Headers,
  HttpCode,
  HttpStatus,
  Post,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { JWTService } from '../jwt/jwt.service';
import { UserService } from '../user/user.service';
import { AuthService } from './auth.service';
import { PublicUser } from '../user/interface/user';
import { CreateUserDTO, SignInUserDTO } from './dto/user.dto';
import { ValidateSignUpPipe } from './pipes/validateSignUp.pipe';
import { ValidateSignInPipe } from './pipes/validateSignIn.pipe';
import { AuthGuard } from '../guards/auth.guard';

@Controller('auth')
@UseGuards(AuthGuard)
export class AuthController {
  constructor(
    private readonly jwtService: JWTService,
    private readonly authService: AuthService,
    private readonly userService: UserService,
  ){}

  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  async signUp(@Body(ValidateSignUpPipe) createUserDTO: CreateUserDTO) {
    const { email, password } = createUserDTO;

    const user = await this.userService.getUserByEmail(email);
    if (user) {
      throw new BadRequestException(`User with email ${email} already exists.`);
    }

    const userObj = await this.authService.createUserObj(email, password);
    await this.userService.createUser(userObj);
    return {
      statusCode: HttpStatus.CREATED,
    };
  }

  @Post('signin')
  @HttpCode(HttpStatus.OK)
  async signIn(@Body(ValidateSignInPipe) signInUserDTO: SignInUserDTO) {
    const { email, password } = signInUserDTO;

    const user = await this.userService.getUserByEmail(email);
    if (!user) {
      throw new UnauthorizedException('Incorrect email or password.');
    }

    const hashedPassword = await this.authService.hash(password, user.salt);
    if (hashedPassword !== user.hashedPassword) {
      throw new UnauthorizedException('Incorrect email or password.');
    }

    const publicUser = this.userService.getPublicUser(user);
    const jwtTokens = this.jwtService.generateTokens(publicUser);
    const hashedRefreshToken = await this.authService.hash(jwtTokens.refreshToken, user.salt);
    await this.userService.updateUserByEmail(user.email, { hashedRefreshToken });
    return {
      statusCode: HttpStatus.OK,
      data: {
        accessToken: jwtTokens.accessToken,
        refreshToken: jwtTokens.refreshToken,
      },
    };
  }

  @Post('signout')
  @HttpCode(HttpStatus.ACCEPTED)
  async signOut(@Headers('authorization') authHeader: string) {
    const accessToken: string = this.jwtService.getTokenFromAuthHeader(authHeader);
    if (!accessToken) {
      throw new BadRequestException('Invalid authorization header.');
    }

    const tokenPayload = this.jwtService.verifyAccessToken(accessToken) as PublicUser;
    const user = await this.userService.getUserByEmail(tokenPayload.email);
    await this.userService.updateUserByEmail(user.email, { hashedRefreshToken: null });
    return {
      statusCode: HttpStatus.ACCEPTED,
    };
  }

  @Post('authorize')
  @HttpCode(HttpStatus.OK)
  authorize(@Headers('authorization') authHeader: string) {
    const accessToken: string = this.jwtService.getTokenFromAuthHeader(authHeader);
    if (!accessToken) {
      throw new ForbiddenException('Invalid authorization header.');
    }

    const tokenPayload = this.jwtService.verifyAccessToken(accessToken) as PublicUser;
    return {
      statusCode: HttpStatus.OK,
      data: {
        user: tokenPayload,
      },
    };
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(@Headers('authorization') authHeader: string) {
    const refreshToken: string = this.jwtService.getTokenFromAuthHeader(authHeader);
    if (!refreshToken) {
      throw new BadRequestException('Invalid authorization header.');
    }

    const tokenPayload = this.jwtService.verifyRefreshToken(refreshToken) as PublicUser;
    const user = await this.userService.getUserByEmail(tokenPayload.email);
    const hashedRefreshToken = await this.authService.hash(refreshToken, user.salt);

    if (!user.hashedRefreshToken) {
      throw new BadRequestException('User signed out.');
    }

    if (user.hashedRefreshToken !== hashedRefreshToken) {
      throw new BadRequestException('Refresh token reused.');
    }

    const publicUser = this.userService.getPublicUser(user);
    const jwtTokens = this.jwtService.generateTokens(publicUser);
    const newHashedRefreshToken = await this.authService.hash(jwtTokens.refreshToken, user.salt);
    await this.userService.updateUserByEmail(user.email, { hashedRefreshToken: newHashedRefreshToken });

    return {
      statusCode: HttpStatus.OK,
      data: {
        accessToken: jwtTokens.accessToken,
        refreshToken: jwtTokens.refreshToken,
      },
    };
  }
}
