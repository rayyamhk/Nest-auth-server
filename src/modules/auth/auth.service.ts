import { randomBytes, randomUUID } from 'node:crypto';
import {
  ConflictException,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { UserService } from '../user/user.service';
import { UtilsService } from '../utils/utils.service';
import { JWTService } from '../jwt/jwt.service';
import { User } from '../user/types/User';
import { CreateUserDTO } from './dto/user.dto';
import { EMAIL_REGEX, STRONG_PASSWORD_REGEX } from '../../constants';

@Injectable()
export class AuthService {
  private readonly ENCODING = 'base64';
  private readonly SALT_BYTE = 16;

  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JWTService,
    private readonly utilsService: UtilsService,
  ) {}

  async signUp({ email, password }: CreateUserDTO) {
    const existedUser = await this.userService.get(email);
    if (existedUser)
      throw new ConflictException(`User existed (email: ${email})`);
    const now = new Date().toISOString();
    const salt = this.generateSalt();
    const hashedPassword = await this.utilsService.hash(password, salt);
    const createdUser: User = {
      id: randomUUID(),
      email,
      hashedPassword,
      salt,
      role: 'user',
      createdAt: now,
      refreshTokens: {},
    };
    await this.userService.put(createdUser);
    return this.userService.serialize(createdUser);
  }

  async signIn(email: string, password: string, identifier: string, keepSession: boolean) {
    if (!this.isValidEmail(email) || !this.isValidPassword(password))
      throw new UnauthorizedException('Incorrect email or password.');
    const existedUser = await this.userService.get(email);
    if (!existedUser)
      throw new UnauthorizedException('Incorrect email or password.');
    const hashedPassword = await this.utilsService.hash(
      password,
      existedUser.salt,
    );
    if (hashedPassword !== existedUser.hashedPassword)
      throw new UnauthorizedException('Incorrect email or password.');
    const payload = this.userService.serialize(existedUser);
    const {
      accessToken,
      refreshToken,
    } = this.jwtService.generateTokens(payload);
    if (keepSession) {
      await this.userService.put({
        ...existedUser,
        refreshTokens: {
          ...existedUser.refreshTokens,
          [identifier]: refreshToken,
        },
      });
      return {
        user: payload,
        accessToken,
        refreshToken,
      }
    }
    return {
      user: payload,
      accessToken,
    };
  }

  async signOut(refreshToken: string, identifier: string) {
    const payload = this.jwtService.verifyRefreshToken(
      refreshToken,
    ) as Partial<User>;
    const user = await this.userService.get(payload.email);
    const revokedRefreshToken = user.refreshTokens[identifier];

    // already signed out
    if (!revokedRefreshToken) return;

    // refresh token reused
    if (revokedRefreshToken !== refreshToken) {
      await this.userService.put({
        ...user,
        refreshTokens: {},
      });
      throw new ForbiddenException('Refresh token reused.');
    }

    // revoke the refresh token
    delete user.refreshTokens[identifier];
    await this.userService.put({
      ...user,
      refreshTokens: {
        ...user.refreshTokens,
      },
    });
  }

  async authorize(accessToken: string) {
    const payload = this.jwtService.verifyAccessToken(accessToken) as Partial<User>;
    return this.userService.serialize(payload);
  }

  async refresh(refreshToken: string, identifier: string) {
    const payload = this.jwtService.verifyRefreshToken(
      refreshToken,
    ) as Partial<User>;
    const user = await this.userService.get(payload.email);
    const revokedRefreshToken = user.refreshTokens[identifier];
    if (!revokedRefreshToken) throw new ConflictException('User signed out.');
    if (revokedRefreshToken !== refreshToken) {
      await this.userService.put({
        ...user,
        refreshTokens: {},
      });
      throw new ForbiddenException('Refresh token reused.');
    }
    const _payload = this.userService.serialize(user);
    const tokens = this.jwtService.generateTokens(_payload);
    await this.userService.put({
      ...user,
      refreshTokens: {
        ...user.refreshTokens,
        [identifier]: tokens.refreshToken,
      },
    });
    return {
      user: _payload,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }

  // https://en.wikipedia.org/wiki/Email_address#Syntax
  private isValidEmail(email: string): boolean {
    if (!email) return false;
    if (email.length > 255) return false;
    const emailParts = email.split('@');
    if (emailParts.length !== 2) return false;
    const [localPart, domain] = emailParts;
    if (localPart.length > 64) return false;
    const domainParts = domain.split('.');
    if (domainParts.length < 2 || domainParts.some((part) => part.length > 63))
      return false;
    return EMAIL_REGEX.test(email);
  }

  private isValidPassword(password: string): boolean {
    if (!password || password.length < 8) return false;
    return STRONG_PASSWORD_REGEX.test(password);
  }

  private generateSalt(): string {
    return randomBytes(this.SALT_BYTE).toString(this.ENCODING);
  }
}
