import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { UtilsService } from '../utils/utils.service';
import { AuthGuard } from '../../guards/auth.guard';
import { AccessToken } from './decorators/accessToken.decorator';
import { RefreshToken } from './decorators/refreshToken.decorator';
import { AgentIdentifier } from './decorators/agentIdentifier.decorator';
import { CreateUserDTO } from './dto/user.dto';

@Controller()
@UseGuards(AuthGuard)
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly utilsService: UtilsService,
  ) {}

  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  async signUp(@Body() body: CreateUserDTO) {
    const user = await this.authService.signUp(body);
    return this.utilsService.formatResponse(null, user);
  }

  @Post('signin')
  @HttpCode(HttpStatus.OK)
  async signIn(
    @Body('email') email: string,
    @Body('password') password: string,
    @AgentIdentifier() identifier: string,
  ) {
    const payload = await this.authService.signIn(email, password, identifier);
    return this.utilsService.formatResponse('User signed in.', payload);
  }

  @Post('signout')
  @HttpCode(HttpStatus.ACCEPTED)
  async signOut(
    @RefreshToken() refreshToken: string,
    @AgentIdentifier() identifier: string,
  ) {
    await this.authService.signOut(refreshToken, identifier);
    return this.utilsService.formatResponse('Signed out.');
  }

  @Post('authorize')
  @HttpCode(HttpStatus.OK)
  async authorize(@AccessToken() accessToken: string) {
    const payload = await this.authService.authorize(accessToken);
    return this.utilsService.formatResponse('Authorized.', payload);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @RefreshToken() refreshToken: string,
    @AgentIdentifier() identifier: string,
  ) {
    const tokens = await this.authService.refresh(refreshToken, identifier);
    return this.utilsService.formatResponse(null, tokens);
  }
}
