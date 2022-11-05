import { ArgumentMetadata, BadRequestException, Injectable, PipeTransform, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class ValidateSignInPipe implements PipeTransform {
  constructor(private readonly authService: AuthService) {}

  transform(value: any, metadata: ArgumentMetadata) {
    if (!value.email || !value.password) {
      throw new BadRequestException('Email and password are required.');
    }

    const { email, password } = value;

    if (typeof email !== 'string' || !this.authService.isValidEmail(email)) {
      throw new UnauthorizedException('Incorrect email or password.');
    }

    if (typeof password !== 'string' || !this.authService.isValidPassword(password)) {
      throw new UnauthorizedException('Incorrect email or password.');
    }

    return {
      email,
      password,
    };
  }
}