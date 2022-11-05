import { ArgumentMetadata, BadRequestException, Injectable, PipeTransform } from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class ValidateSignUpPipe implements PipeTransform {
  constructor(private readonly authService: AuthService) {}

  transform(value: any, metadata: ArgumentMetadata) {
    if (!value.email || !value.password) {
      throw new BadRequestException('Email and password are required.');
    }

    const { email, password } = value;

    if (typeof email !== 'string' || !this.authService.isValidEmail(email)) {
      throw new BadRequestException('Invalid email format.');
    }

    if (typeof password !== 'string' || !this.authService.isValidPassword(password)) {
      throw new BadRequestException('Invalid password.');
    }

    return {
      email,
      password,
    };
  }
}