import { ArgumentMetadata, HttpException, HttpStatus, Injectable, PipeTransform } from "@nestjs/common";
import { AuthService } from "../auth.service";

@Injectable()
export class ValidateSignUpPipe implements PipeTransform {
  constructor(private readonly authService: AuthService) {}

  transform(value: any, metadata: ArgumentMetadata) {
    if (!value.email || !value.password) {
      throw new HttpException('Email and password are required.', HttpStatus.BAD_REQUEST);
    }

    const { email, password } = value;

    if (typeof email !== 'string' || !this.authService.isValidEmail(email)) {
      throw new HttpException('Invalid email format.', HttpStatus.BAD_REQUEST);
    }

    if (typeof password !== 'string' || !this.authService.isValidPassword(password)) {
      throw new HttpException('Invalid password.', HttpStatus.BAD_REQUEST);
    }

    return {
      email,
      password,
    };
  }
}