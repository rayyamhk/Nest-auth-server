import { IsEmail, Matches, MinLength } from 'class-validator';
import { STRONG_PASSWORD_REGEX } from '../../../constants';

export class CreateUserDTO {
  @IsEmail()
  email: string;

  @MinLength(8)
  @Matches(STRONG_PASSWORD_REGEX)
  password: string;
}
