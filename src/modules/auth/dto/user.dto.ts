import {
  IsBoolean,
  IsEmail,
  IsOptional,
  Matches,
  MinLength,
} from 'class-validator';
import { STRONG_PASSWORD_REGEX } from '../../../constants';

export class SignUpDTO {
  @IsEmail()
  email: string;

  @MinLength(8)
  @Matches(STRONG_PASSWORD_REGEX)
  password: string;
}

export class SignInDTO {
  @IsOptional()
  email?: string;

  @IsOptional()
  password?: string;

  @IsOptional()
  @IsBoolean()
  keepSession?: boolean = false;
}
