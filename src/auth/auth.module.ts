import { Module } from '@nestjs/common';
import { JWTModule } from 'src/jwt/jwt.module';
import { UserModule } from 'src/user/user.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

@Module({
  imports: [UserModule, JWTModule],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
