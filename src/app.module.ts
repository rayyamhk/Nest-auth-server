import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './modules/auth/auth.module';
import { UtilsModule } from './modules/utils/utils.module';

@Module({
  imports: [ConfigModule.forRoot(), UtilsModule, AuthModule],
})
export class AppModule {}
