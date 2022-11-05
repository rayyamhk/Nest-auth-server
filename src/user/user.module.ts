import { Module } from '@nestjs/common';
import { DatabaseModule } from '../database/database.module';
import { UserService } from './user.service';

@Module({
  imports: [DatabaseModule.register('Users')],
  providers: [UserService],
  exports: [UserService],
})
export class UserModule {}
