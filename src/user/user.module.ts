import { Module } from '@nestjs/common';
import { UsersDatabaseModule } from '../database/usersDatabase.module';
import { UserService } from './user.service';

@Module({
  imports: [UsersDatabaseModule],
  providers: [UserService],
  exports: [UserService],
})
export class UserModule {}
