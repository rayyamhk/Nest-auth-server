import { Module } from '@nestjs/common';
import { DatabaseModule } from '../database/database.module';
import { UserService } from './user.service';
import { USER_TABLE } from '../../constants';

@Module({
  imports: [DatabaseModule.register(USER_TABLE)],
  providers: [UserService],
  exports: [UserService],
})
export class UserModule {}
