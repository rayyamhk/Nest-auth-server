import { Module } from '@nestjs/common';
import { User } from '../user/interface/user';
import { DatabaseService } from './database.service';

const UsersDatabaseProvider = {
  provide: 'USERS_DATABASE_SERVICE',
  useValue: new DatabaseService<User>('Users'),
};

@Module({
  providers: [UsersDatabaseProvider],
  exports: [UsersDatabaseProvider],
})
export class UsersDatabaseModule {}