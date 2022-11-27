import { Injectable } from '@nestjs/common';
import { DatabaseService } from '../database/database.service';
import { User } from './types/User';

@Injectable()
export class UserService {
  constructor(private readonly usersDatabaseService: DatabaseService<User>) {}

  async get(email: string) {
    return await this.usersDatabaseService.getItemByPrimaryKey({ email });
  }

  async put(user: User) {
    return await this.usersDatabaseService.putItem(user);
  }

  serialize(user: Partial<User>): Partial<User> {
    return {
      id: user.id,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
    };
  }
}
