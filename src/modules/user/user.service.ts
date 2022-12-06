import { Injectable } from '@nestjs/common';
import { DatabaseService } from '../database/database.service';
import { User } from './types/User';

@Injectable()
export class UserService {
  constructor(private readonly usersDatabaseService: DatabaseService<User>) {}

  async get(email: string) {
    return await this.usersDatabaseService.findOne({ email });
  }

  async create(user: User) {
    return await this.usersDatabaseService.insertOne(user);
  }

  async replace(user: User) {
    return await this.usersDatabaseService.replaceOne(user);
  }

  serialize(user: Partial<User>): Partial<User> {
    return {
      _id: user._id,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
    };
  }
}
