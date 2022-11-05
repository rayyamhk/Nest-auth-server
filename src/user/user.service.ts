import { Inject, Injectable } from '@nestjs/common';
import { DatabaseService } from '../database/database.service';
import { PublicUser, User } from './interface/user';

@Injectable()
export class UserService {
  constructor(@Inject('USERS_DATABASE_SERVICE') private readonly usersDatabaseService: DatabaseService<User>) {}

  async getUserByEmail(email: string) {
    return await this.usersDatabaseService.get({ email });
  }

  async createUser(user: User) {
    return await this.usersDatabaseService.create(user);
  }

  async updateUserByEmail(email: string, updatedFields: Partial<User>) {
    return await this.usersDatabaseService.update({ email }, updatedFields);
  }

  getPublicUser(user: User): PublicUser {
    return {
      id: user.id,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
    };
  }
}
