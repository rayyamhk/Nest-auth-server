import { Injectable } from '@nestjs/common';
import { DatabaseService } from '../database/database.service';
import { PublicUser, User } from './interface/user';

@Injectable()
export class UserService {
  constructor(private databaseService: DatabaseService) {}

  async getUserByEmail(email: string) {
    try {
      const user = await this.databaseService.getUser(email);
      return user;
    } catch (err) {
      console.error(err);
      return null;
    }
  }

  async createUser(user: User) {
    return await this.databaseService.createUser(user);
  }

  async updateUserByEmail(email: string, updatedField: Partial<User>) {
    return await this.databaseService.updateUser(email, updatedField);
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
