import { randomBytes, pbkdf2, randomUUID } from 'node:crypto';
import { promisify } from 'node:util';
import { Injectable } from '@nestjs/common';
import { ROLE, User } from '../user/interface/user';

const pbkdf2Async = promisify(pbkdf2);

@Injectable()
export class AuthService {
  private readonly EMAIL_REGEX = /^[a-z0-9!#$%&'*+-/=?^_`{|}~]+(?:\.[a-z0-9!#$%&'*+-/=?^_`{|}~])*@[a-z0-9][-a-z0-9]*(?:\.[-a-z0-9]+)*\.[-a-z0-9]*[a-z0-9]$/i;
  private readonly STRONG_PASSWORD_REGEX = /(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])/;
  private readonly ENCODING = 'base64';
  private readonly SALT_BYTE = 16;
  private readonly SALT_ITERATION = 1000;
  private readonly KEY_LEN = 64;
  private readonly HASH_ALGO = 'sha512';

  // https://en.wikipedia.org/wiki/Email_address#Syntax
  isValidEmail(email: string): boolean {
    if (!email) return false;
    if (email.length > 255) return false;
    const emailParts = email.split('@');
    if (emailParts.length !== 2) return false;
    const [localPart, domain] = emailParts;
    if (localPart.length > 64) return false;
    const domainParts = domain.split('.');
    if (domainParts.length < 2 || domainParts.some((part) => part.length > 63))
      return false;
    return this.EMAIL_REGEX.test(email);
  }

  isValidPassword(password: string): boolean {
    if (!password || password.length < 8) return false;
    return this.STRONG_PASSWORD_REGEX.test(password);
  }

  async createUserObj(email: string, password: string) {
    try {
      const now = Date.now();
      const salt = this.generateSalt();
      const hashedPassword = await this.hash(password, salt);
      const user: User = {
        id: randomUUID(),
        email,
        hashedPassword,
        salt,
        role: ROLE.USER,
        createdAt: now,
        hashedRefreshToken: null,
      };
      return user;
    } catch (err) {
      throw err;
    }
  }

  async hash(plaintext: string, salt: string) {
    try {
      const hashed = await pbkdf2Async(
        plaintext,
        salt,
        this.SALT_ITERATION,
        this.KEY_LEN,
        this.HASH_ALGO,
      );
      const stringified = hashed.toString(this.ENCODING);
      return stringified;
    } catch (err) {
      console.error('AuthService: hash', err);
      throw err;
    }
  }

  private generateSalt(): string {
    return randomBytes(this.SALT_BYTE).toString(this.ENCODING);
  }
}
