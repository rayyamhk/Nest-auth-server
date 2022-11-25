import { pbkdf2 } from 'node:crypto';
import { promisify } from 'node:util';
import { Injectable } from '@nestjs/common';

const pbkdf2Async = promisify(pbkdf2);

@Injectable()
export class UtilsService {
  private readonly SALT_ITERATION = 1000;
  private readonly KEY_LEN = 64;
  private readonly HASH_ALGO = 'sha512';
  private readonly ENCODING = 'base64';

  formatResponse(message: any, data?: any) {
    return {
      status: 'success',
      message,
      data: data || {},
    };
  }

  async hash(plaintext: string, salt: string) {
    const hashed = await pbkdf2Async(
      plaintext,
      salt,
      this.SALT_ITERATION,
      this.KEY_LEN,
      this.HASH_ALGO,
    );
    const stringified = hashed.toString(this.ENCODING);
    return stringified;
  }
}
