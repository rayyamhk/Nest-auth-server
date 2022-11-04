import { Injectable } from '@nestjs/common';
import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  UpdateItemCommand,
} from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { User } from '../user/interface/user';

@Injectable()
export class DatabaseService {
  private readonly ddbClient: DynamoDBClient;
  private readonly USER_TABLE_NAME = 'Users';
  private readonly REGION = process.env.REGION || 'us-east-2';

  constructor() {
    this.ddbClient = new DynamoDBClient({ region: this.REGION });
  }

  async getUser(email: string) {
    try {
      const res = await this.ddbClient.send(
        new GetItemCommand({
          TableName: this.USER_TABLE_NAME,
          Key: {
            email: { S: email },
          },
        }),
      );
      if (!res.Item) return null;
      const data = unmarshall(res.Item) as User;
      return data;
    } catch (err) {
      console.error('[Database Service] getUser: ', err);
      throw err;
    }
  }

  async createUser(user: User) {
    try {
      const item = marshall(user);
      const res = await this.ddbClient.send(
        new PutItemCommand({
          TableName: this.USER_TABLE_NAME,
          Item: item,
        }),
      );
      return res;
    } catch (err) {
      console.error('[Database Service] createUser: ', err);
      throw err;
    }
  }

  async updateUser(email: string, updatedField: Partial<User>) {
    try {
      const marshalled = marshall(updatedField);
      const expressions = [];
      let i = 1;
      const ExpressionAttributeValues = {};
      for (const key in updatedField) {
        expressions.push(` ${key} = :v${i}`);
        ExpressionAttributeValues[`:v${i}`] = marshalled[key];
        i += 1;
      }
      if (expressions.length !== 0) {
        await this.ddbClient.send(
          new UpdateItemCommand({
            TableName: this.USER_TABLE_NAME,
            Key: {
              email: { S: email },
            },
            UpdateExpression: 'SET' + expressions.join(','),
            ExpressionAttributeValues,
            ReturnValues: 'NONE',
          }),
        );
      }
    } catch (err) {
      console.error('[Database Service] updateUser: ', err);
      throw err;
    }
  }
}
