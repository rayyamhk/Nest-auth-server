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

  constructor() {
    this.ddbClient = new DynamoDBClient({ region: process.env.REGION });
  }

  async getUser(email: string) {
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
  }

  async createUser(user: User) {
    const item = marshall(user);
    const res = await this.ddbClient.send(
      new PutItemCommand({
        TableName: this.USER_TABLE_NAME,
        Item: item,
      }),
    );
    return res;
  }

  async updateUser(email: string, updatedField: Partial<User>) {
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
  }
}
