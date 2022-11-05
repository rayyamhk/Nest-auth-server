import { Inject, Injectable } from '@nestjs/common';
import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  UpdateItemCommand,
} from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { TABLE_NAME } from '../constants';

@Injectable()
export class DatabaseService<T> {
  private readonly ddbClient: DynamoDBClient;
  private readonly REGION = process.env.REGION || 'us-east-2';

  constructor(@Inject(TABLE_NAME) private readonly tableName: string) {
    this.ddbClient = new DynamoDBClient({ region: this.REGION });
  }

  async get(key: Record<string, any>) {
    try {
      const getItemInputKey = marshall(key);
      const res = await this.ddbClient.send(new GetItemCommand({
        TableName: this.tableName,
        Key: getItemInputKey,
      }));
      if (!res.Item) return null;
      const data = unmarshall(res.Item) as T;
      return data;
    } catch (err) {
      console.error(`[Database Service] ${this.tableName} - get: `, err);
      throw err;
    }
  }

  async create(item: T) {
    try {
      await this.ddbClient.send(new PutItemCommand({
        TableName: this.tableName,
        Item: marshall(item),
      }));
    } catch (err) {
      console.error(`[Database Service] ${this.tableName} - create: `, err);
      throw err;
    }
  }

  async update(key: Record<string, any>, updatedFields: Partial<T>) {
    try {
      const marshalled = marshall(updatedFields);
      const expressions = [];
      let i = 1;
      const ExpressionAttributeValues = {};
      for (const key in updatedFields) {
        expressions.push(` ${key} = :v${i}`);
        ExpressionAttributeValues[`:v${i}`] = marshalled[key];
        i += 1;
      }
      if (expressions.length !== 0) {
        await this.ddbClient.send(
          new UpdateItemCommand({
            TableName: this.tableName,
            Key: marshall(key),
            UpdateExpression: 'SET' + expressions.join(','),
            ExpressionAttributeValues,
            ReturnValues: 'NONE',
          }),
        );
      }
    } catch (err) {
      console.error(`[Database Service] ${this.tableName} - update: `, err);
      throw err;
    }
  }
}
