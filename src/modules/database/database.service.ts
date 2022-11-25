import { Inject, Injectable } from '@nestjs/common';
import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
} from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { TABLE_NAME } from '../../constants';

@Injectable()
export class DatabaseService<T> {
  private readonly ddbClient: DynamoDBClient;
  private readonly REGION = process.env.REGION || 'us-east-2';

  constructor(@Inject(TABLE_NAME) private readonly tableName: string) {
    this.ddbClient = new DynamoDBClient({ region: this.REGION });
  }

  async getItemByPrimaryKey(key: Record<string, any>) {
    const res = await this.ddbClient.send(
      new GetItemCommand({
        TableName: this.tableName,
        Key: marshall(key),
      }),
    );
    if (!res.Item) return null;
    const data = unmarshall(res.Item) as T;
    return data;
  }

  async putItem(item: T) {
    await this.ddbClient.send(
      new PutItemCommand({
        TableName: this.tableName,
        Item: marshall(item),
      }),
    );
  }
}
