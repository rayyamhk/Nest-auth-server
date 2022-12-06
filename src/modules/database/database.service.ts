import { Inject, Injectable } from '@nestjs/common';
import { Collection, Document, MongoClient } from 'mongodb';
import { COLLECTION_NAME } from '../../constants';

@Injectable()
export class DatabaseService<T> {
  private readonly collection: Collection<Document>;
  private readonly MONGO_USERNAME = process.env.MONGO_USERNAME;
  private readonly MONGO_PASSWORD = process.env.MONGO_PASSWORD;
  private readonly MONGO_HOST = process.env.MONGO_HOST;
  private readonly MONGO_DATABASE = process.env.MONGO_DATABASE;

  constructor(
    @Inject(COLLECTION_NAME) private readonly collectionName: string,
  ) {
    const uri = `mongodb://${this.MONGO_USERNAME}:${this.MONGO_PASSWORD}@${this.MONGO_HOST}?retryWrites=true&w=majority`;
    this.collection = new MongoClient(uri).db(this.MONGO_DATABASE).collection(this.collectionName);
  }

  async findOne(query: Partial<T>) {
    return await this.collection.findOne<T>(query);
  }

  async insertOne(item: T) {
    await this.collection.insertOne(item);
  }

  async replaceOne(item: T & {_id: string}) {
    await this.collection.replaceOne({ _id: item._id }, item);
  }
}
