import { Inject, Injectable } from '@nestjs/common';
import { Collection, Document, MongoClient } from 'mongodb';
import { COLLECTION_NAME } from '../../constants';

@Injectable()
export class DatabaseService<T> {
  private readonly collection: Collection<Document>;
  private readonly MONGO_USERNAME = process.env.MONGO_USERNAME;
  private readonly MONGO_PASSWORD = process.env.MONGO_PASSWORD;
  private readonly MONGO_HOST = process.env.MONGO_HOST || 'localhost:27017';
  private readonly MONGO_DATABASE = process.env.MONGO_DATABASE || 'test';

  constructor(
    @Inject(COLLECTION_NAME) private readonly collectionName: string,
  ) {
    const credentials =
      this.MONGO_USERNAME && this.MONGO_PASSWORD
        ? `${this.MONGO_USERNAME}:${this.MONGO_PASSWORD}@`
        : '';
    const uri = `mongodb://${credentials}${this.MONGO_HOST}?retryWrites=true&w=majority`;
    this.collection = new MongoClient(uri)
      .db(this.MONGO_DATABASE)
      .collection(this.collectionName);
  }

  async findOneByEmail(email: string) {
    return await this.collection.findOne<T>({ email });
  }

  async insertOne(item: T) {
    await this.collection.insertOne(item);
  }

  async replaceOneById(id: string, item: T) {
    await this.collection.replaceOne({ _id: id }, item);
  }
}
