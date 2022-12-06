import { DynamicModule, Module } from '@nestjs/common';
import { COLLECTION_NAME } from '../../constants';
import { DatabaseService } from './database.service';

@Module({})
export class DatabaseModule {
  static register(collectionName: string): DynamicModule {
    return {
      module: DatabaseModule,
      providers: [
        {
          provide: COLLECTION_NAME,
          useValue: collectionName,
        },
        DatabaseService,
      ],
      exports: [DatabaseService],
    };
  }
}
