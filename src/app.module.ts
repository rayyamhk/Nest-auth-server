import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { authMiddleware } from './middlewares/auth';

@Module({
  imports: [ConfigModule.forRoot(), AuthModule],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(authMiddleware).forRoutes('/auth');
  }
}
