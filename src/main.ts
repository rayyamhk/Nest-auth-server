import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import helmet from 'helmet';
import * as cookieParser from 'cookie-parser';
import { AppModule } from './app.module';
import { AllExceptionFilter } from './filters/allException.filter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(helmet.hidePoweredBy());
  app.useGlobalFilters(new AllExceptionFilter());
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // remove unnecessary fields
    }),
  );
  app.enableCors({
    origin: process.env.CLIENT_ORIGIN || '*',
    methods: 'POST', // only POST request allowed
    credentials: true, // allows credentials (cookie) from clients
  });
  app.use(cookieParser());
  await app.listen(process.env.PORT || 8081);
}
bootstrap();
