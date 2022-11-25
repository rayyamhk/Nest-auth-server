import { ValidationPipe } from '@nestjs/common';
import { APP_FILTER, NestFactory } from '@nestjs/core';
import helmet from 'helmet';
import { AppModule } from './app.module';
import { AllExceptionFilter } from './filters/allException.filter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  // Helmet is not required because it is a private server (authorized by x-api-key).
  app.use(helmet.hidePoweredBy());
  app.useGlobalFilters(new AllExceptionFilter());
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // remove unnecessary fields
    }),
  );
  await app.listen(process.env.PORT || 8081);
}
bootstrap();
