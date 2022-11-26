import { Controller, Get } from '@nestjs/common';

@Controller()
export class AppController {
  @Get('_health')
  healthCheck() {
    return 'OK';
  }
}
