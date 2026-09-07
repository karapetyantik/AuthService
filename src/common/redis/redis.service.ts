import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis/built/Redis';

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  public client!: Redis;

  constructor(private readonly config: ConfigService) {}

  onModuleInit() {
    this.client = new Redis({
      host: this.config.get<string>('REDIS_HOST', 'localhost'),
      port: this.config.get<number>('REDIS_PORT', 6379),
    });
  }

  async onModuleDestroy() {
    await this.client.quit();
  }
}
