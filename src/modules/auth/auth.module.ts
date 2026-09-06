import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import type { StringValue } from 'ms';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PrismaModule } from '../../common/prisma/prisma.module';
import { EmailModule } from 'src/modules/email/email.module';
import { RedisModule } from 'src/common/redis/redis.module';
import { JwtStrategy } from './jwt/jwt.strategy';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { GoogleStrategy } from './oauth/google.strategy';
import { GitHubStrategy } from './oauth/github.strategy';

@Module({
  imports: [
    PrismaModule,
    EmailModule,
    RedisModule,
    ClientsModule.registerAsync([
      {
        name: 'RABBITMQ_SERVICE',
        useFactory: (config: ConfigService) => ({
          transport: Transport.RMQ,
          options: {
            urls: [config.getOrThrow<string>('RABBITMQ_URL')],
            queue: 'user_events',
            queueOptions: { durable: true },
          },
        }),
        inject: [ConfigService],
      },
    ]),
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.getOrThrow<string>('JWT_SECRET'),
        signOptions: {
          expiresIn:
            config.get<StringValue>('JWT_ACCESS_EXPIRES_IN') ??
            ('30m' as StringValue),
        },
      }),
    }),
  ],
  providers: [AuthService, JwtStrategy, GoogleStrategy, GitHubStrategy],
  controllers: [AuthController],
})
export class AuthModule {}
