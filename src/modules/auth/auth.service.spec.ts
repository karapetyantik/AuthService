import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { PrismaService } from '@common/prisma/prisma.service';
import { EmailService } from '@modules/email/email.service';
import { RedisService } from '@common/redis/redis.service';

describe('AuthService', () => {
  let service: AuthService;
  let redisStore: Map<string, string>;

  beforeEach(async () => {
    redisStore = new Map();

    const redisClientMock = {
      get: jest.fn((key: string) =>
        Promise.resolve(redisStore.get(key) ?? null),
      ),
      set: jest.fn((key: string, value: string) => {
        redisStore.set(key, value);
        return Promise.resolve('OK');
      }),
      del: jest.fn((key: string) => {
        redisStore.delete(key);
        return Promise.resolve(1);
      }),
      incr: jest.fn(),
      expire: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: PrismaService,
          useValue: {
            user: { findFirst: jest.fn(), findUnique: jest.fn() },
            refreshToken: { deleteMany: jest.fn() },
          },
        },
        {
          provide: JwtService,
          useValue: { signAsync: jest.fn(), verifyAsync: jest.fn() },
        },
        {
          provide: ConfigService,
          useValue: { get: jest.fn(), getOrThrow: jest.fn() },
        },
        {
          provide: EmailService,
          useValue: {
            sendVerificationEmail: jest.fn(),
            sendPasswordResetEmail: jest.fn(),
          },
        },
        { provide: RedisService, useValue: { client: redisClientMock } },
        { provide: 'RABBITMQ_SERVICE', useValue: { emit: jest.fn() } },
      ],
    }).compile();

    service = module.get(AuthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('OAuth exchange code', () => {
    it('returns the tokens exactly once and rejects a second exchange', async () => {
      const tokens = { accessToken: 'a', refreshToken: 'b' };
      const code = await service.createOauthExchangeCode(tokens);

      await expect(service.exchangeOauthCode(code)).resolves.toEqual(tokens);
      await expect(service.exchangeOauthCode(code)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('rejects an unknown code', async () => {
      await expect(service.exchangeOauthCode('does-not-exist')).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });
});
