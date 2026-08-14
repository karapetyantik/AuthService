import {
  Injectable,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { randomBytes, createHash } from 'crypto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import ms, { StringValue } from 'ms';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { EmailService } from 'src/email/email.service';
import { RedisService } from 'src/redis/redis.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly config: ConfigService,
    private readonly emailService: EmailService,
    private readonly redisService: RedisService,
  ) {}

  async register(dto: RegisterDto) {
    const existingUser = await this.prisma.user.findFirst({
      where: { OR: [{ email: dto.email }, { username: dto.username }] },
    });
    if (existingUser) {
      throw new ConflictException(
        'User with this email or username already exists',
      );
    }

    const passwordHash = await bcrypt.hash(dto.password, 10);

    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        username: dto.username,
        passwordHash,
      },
    });

    await this.sendVerificationEmail(user.email);

    const { passwordHash: _, ...safeUser } = user;
    return safeUser;
  }

  async login(dto: LoginDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });
    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    } else if (user.isEmailVerified === false) {
      throw new UnauthorizedException('Email not verified');
    }

    const isPasswordValid = await bcrypt.compare(
      dto.password,
      user.passwordHash,
    );
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid email or password');
    }

    return this.issueTokens(user.id, user.email);
  }

  async resendVerificationEmail(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });

    if (!user) {
      return { success: true };
    }
    if (user.isEmailVerified) {
      throw new ConflictException('Email уже подтвержден');
    }

    await this.sendVerificationEmail(user.email);
    return { success: true };
  }

  private async sendVerificationEmail(email: string) {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    await this.redisService.client.set(
      `email_verification_code:${email}`,
      code,
      'EX',
      15 * 60,
    );

    const token = await this.jwtService.signAsync(
      { email, purpose: 'verify-email' },
      { expiresIn: '15m' },
    );

    await this.emailService.sendVerificationEmail(email, code, token);
  }

  async verifyEmailByCode(email: string, code: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });

    if (user?.isEmailVerified) {
      return { success: true, alreadyVerified: true };
    }

    const storedCode = await this.redisService.client.get(
      `email_verification_code:${email}`,
    );

    if (!user || storedCode !== code) {
      const attemptsKey = `email_verification_attempts:${email}`;
      const attempts = await this.redisService.client.incr(attemptsKey);

      if (attempts === 1) {
        await this.redisService.client.expire(attemptsKey, 15 * 60);
      }
      if (attempts > 5) {
        throw new UnauthorizedException(
          'Превышено количество попыток. Попробуйте через 15 минут.',
        );
      }
      throw new UnauthorizedException('Неверный код подтверждения');
    }

    await this.redisService.client.del(`email_verification_attempts:${email}`);
    await this.redisService.client.del(`email_verification_code:${email}`);
    return this.markEmailVerified(user.id);
  }

  async verifyEmailByToken(token: string) {
    let payload: { email: string; purpose: string };
    try {
      payload = await this.jwtService.verifyAsync(token);
    } catch {
      throw new UnauthorizedException(
        'Ссылка подтверждения недействительна или истекла',
      );
    }

    if (payload.purpose !== 'verify-email') {
      throw new UnauthorizedException('Неверный тип токена');
    }

    const user = await this.prisma.user.findUnique({
      where: { email: payload.email },
    });
    if (!user) {
      throw new UnauthorizedException('Пользователь не найден');
    }
    if (user.isEmailVerified) {
      return { success: true, alreadyVerified: true };
    }

    return this.markEmailVerified(user.id);
  }

  private async markEmailVerified(userId: string) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { isEmailVerified: true },
    });
    return { success: true };
  }

  async forgotPassword(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      return { success: true };
    }

    const attemptsKey = `password_reset_attempts:${email}`;
    const attempts = await this.redisService.client.incr(attemptsKey);
    if (attempts === 1) {
      await this.redisService.client.expire(attemptsKey, 60 * 60);
    }
    if (attempts > 3) {
      return { success: true };
    }

    const resetToken = randomBytes(32).toString('hex');
    await this.redisService.client.set(
      `password_reset_token:${resetToken}`,
      user.email,
      'EX',
      60 * 60,
    );

    await this.emailService.sendPasswordResetEmail(user.email, resetToken);
    return { success: true };
  }

  async resetPassword(token: string, newPassword: string) {
    const key = `password_reset_token:${token}`;
    const email = await this.redisService.client.get(key);

    if (!email) {
      throw new UnauthorizedException(
        'Ссылка сброса пароля недействительна или истекла',
      );
    }

    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new UnauthorizedException('Пользователь не найден');
    }

    const isSamePassword = await bcrypt.compare(newPassword, user.passwordHash);
    if (isSamePassword) {
      throw new ConflictException('Новый пароль не должен совпадать со старым');
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);

    await this.prisma.user.update({
      where: { id: user.id },
      data: { passwordHash },
    });
    await this.prisma.refreshToken.deleteMany({ where: { userId: user.id } });
    await this.redisService.client.del(key); // одноразовость — сразу удаляем после использования

    return { success: true };
  }

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
  ) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new UnauthorizedException('Пользователь не найден');
    }

    const isCurrentPasswordValid = await bcrypt.compare(
      currentPassword,
      user.passwordHash,
    );
    if (!isCurrentPasswordValid) {
      throw new UnauthorizedException('Неверный текущий пароль');
    }

    const isSamePassword = await bcrypt.compare(newPassword, user.passwordHash);
    if (isSamePassword) {
      throw new ConflictException('Новый пароль не должен совпадать со старым');
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);
    await this.prisma.user.update({
      where: { id: user.id },
      data: { passwordHash },
    });

    await this.prisma.refreshToken.deleteMany({ where: { userId: user.id } });
    return { success: true };
  }

  async refresh(refreshToken: string) {
    const tokenHash = this.hashToken(refreshToken);
    const stored = await this.prisma.refreshToken.findUnique({
      where: { tokenHash },
      include: { user: true },
    });

    if (!stored || stored.expiresAt < new Date()) {
      throw new UnauthorizedException('Невалидный или истёкший refresh token');
    }

    await this.prisma.refreshToken.delete({ where: { id: stored.id } });
    return this.issueTokens(stored.user.id, stored.user.email);
  }

  async logout(refreshToken: string) {
    const tokenHash = this.hashToken(refreshToken);
    await this.prisma.refreshToken.deleteMany({ where: { tokenHash } });
    return { success: true };
  }

  private async issueTokens(userId: string, email: string) {
    const accessToken = await this.jwtService.signAsync({ sub: userId, email });
    const refreshToken = randomBytes(40).toString('hex');

    const tokenHash = this.hashToken(refreshToken);
    const refreshTokenExpiry =
      this.config.get<StringValue>('JWT_REFRESH_EXPIRES_IN') ??
      ('15d' as StringValue);
    const expiresAt = new Date(Date.now() + ms(refreshTokenExpiry));

    await this.prisma.refreshToken.create({
      data: {
        tokenHash,
        userId,
        expiresAt,
      },
    });

    return { accessToken, refreshToken };
  }

  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }
}
