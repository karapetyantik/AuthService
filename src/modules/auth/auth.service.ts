import {
  Injectable,
  Inject,
  ConflictException,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { randomBytes, createHash } from 'crypto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import ms, { StringValue } from 'ms';
import { PrismaService } from '../../common/prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { EmailService } from 'src/modules/email/email.service';
import { RedisService } from 'src/common/redis/redis.service';
import { generateSecret, generateURI, verify } from 'otplib';
import * as qrcode from 'qrcode';
import { ClientProxy } from '@nestjs/microservices';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly config: ConfigService,
    private readonly emailService: EmailService,
    private readonly redisService: RedisService,
    @Inject('RABBITMQ_SERVICE') private readonly rabbitClient: ClientProxy,
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

    this.rabbitClient.emit('user.registered', {
      userId: user.id,
      email: user.email,
      username: user.username,
    });

    const { passwordHash: _, ...safeUser } = user;
    return safeUser;
  }

  async login(dto: LoginDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });
    if (!user || !user.passwordHash) {
      throw new UnauthorizedException(
        user
          ? 'Этот аккаунт использует вход через Google'
          : 'Неверный email или пароль',
      );
    }
    // else if (user.isEmailVerified === false) {
    //   throw new UnauthorizedException('Email not verified');
    // }

    const isPasswordValid = await bcrypt.compare(
      dto.password,
      user.passwordHash,
    );
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid email or password');
    }

    if (user.isTotpEnabled) {
      const tempToken = await this.jwtService.signAsync(
        { sub: user.id, email: user.email, purpose: 'totp-login' },
        { expiresIn: '5m' },
      );
      return { requiresTotp: true, tempToken };
    }

    return this.issueTokens(user.id, user.email);
  }

  async verifyTotpLogin(tempToken: string, code: string) {
    let payload: { sub: string; purpose: string };
    try {
      payload = await this.jwtService.verifyAsync(tempToken);
    } catch {
      throw new UnauthorizedException(
        'Сессия входа истекла, авторизуйтесь заново',
      );
    }

    if (payload.purpose !== 'totp-login') {
      throw new UnauthorizedException('Неверный тип токена');
    }

    const blockKey = `totp_blocked:${payload.sub}`;
    const isBlocked = await this.redisService.client.get(blockKey);
    if (isBlocked) {
      throw new UnauthorizedException(
        'Слишком много неверных попыток. Вход заблокирован на 24 часа.',
      );
    }
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });
    if (!user || !user.isTotpEnabled || !user.totpSecret) {
      throw new UnauthorizedException('2FA не включена');
    }

    const isValid = await this.verifyTotpCode(
      payload.sub,
      user.totpSecret,
      code,
    );

    if (!isValid) {
      const attemptsKey = `totp_attempts:${payload.sub}`;
      const attempts = await this.redisService.client.incr(attemptsKey);
      if (attempts === 1) {
        await this.redisService.client.expire(attemptsKey, 15 * 60);
      }
      if (attempts >= 5) {
        await this.redisService.client.set(blockKey, '1', 'EX', 24 * 60 * 60);
        await this.redisService.client.del(attemptsKey);
        throw new UnauthorizedException(
          'Слишком много неверных попыток. Вход заблокирован на 24 часа.',
        );
      }
      throw new UnauthorizedException('Неверный код');
    }

    await this.redisService.client.del(`totp_attempts:${payload.sub}`);
    return this.issueTokens(user.id, user.email);
  }

  async oauthLogin(googleUser: {
    providerId: string;
    email: string;
    displayName: string;
  }) {
    let user = await this.prisma.user.findUnique({
      where: { providerId: googleUser.providerId },
    });

    if (!user) {
      const existingByEmail = await this.prisma.user.findUnique({
        where: { email: googleUser.email },
      });
      if (existingByEmail) {
        user = await this.prisma.user.update({
          where: { id: existingByEmail.id },
          data: {
            provider: 'google',
            providerId: googleUser.providerId,
            isEmailVerified: true,
          },
        });
      } else {
        const username = await this.generateUniqueUsername(
          googleUser.displayName,
        );
        user = await this.prisma.user.create({
          data: {
            email: googleUser.email,
            username,
            provider: 'google',
            providerId: googleUser.providerId,
            isEmailVerified: true,
          },
        });

        this.rabbitClient.emit('user.registered', {
          userId: user.id,
          email: user.email,
          username: user.username,
        });
      }
    }
    return this.issueTokens(user.id, user.email);
  }

  private async generateUniqueUsername(base: string): Promise<string> {
    const cleanBase = base.replace(/\s+/g, '').toLowerCase().slice(0, 20);
    let username = cleanBase;
    let attempt = 0;

    while (await this.prisma.user.findUnique({ where: { username } })) {
      attempt++;
      username = `${cleanBase}${attempt}`;
    }

    return username;
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

    if (user.passwordHash) {
      const isSamePassword = await bcrypt.compare(
        newPassword,
        user.passwordHash,
      );
      if (isSamePassword) {
        throw new ConflictException(
          'Новый пароль не должен совпадать со старым',
        );
      }
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);

    await this.prisma.user.update({
      where: { id: user.id },
      data: { passwordHash },
    });
    await this.prisma.refreshToken.deleteMany({ where: { userId: user.id } });
    await this.redisService.client.del(key);

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
    if (!user.passwordHash) {
      throw new BadRequestException(
        'У этого аккаунта ещё нет пароля (вход через Google) — используйте восстановление пароля, чтобы задать его',
      );
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

  async generateTotpSecret(userId: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new UnauthorizedException('Пользователь не найден');
    }
    if (user.isTotpEnabled) {
      throw new ConflictException('2FA уже включена');
    }
    const secret = generateSecret();
    await this.prisma.user.update({
      where: { id: userId },
      data: { totpSecret: secret },
    });

    const otpAuthUrl = generateURI({
      issuer: 'ChatApp',
      label: user.email,
      secret,
    });

    const qrCodeDataUrl = await qrcode.toDataURL(otpAuthUrl);
    return { qrCodeDataUrl, secret };
  }

  async enableTotp(userId: string, code: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.totpSecret) {
      throw new UnauthorizedException('Сначала сгенерируйте секрет');
    }
    if (user.isTotpEnabled) {
      throw new UnauthorizedException('2FA уже включена');
    }

    const isValid = await this.verifyTotpCode(userId, user.totpSecret, code);
    if (!isValid) {
      throw new UnauthorizedException('Неверный код 2FA');
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: { isTotpEnabled: true },
    });

    return { success: true };
  }

  async disableTotp(userId: string, code: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.totpSecret || !user.isTotpEnabled) {
      throw new UnauthorizedException('2FA не включена');
    }

    const isValid = await this.verifyTotpCode(userId, user.totpSecret, code);
    if (!isValid) {
      throw new UnauthorizedException('Неверный код 2FA');
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: { isTotpEnabled: false, totpSecret: null },
    });
    return { success: true };
  }

  private async verifyTotpCode(
    userId: string,
    secret: string,
    token: string,
  ): Promise<boolean> {
    const result = await verify({ secret, token });
    if (!result.valid) {
      return false;
    }

    const currentStep = Math.floor(Date.now() / 1000 / 30);
    const usedStep = currentStep + (result.delta ?? 0);

    const lastStepKey = `totp_last_step:${userId}`;
    const lastStep = await this.redisService.client.get(lastStepKey);

    if (lastStep !== null && Number(lastStep) >= usedStep) {
      return false;
    }

    await this.redisService.client.set(
      lastStepKey,
      usedStep.toString(),
      'EX',
      5 * 60,
    );
    return true;
  }
}
