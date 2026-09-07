import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import type SMTPTransport from 'nodemailer/lib/smtp-transport';

@Injectable()
export class EmailService implements OnModuleInit {
  private readonly logger = new Logger(EmailService.name);
  private transporter!: nodemailer.Transporter<SMTPTransport.SentMessageInfo>;
  private usingTestAccount = false;

  constructor(private readonly config: ConfigService) {}

  async onModuleInit() {
    const smtpHost = this.config.get<string>('SMTP_HOST');

    if (smtpHost) {
      this.transporter = nodemailer.createTransport({
        host: smtpHost,
        port: this.config.get<number>('SMTP_PORT', 587),
        secure: this.config.get<boolean>('SMTP_SECURE', false),
        auth: {
          user: this.config.getOrThrow<string>('SMTP_USER'),
          pass: this.config.getOrThrow<string>('SMTP_PASSWORD'),
        },
      });
      this.logger.log(`SMTP transport настроен: ${smtpHost}`);
      return;
    }

    this.usingTestAccount = true;
    this.logger.warn(
      'SMTP_HOST не задан — используется тестовый Ethereal-аккаунт. ' +
        'Письма НЕ доставляются реальным получателям. ' +
        'Задайте SMTP_HOST/SMTP_USER/SMTP_PASSWORD для реальной отправки.',
    );

    const testAccount = await nodemailer.createTestAccount();
    this.transporter = nodemailer.createTransport({
      host: testAccount.smtp.host,
      port: testAccount.smtp.port,
      secure: testAccount.smtp.secure,
      auth: {
        user: testAccount.user,
        pass: testAccount.pass,
      },
    });
  }

  private get fromAddress(): string {
    return this.config.get<string>('SMTP_FROM', '"Tapik" <no-reply@tapik.dev>');
  }

  async sendVerificationEmail(to: string, code: string, token: string) {
    const appUrl = this.config.get<string>('APP_URL', 'http://localhost:3000');
    const verifyLink = `${appUrl}/auth/verify-email/${token}`;

    const info = await this.transporter.sendMail({
      from: this.fromAddress,
      to,
      subject: 'Подтвердите email',
      html: `
          <p>Ваш код подтверждения: <b>${code}</b></p>
          <p>Или перейдите по ссылке: <a href="${verifyLink}">${verifyLink}</a></p>
        `,
    });

    this.logPreviewUrlIfTestAccount(info, 'Письмо подтверждения');
  }

  async sendPasswordResetEmail(to: string, token: string) {
    const frontendUrl = this.config.get<string>(
      'FRONTEND_URL',
      'http://localhost:5173',
    );
    const resetLink = `${frontendUrl}/reset-password/${token}`;

    const info = await this.transporter.sendMail({
      from: this.fromAddress,
      to,
      subject: 'Сброс пароля',
      html: `
        <p>Вы запросили сброс пароля.</p>
        <p>Перейдите по ссылке, чтобы задать новый пароль: <a href="${resetLink}">${resetLink}</a></p>
        <p>Если это были не вы — просто проигнорируйте это письмо.</p>
    `,
    });

    this.logPreviewUrlIfTestAccount(info, 'Письмо сброса пароля');
  }

  private logPreviewUrlIfTestAccount(
    info: SMTPTransport.SentMessageInfo,
    label: string,
  ) {
    if (!this.usingTestAccount) {
      return;
    }
    this.logger.log(
      `${label} отправлено (Ethereal): ${nodemailer.getTestMessageUrl(info)}`,
    );
  }
}
