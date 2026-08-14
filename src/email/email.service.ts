import { Injectable, OnModuleInit } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService implements OnModuleInit {
  private transporter!: nodemailer.Transporter;

  async onModuleInit() {
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

    console.log('📧 Ethereal test account created:', testAccount.user);
  }

  async sendVerificationEmail(to: string, code: string, token: string) {
    const verifyLink = `http://localhost:3000/auth/verify-email/${token}`;

    const info = await this.transporter.sendMail({
      from: '"Chat Alpha" <no-reply@chat-alpha.dev>',
      to,
      subject: 'Подтвердите email',
      html: `
          <p>Ваш код подтверждения: <b>${code}</b></p>
          <p>Или перейдите по ссылке: <a href="${verifyLink}">ACTIVE</a></p>
        `,
    });

    console.log(
      '📨 Письмо отправлено, посмотреть можно здесь:',
      nodemailer.getTestMessageUrl(info),
    );
  }

  async sendPasswordResetEmail(to: string, token: string) {
    const resetLink = `http://localhost:3000/auth/reset-password/${token}`;

    const info = await this.transporter.sendMail({
      from: '"Chat Alpha" <no-reply@chat-alpha.dev>',
      to,
      subject: 'Сброс пароля',
      html: `
        <p>Вы запросили сброс пароля.</p>
        <p>Перейдите по ссылке, чтобы задать новый пароль: <a href="${resetLink}">${resetLink}</a></p>
        <p>Если это были не вы — просто проигнорируйте это письмо.</p>
    `,
    });

    console.log(
      '📨 Письмо сброса пароля отправлено:',
      nodemailer.getTestMessageUrl(info),
    );
  }
}
