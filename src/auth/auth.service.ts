import { Injectable, ConflictException, UnauthorizedException} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { randomBytes, createHash } from 'crypto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import ms, { StringValue } from 'ms';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { EmailService } from 'src/email/email.service';

@Injectable()
export class AuthService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly jwtService: JwtService,
        private readonly config: ConfigService,
        private readonly emailService: EmailService
    ) {}

    async register(dto: RegisterDto) {
        const existingUser = await this.prisma.user.findFirst({
            where: {OR: [{email: dto.email}, {username: dto.username}]},
        })
        if (existingUser) {
            throw new ConflictException('User with this email or username already exists');
        }

        const passwordHash = await bcrypt.hash(dto.password, 10);

        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const verificationToken = randomBytes(32).toString('hex');
        const verificationExpiresAt = new Date(Date.now() + 15 * 60 * 1000);

        const user = await this.prisma.user.create({
            data: {
                email: dto.email,
                username: dto.username,
                passwordHash,   
                emailVerificationCode: verificationCode,
                emailVerificationToken: verificationToken,
                emailVerificationExpiresAt: verificationExpiresAt,
            }
        })

        await this.emailService.sendVerificationEmail(user.email, verificationCode, verificationToken);

        const {passwordHash:_, emailVerificationCode: __, ...safeUser} = user;
        return safeUser;
    }

    async verifyEmailByCode(email: string, code: string) {
        const user = await this.prisma.user.findUnique({ where: { email } });

        if (!user || user.emailVerificationCode !== code) {
            throw new UnauthorizedException('Неверный код подтверждения');
        }

        if (!user.emailVerificationExpiresAt || user.emailVerificationExpiresAt < new Date()) {
            throw new UnauthorizedException('Код истёк, запросите новый');
        }

        return this.markEmailVerified(user.id);
    }

    async verifyEmailByToken(token: string) {
    const user = await this.prisma.user.findUnique({ where: { emailVerificationToken: token } });

    if (!user) {
        throw new UnauthorizedException('Неверная ссылка подтверждения');
    }

    if (!user.emailVerificationExpiresAt || user.emailVerificationExpiresAt < new Date()) {
        throw new UnauthorizedException('Ссылка истекла, запросите новую');
    }

    return this.markEmailVerified(user.id);
    }

    private async markEmailVerified(userId: string) {
        await this.prisma.user.update({
            where: { id: userId },
            data: {
            isEmailVerified: true,
            emailVerificationCode: null,
            emailVerificationToken: null,
            emailVerificationExpiresAt: null,
        },
    });

    return { success: true };
    }

    async login(dto: LoginDto) {
        const user = await this.prisma.user.findUnique({
            where: {email: dto.email},
        });
        if (!user) {
            throw new UnauthorizedException('Invalid email or password');
        }

        const isPasswordValid = await bcrypt.compare(dto.password, user.passwordHash);
        if (!isPasswordValid) {
            throw new UnauthorizedException('Invalid email or password');
        }

        return this.issueTokens(user.id, user.email);
    }

    async refresh(refreshToken: string) {
        const tokenHash = this.hashToken(refreshToken);
        const stored = await this.prisma.refreshToken.findUnique({
            where: {tokenHash},
            include: {user: true},
        });
        
        if (!stored || stored.expiresAt < new Date()) {
            throw new UnauthorizedException('Невалидный или истёкший refresh token');
        }

        await this.prisma.refreshToken.delete({where: {id: stored.id}});
        return this.issueTokens(stored.user.id, stored.user.email);
    }

    async logout(refreshToken: string) {
        const tokenHash = this.hashToken(refreshToken);
        await this.prisma.refreshToken.deleteMany({ where: { tokenHash } });
        return { success: true };
    }

    private async issueTokens(userId: string, email: string) {
        const accessToken = await this.jwtService.signAsync({sub: userId, email});
        const refreshToken = randomBytes(40).toString('hex');

        const tokenHash = this.hashToken(refreshToken);
        const refreshTokenExpiry = this.config.get<StringValue>('JWT_REFRESH_EXPIRES_IN') ?? ("15d" as StringValue);
        const expiresAt = new Date(Date.now() + ms(refreshTokenExpiry));

        await this.prisma.refreshToken.create({
            data: {
                tokenHash,
                userId,
                expiresAt,
            }
        });

        return {accessToken, refreshToken};
    }

    private hashToken(token: string): string {
        return createHash('sha256').update(token).digest('hex');
    }
}
