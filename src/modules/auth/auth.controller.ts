import {
  Controller,
  Body,
  Post,
  Get,
  Param,
  UseGuards,
  Req,
  Res,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { Throttle } from '@nestjs/throttler';
import { Response } from 'express';
import { AuthService, AuthTokens } from './auth.service';
import { JwtAuthGuard } from './jwt/jwt-auth.guard';
import { AuthenticatedRequest } from './jwt/authenticated-request.interface';
import { OauthRequest } from './oauth/oauth-request.interface';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshDto } from './dto/refresh.dto';
import { VerifyEmailCodeDto } from './dto/verify-email-code.dto';
import { ResendVerificationDto } from './dto/resend-verification.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { TotpCodeDto } from './dto/totp.dto';
import { TotpLoginDto } from './dto/totp-login.dto';
import { OauthExchangeDto } from './dto/oauth-exchange.dto';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {}

  @Get('google')
  @UseGuards(AuthGuard('google'))
  googleAuth() {}

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthCallback(@Req() req: OauthRequest, @Res() res: Response) {
    const tokens = await this.authService.oauthLogin(req.user, 'google');
    await this.redirectWithExchangeCode(res, tokens);
  }

  @Get('github')
  @UseGuards(AuthGuard('github'))
  githubAuth() {}

  @Get('github/callback')
  @UseGuards(AuthGuard('github'))
  async githubAuthCallback(@Req() req: OauthRequest, @Res() res: Response) {
    const tokens = await this.authService.oauthLogin(req.user, 'github');
    await this.redirectWithExchangeCode(res, tokens);
  }

  private async redirectWithExchangeCode(res: Response, tokens: AuthTokens) {
    const code = await this.authService.createOauthExchangeCode(tokens);
    const frontendUrl = this.configService.get<string>(
      'FRONTEND_URL',
      'http://localhost:5173',
    );
    res.redirect(`${frontendUrl}/oauth/callback?code=${code}`);
  }

  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @Post('oauth/exchange')
  exchangeOauthCode(@Body() dto: OauthExchangeDto) {
    return this.authService.exchangeOauthCode(dto.code);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Req() req: AuthenticatedRequest) {
    return req.user;
  }

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('refresh')
  refresh(@Body() dto: RefreshDto) {
    return this.authService.refresh(dto.refreshToken);
  }

  @Post('forgot-password')
  forgotPassword(@Body() dto: ForgotPasswordDto) {
    return this.authService.forgotPassword(dto.email);
  }

  @Post('reset-password')
  resetPassword(@Body() dto: ResetPasswordDto) {
    return this.authService.resetPassword(dto.token, dto.newPassword);
  }

  @UseGuards(JwtAuthGuard)
  @Post('change-password')
  changePassword(
    @Req() req: AuthenticatedRequest,
    @Body() dto: ChangePasswordDto,
  ) {
    return this.authService.changePassword(
      req.user.userId,
      dto.currentPassword,
      dto.newPassword,
    );
  }

  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @Post('logout')
  logout(@Body() dto: RefreshDto) {
    return this.authService.logout(dto.refreshToken);
  }

  @Post('verify-email')
  verifyEmailByCode(@Body() dto: VerifyEmailCodeDto) {
    return this.authService.verifyEmailByCode(dto.email, dto.code);
  }

  @Get('verify-email/:token')
  verifyEmailByToken(@Param('token') token: string) {
    return this.authService.verifyEmailByToken(token);
  }

  @Post('resend-verification')
  resendVerification(@Body() dto: ResendVerificationDto) {
    return this.authService.resendVerificationEmail(dto.email);
  }

  @UseGuards(JwtAuthGuard)
  @Post('totp/generate')
  generateTotpSecret(@Req() req: AuthenticatedRequest) {
    return this.authService.generateTotpSecret(req.user.userId);
  }

  @UseGuards(JwtAuthGuard)
  @Post('totp/enable')
  enableTotp(@Req() req: AuthenticatedRequest, @Body() dto: TotpCodeDto) {
    return this.authService.enableTotp(req.user.userId, dto.code);
  }

  @UseGuards(JwtAuthGuard)
  @Post('totp/disable')
  disableTotp(@Req() req: AuthenticatedRequest, @Body() dto: TotpCodeDto) {
    return this.authService.disableTotp(req.user.userId, dto.code);
  }

  @Post('totp/login')
  verifyTotpLogin(@Body() dto: TotpLoginDto) {
    return this.authService.verifyTotpLogin(dto.tempToken, dto.code);
  }
}
