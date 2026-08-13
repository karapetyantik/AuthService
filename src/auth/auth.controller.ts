import { Controller, Body, Post, Get, Param } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshDto } from './dto/refresh.dto';
import { VerifyEmailCodeDto } from './dto/verify-email-code.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('register')
    register(@Body() dto: RegisterDto) {
        return this.authService.register(dto);
    }

    @Post('login')
    login(@Body() dto: LoginDto) {
        return this.authService.login(dto);
    }

    @Post('refresh')
    refresh(@Body() dto: RefreshDto) {
        return this.authService.refresh(dto.refreshToken);
    }

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
}
