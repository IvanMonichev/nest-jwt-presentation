import { Body, Controller, Post, Res, Req } from '@nestjs/common';
import type { Response } from 'express';
import { AuthService } from './auth.service';
import type { IAuthRequest, ILoginDto } from './types';

@Controller()
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Post('login')
  login(@Body() dto: ILoginDto, @Res({ passthrough: true }) res: Response) {
    const { accessToken, refreshToken } = this.auth.login(
      dto.username,
      dto.password,
    );

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
    });

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/refresh',
    });

    return { success: true };
  }

  @Post('refresh')
  refresh(@Req() req: IAuthRequest, @Res({ passthrough: true }) res: Response) {
    const { accessToken, refreshToken } = this.auth.refresh(
      req.cookies?.['refresh_token'],
    );

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
    });

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/auth/refresh',
    });

    return { success: true };
  }
}
