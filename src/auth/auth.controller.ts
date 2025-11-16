import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards
} from '@nestjs/common'
import type { Response } from 'express'
import { AuthService } from './auth.service'
import { ApiBody, ApiCookieAuth, ApiResponse } from '@nestjs/swagger'
import { LocalAuthGuard } from './guards/local-auth.guard'
import { LoginRdo } from './rdo/login.rdo'
import { LoginUserDto } from './dto/login-user.dto'
import { IUser } from '../shared/types/user.types'
import { RegisterUserDto } from './dto/register-user.dto'
import { JwtRefreshGuard } from './guards/jwt-refresh.guard'
import { JwtAuthGuard } from './guards/jwt-auth.guard'
import { IUserPayload } from '../shared/types/auth.types'
import { CookieKey } from '../shared/constants/cookie-key.constant'

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @ApiBody({ type: LoginUserDto })
  @ApiResponse({
    type: LoginRdo,
    status: HttpStatus.OK,
    description: 'User has been successfully logged'
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'User not found'
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'User password is wrong'
  })
  @UseGuards(LocalAuthGuard)
  @Post('login')
  public async login(
    @Req() req: { user: IUser },
    @Res({ passthrough: true }) res: Response
  ) {
    const tokens = await this.authService.createTokens(req.user)
    this.authService.setCookie(res, tokens.accessToken, tokens.refreshToken)
    return { userId: req.user.id }
  }

  @UseGuards(JwtRefreshGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Get a new access/refresh tokens'
  })
  public async refreshToken(
    @Req() { user }: { user: IUser },
    @Res({ passthrough: true }) res: Response
  ) {
    const tokens = await this.authService.createTokens(user)
    this.authService.setCookie(res, tokens.accessToken, tokens.refreshToken)
    return { userId: user.id }
  }

  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'User has been successfully registered'
  })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: 'User with this email already exists'
  })
  @Post('register')
  public async register(@Body() dto: RegisterUserDto) {
    const { id } = await this.authService.register(dto)

    return id
  }

  @ApiCookieAuth(CookieKey.Access)
  @UseGuards(JwtAuthGuard)
  @Post('check')
  public checkToken(
    @Req() { user: payload }: Request & { user: IUserPayload }
  ) {
    return payload
  }
}
