import {
  ConflictException,
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException
} from '@nestjs/common'
import { JwtService, JwtSignOptions } from '@nestjs/jwt'
import type { ConfigService, ConfigType } from '@nestjs/config'
import {
  IJWTPayload,
  IAccessPayload,
  IUserPayload
} from '../shared/types/auth.types'
import { randomUUID } from 'node:crypto'
import { RefreshTokenService } from '../refresh-token/refresh-token.service'
import jwtConfig from '../config/auth-config/jwt.config'
import { LoginUserDto } from './dto/login-user.dto'
import { UserService } from '../user/user.service'
import type { IHasher } from '../shared/types/hasher.interface'
import { IUser } from '../shared/types/user.types'
import { RegisterUserDto } from './dto/register-user.dto'
import type { Response } from 'express'
import { CookieKey } from '../shared/constants/cookie-key.constant'

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name)

  constructor(
    private readonly jwtService: JwtService,
    // private readonly config: ConfigService,
    private readonly refreshTokenService: RefreshTokenService,
    @Inject(jwtConfig.KEY)
    private readonly jwtOptions: ConfigType<typeof jwtConfig>,
    private readonly userService: UserService,
    @Inject('Hasher') private readonly hasher: IHasher
  ) {}

  // private validateUser(username: string, password: string): IUserPayload {
  //   const localUser = MOCK_USER
  //   if (username !== localUser.username || password !== localUser.password) {
  //     throw new UnauthorizedException('Invalid credentials')
  //   }
  //
  //   return this.toUserPayload(localUser)
  // }

  public async register(dto: RegisterUserDto) {
    const { username, password } = dto

    const exists = await this.userService.findByUsername(username)
    if (exists) {
      throw new ConflictException('User with this name already exists')
    }

    const passwordHash = await this.hasher.hash(password)

    const user: IUser = {
      username,
      passwordHash
    }

    return await this.userService.saveUser(user)
  }

  public async createTokens(user: IUser) {
    const accessPayload: IAccessPayload = {
      sub: user.id,
      username: user.username
    }

    const refreshPayload = {
      ...accessPayload,
      tokenId: randomUUID()
    }

    await this.refreshTokenService.createRefreshSession(refreshPayload)

    try {
      const accessToken = await this.jwtService.signAsync(accessPayload)
      const refreshToken = await this.jwtService.signAsync(refreshPayload, {
        secret: this.jwtOptions.refreshTokenSecret,
        expiresIn: this.jwtOptions.refreshTokenExpiresIn
      })

      return { accessToken, refreshToken }
    } catch (e) {
      const error = e as { message: string }
      this.logger.error('[Token generation error]: ' + error.message)
      throw new HttpException(
        'Ошибка при создании токена.',
        HttpStatus.INTERNAL_SERVER_ERROR
      )
    }
  }

  public async setCookie(
    res: Response,
    accessToken: string,
    refreshToken: string
  ) {
    const accessTtl = this.jwtOptions.accessTokenExpiresIn
    const refreshTtl = this.jwtOptions.refreshTokenExpiresIn

    res.cookie(CookieKey.Access, accessToken, {
      httpOnly: true,
      secure: false,
      sameSite: false,
      maxAge: accessTtl
    })

    res.cookie(CookieKey.Refresh, refreshToken, {
      httpOnly: true,
      secure: false, // только для демонстрации
      sameSite: 'lax',
      maxAge: refreshTtl
    })
    this.logger.log(
      `Cookies successfully set: [${CookieKey.Access}], [${CookieKey.Refresh}] ${refreshToken}`
    )
  }

  public async verifyUser(dto: LoginUserDto) {
    const { username, password } = dto
    const existUser = await this.userService.findByUsername(username)

    if (!existUser) {
      throw new NotFoundException('User not found')
    }
    const isCorrectPassword = existUser.passwordHash
      ? await this.hasher.compareHash(password, existUser.passwordHash)
      : false

    if (!isCorrectPassword) {
      throw new UnauthorizedException('User password is wrong')
    }

    return existUser
  }

  // private createAccessToken(user: IUserPayload): string {
  //   return this.jwtService.sign(
  //     { user },
  //     {
  //       secret: this.config.getOrThrow<string>('JWT_ACCESS_SECRET'),
  //       expiresIn: this.config.getOrThrow<string>(
  //         'JWT_ACCESS_EXPIRES_IN'
  //       ) as JwtSignOptions['expiresIn']
  //     }
  //   )
  // }
  // private createRefreshToken(user: IUserPayload): string {
  //   return this.jwtService.sign(
  //     { user },
  //     {
  //       secret: this.config.getOrThrow<string>('JWT_REFRESH_SECRET'),
  //       expiresIn: this.config.getOrThrow<string>(
  //         'JWT_REFRESH_EXPIRES_IN'
  //       ) as JwtSignOptions['expiresIn']
  //     }
  //   )
  // }

  // login(username: string, password: string) {
  //   const user = this.validateUser(username, password)
  //
  //   const accessToken = this.createAccessToken(user)
  //   const refreshToken = this.createRefreshToken(user)
  //
  //   return {
  //     accessToken,
  //     refreshToken
  //   }
  // }

  // refresh(refreshToken?: string) {
  //   if (!refreshToken) {
  //     throw new UnauthorizedException('No refresh token')
  //   }
  //
  //   try {
  //     const payload = this.jwtService.verify<IJWTPayload>(refreshToken, {
  //       secret: this.config.getOrThrow<string>('JWT_REFRESH_SECRET')
  //     })
  //
  //     const newAccessToken = this.createAccessToken(payload.user)
  //     const newRefreshToken = this.createRefreshToken(payload.user)
  //
  //     return {
  //       accessToken: newAccessToken,
  //       refreshToken: newRefreshToken
  //     }
  //   } catch {
  //     throw new UnauthorizedException('Invalid refresh token')
  //   }
  // }

  // toUserPayload(localUser: IUser): IUserPayload {
  //   // eslint-disable-next-line @typescript-eslint/no-unused-vars
  //   const { password, ...userWithoutPassword } = localUser
  //   return userWithoutPassword
  // }
}
