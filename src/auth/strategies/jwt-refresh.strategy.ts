import { Inject, Injectable, UnauthorizedException } from '@nestjs/common'
import { PassportStrategy } from '@nestjs/passport'
import { ExtractJwt, Strategy } from 'passport-jwt'
import type { ConfigType } from '@nestjs/config'
import { cookieExtractor } from '../../shared/types/cookie-extractor.util'
import { RefreshTokenService } from '../../refresh-token/refresh-token.service'
import { IRefreshPayload } from '../../shared/types/refresh-token.types'
import { UserService } from '../../user/user.service'
import jwtConfig from '../../config/auth-config/jwt.config'
import { CookieKey } from '../../shared/constants/cookie-key.constant'
import { StrategName } from '../../shared/constants/strategy-type.constant'

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(
  Strategy,
  StrategName.JwtRefresh
) {
  constructor(
    @Inject(jwtConfig.KEY)
    private readonly jwtOptions: ConfigType<typeof jwtConfig>,
    private readonly userService: UserService,
    private readonly refreshTokenService: RefreshTokenService
  ) {
    super({
      jwtFromRequest: (req) => cookieExtractor(req, CookieKey.Refresh),
      secretOrKey: jwtOptions.refreshTokenSecret
    })
  }

  public async validate(payload: IRefreshPayload) {
    if (!(await this.refreshTokenService.isExists(payload.tokenId))) {
      throw new UnauthorizedException(
        `Token with ID ${payload.tokenId} does not exists`
      )
    }

    await this.refreshTokenService.deleteRefreshSession(payload.tokenId)
    await this.refreshTokenService.deleteExpiredRefreshTokens()

    return this.userService.findByUsername(payload.username)
  }
}
