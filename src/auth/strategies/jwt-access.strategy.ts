import { PassportStrategy } from '@nestjs/passport'
import { Strategy } from 'passport-jwt'
import { Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { IAccessPayload } from '../../shared/types/auth.types'
import { cookieExtractor } from '../../shared/types/cookie-extractor.util'
import { CookieKey } from '../../shared/constants/cookie-key.constant'
import { StrategName } from '../../shared/constants/strategy-type.constant'

@Injectable()
export class JwtAccessStrategy extends PassportStrategy(
  Strategy,

  StrategName.JwtAccess
) {
  constructor(private readonly configService: ConfigService) {
    super({
      jwtFromRequest: (req) => cookieExtractor(req, CookieKey.Access),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('jwt.accessTokenSecret') as string
    })
  }

  public async validate(payload: IAccessPayload) {
    return payload
  }
}
