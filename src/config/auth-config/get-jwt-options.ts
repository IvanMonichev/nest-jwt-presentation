import { ConfigService } from '@nestjs/config'
import { JwtModuleOptions } from '@nestjs/jwt'
import { msToExpiresIn } from '../../shared/utils/ms-to-expires-in.util'

export function getJwtOptions(configService: ConfigService): JwtModuleOptions {
  return {
    secret: configService.get<string>('jwt.accessTokenSecret'),
    signOptions: {
      expiresIn: msToExpiresIn(
        configService.get<number>('jwt.accessTokenExpiresIn') || 0
      ),
      algorithm: 'HS256'
    }
  }
}
