import { Module } from '@nestjs/common'
import { JwtModule } from '@nestjs/jwt'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { AuthService } from './auth.service'
import { AuthController } from './auth.controller'
import { JwtAuthGuard } from './guards/jwt-auth.guard'
import { RefreshTokenModule } from '../refresh-token/refresh-token.module'
import { getJwtOptions } from '../config/auth-config/get-jwt-options'
import { BcryptHasher } from '../shared/helpers/bcrypt-hasher'
import { LocalStrategy } from './strategies/local.strategy'
import { UserModule } from '../user/user.module'
import { JwtAccessStrategy } from './strategies/jwt-access.strategy'
import { JwtRefreshStrategy } from './strategies/jwt-refresh.strategy'

@Module({
  imports: [
    ConfigModule,
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: getJwtOptions
    }),
    RefreshTokenModule,
    UserModule
  ],
  providers: [
    AuthService,
    JwtAuthGuard,
    {
      provide: 'SaltRound',
      useValue: 10
    },
    {
      provide: 'Hasher',
      useClass: BcryptHasher
    },
    JwtAccessStrategy,
    LocalStrategy,
    JwtRefreshStrategy
  ],
  controllers: [AuthController],
  exports: [AuthService, JwtAuthGuard, JwtModule]
})
export class AuthModule {}
