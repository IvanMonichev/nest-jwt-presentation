import { ConfigModule } from '@nestjs/config'
import { Module } from '@nestjs/common'
import jwtConfig from './auth-config/jwt.config'
import mongoConfig from './mongodb-config/mongo.config'

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
      load: [jwtConfig, mongoConfig],
      envFilePath: '../../../.env'
    })
  ]
})
export class AppConfigModule {}
