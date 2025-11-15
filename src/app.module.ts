import { Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { AuthModule } from './auth/auth.module'
import { RefreshTokenModule } from './refresh-token/refresh-token.module'
import { AppConfigModule } from './config/app-config.module'
import { UserModule } from './user/user.module'
import { MongooseModule } from '@nestjs/mongoose'
import { getMongooseOptions } from './config/mongodb-config/get-mongoose-options'

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true
    }),
    MongooseModule.forRootAsync(getMongooseOptions()),
    AppConfigModule,
    AuthModule,
    RefreshTokenModule,
    UserModule
  ]
})
export class AppModule {}
