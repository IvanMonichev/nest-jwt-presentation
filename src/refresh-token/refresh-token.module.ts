import { Module } from '@nestjs/common'
import { RefreshTokenController } from './refresh-token.controller'
import { RefreshTokenService } from './refresh-token.service'
import { MongooseModule } from '@nestjs/mongoose'
import { RefreshTokenModel, RefreshTokenSchema } from './refresh-token.model'

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: RefreshTokenModel.name, schema: RefreshTokenSchema }
    ])
  ],
  controllers: [RefreshTokenController],
  providers: [RefreshTokenService],
  exports: [RefreshTokenService]
})
export class RefreshTokenModule {}
