import { Module } from '@nestjs/common'
import { UserService } from './user.service'
import { MongooseModule } from '@nestjs/mongoose'
import { UserModel, UserSchema } from './user.model'
import { UserController } from './user.controller'
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard'

@Module({
  imports: [
    MongooseModule.forFeature([{ name: UserModel.name, schema: UserSchema }])
  ],
  providers: [UserService, JwtAuthGuard],
  exports: [UserService],
  controllers: [UserController]
})
export class UserModule {}
