import { Document, HydratedDocument } from 'mongoose'
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose'
import { IUser } from '../shared/types/user.types'

export type UserDocument = HydratedDocument<UserModel>

@Schema({
  collection: 'users',
  timestamps: true
})
export class UserModel implements IUser {
  @Prop({
    required: true
  })
  username: string

  @Prop()
  passwordHash: string
}

export const UserSchema = SchemaFactory.createForClass(UserModel)
