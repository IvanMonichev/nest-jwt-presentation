import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose'
import { HydratedDocument } from 'mongoose'
import { ISessionToken } from '../shared/types/refresh-token.types'

export type RefreshTokenDocument = HydratedDocument<RefreshTokenModel>

@Schema({
  collection: 'refresh-sessions',
  timestamps: true
})
export class RefreshTokenModel implements ISessionToken {
  @Prop()
  public createdAt: Date

  @Prop({ required: true })
  public tokenId: string

  @Prop({ required: true })
  public userId: string

  @Prop({ required: true })
  public expiresIn: Date
}

export const RefreshTokenSchema =
  SchemaFactory.createForClass(RefreshTokenModel)
