import { Inject, Injectable } from '@nestjs/common'
import {
  IRefreshPayload,
  ISessionToken
} from '../shared/types/refresh-token.types'
import jwtConfig from '../config/auth-config/jwt.config'
import type { ConfigType } from '@nestjs/config'
import { Model } from 'mongoose'
import { InjectModel } from '@nestjs/mongoose'
import { RefreshTokenDocument, RefreshTokenModel } from './refresh-token.model'

@Injectable()
export class RefreshTokenService {
  constructor(
    @Inject(jwtConfig.KEY)
    private readonly jwtOptions: ConfigType<typeof jwtConfig>,
    @InjectModel(RefreshTokenModel.name)
    private readonly refreshTokenModel: Model<RefreshTokenDocument>
  ) {}

  public async createRefreshSession(payload: IRefreshPayload) {
    const refreshMs = this.jwtOptions.refreshTokenExpiresIn
    const refreshToken: Omit<ISessionToken, 'id'> = {
      tokenId: payload.tokenId,
      createdAt: new Date(),
      userId: payload.sub?.toString(),
      expiresIn: new Date(Date.now() + refreshMs)
    }

    return await this.refreshTokenModel.create(refreshToken)
  }

  public async isExists(tokenId: string): Promise<boolean> {
    const refreshToken = await this.refreshTokenModel
      .findOne<ISessionToken>({ tokenId })
      .exec()
    return refreshToken !== null
  }

  public async deleteRefreshSession(tokenId: string): Promise<void> {
    await this.deleteExpiredRefreshTokens()
    await this.refreshTokenModel.deleteOne({ tokenId }).exec()
  }

  public async deleteExpiredRefreshTokens() {
    await this.refreshTokenModel.deleteMany({ expiresIn: { $lt: new Date() } })
  }
}
