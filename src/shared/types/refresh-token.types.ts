import { IAccessPayload } from './auth.types'

export interface IRefreshPayload extends IAccessPayload {
  tokenId: string
}

export interface ISessionToken {
  id?: string
  tokenId: string
  userId?: string
  createdAt: Date
  expiresIn: Date
}
