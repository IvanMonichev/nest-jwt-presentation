import { IUser } from './user.types'

export type IUserPayload = Omit<IUser, 'password'>

export interface ILoginDto {
  username: string
  password: string
}

export interface IAuthRequest extends Request {
  cookies?: Record<string, string>
  user?: IUserPayload
}

export interface IJWTPayload {
  user: IUserPayload
  exp: number
  iat: number
}

export interface IAccessPayload {
  sub?: string
  username: string
}
