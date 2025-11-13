export interface IUser {
  id: number;
  username: string;
  password: string;
}
export type IUserPayload = Omit<IUser, 'password'>;

export interface ILoginDto {
  username: string;
  password: string;
}

export interface IAuthRequest extends Request {
  cookies?: Record<string, string>;
  user?: IUserPayload;
}

