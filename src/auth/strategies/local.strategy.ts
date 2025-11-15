import { Injectable } from '@nestjs/common'
import { PassportStrategy } from '@nestjs/passport'
import { AuthService } from '../auth.service'
import { Strategy } from 'passport-local'

const USERNAME_FIELD_NAME = 'username'

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly authService: AuthService) {
    super({ usernameField: USERNAME_FIELD_NAME })
  }

  public async validate(username: string, password: string) {
    return this.authService.verifyUser({ username, password })
  }
}
