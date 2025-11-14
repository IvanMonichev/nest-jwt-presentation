import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { MOCK_USER } from './constants';
import { IJWTPayload, IUser, IUserPayload } from './types';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  private validateUser(username: string, password: string): IUserPayload {
    const localUser = MOCK_USER;
    if (username !== localUser.username || password !== localUser.password) {
      throw new UnauthorizedException('Invalid credentials');
    }

    return this.toUserPayload(localUser);
  }

  private createAccessToken(user: IUserPayload): string {
    return this.jwt.sign(
      { user },
      {
        secret: this.config.getOrThrow<string>('JWT_ACCESS_SECRET'),
        expiresIn: this.config.getOrThrow<string>(
          'JWT_ACCESS_EXPIRES_IN',
        ) as JwtSignOptions['expiresIn'],
      },
    );
  }
  private createRefreshToken(user: IUserPayload): string {
    return this.jwt.sign(
      { user },
      {
        secret: this.config.getOrThrow<string>('JWT_REFRESH_SECRET'),
        expiresIn: this.config.getOrThrow<string>(
          'JWT_REFRESH_EXPIRES_IN',
        ) as JwtSignOptions['expiresIn'],
      },
    );
  }

  login(username: string, password: string) {
    const user = this.validateUser(username, password);

    const accessToken = this.createAccessToken(user);
    const refreshToken = this.createRefreshToken(user);

    return {
      accessToken,
      refreshToken,
    };
  }

  refresh(refreshToken?: string) {
    if (!refreshToken) {
      throw new UnauthorizedException('No refresh token');
    }

    try {
      const payload = this.jwt.verify<IJWTPayload>(refreshToken, {
        secret: this.config.getOrThrow<string>('JWT_REFRESH_SECRET'),
      });

      const newAccessToken = this.createAccessToken(payload.user);
      const newRefreshToken = this.createRefreshToken(payload.user);

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      };
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  toUserPayload(localUser: IUser): IUserPayload {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...userWithoutPassword } = localUser;
    return userWithoutPassword;
  }
}
