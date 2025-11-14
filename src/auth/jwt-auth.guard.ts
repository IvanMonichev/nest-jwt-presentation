import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { IAuthRequest, IJWTPayload, IUserPayload } from './types';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<IAuthRequest>();

    const token = this.extractTokenFromCookie(req);

    if (!token) {
      throw new UnauthorizedException('No token');
    }

    try {
      const jwtPayload = this.jwt.verify<IJWTPayload>(token, {
        secret: this.config.getOrThrow<string>('JWT_ACCESS_SECRET'),
      });

      req.user = jwtPayload.user;
      return true;
    } catch {
      throw new UnauthorizedException('Invalid token');
    }
  }

  private extractTokenFromCookie(req: IAuthRequest): string | null {
    return req.cookies?.['access_token'] ?? null;
  }
}
