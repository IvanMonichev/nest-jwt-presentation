import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule } from '@nestjs/config';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtAuthGuard } from './jwt-auth.guard';

@Module({
  imports: [ConfigModule, JwtModule.registerAsync({})],
  providers: [AuthService, JwtAuthGuard],
  controllers: [AuthController],
  exports: [AuthService, JwtAuthGuard],
})
export class AuthModule {}
