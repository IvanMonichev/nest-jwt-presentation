import { Module } from '@nestjs/common';
import { ProfileController } from './profile.controller';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [AuthModule],
  providers: [],
  controllers: [ProfileController],
  exports: [],
})
export class ProfileModule {}
