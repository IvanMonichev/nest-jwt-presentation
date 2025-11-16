import { AuthGuard } from '@nestjs/passport'
import { Injectable } from '@nestjs/common'
import { StrategName } from '../../shared/constants/strategy-type.constant'

@Injectable()
export class JwtAuthGuard extends AuthGuard(StrategName.JwtAccess) {}
