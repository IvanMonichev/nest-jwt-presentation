import { AuthGuard } from '@nestjs/passport'
import { StrategName } from '../../shared/constants/strategy-type.constant'

export class LocalAuthGuard extends AuthGuard(StrategName.Local) {}
