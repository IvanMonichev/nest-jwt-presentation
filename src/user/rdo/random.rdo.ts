import { ApiProperty } from '@nestjs/swagger'
import { UserRdo } from './user.rdo'

export class RandomValueRdo {
  @ApiProperty({ type: UserRdo })
  user: UserRdo

  @ApiProperty({ example: 0 })
  random: number
}
