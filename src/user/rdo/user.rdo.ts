import { ApiProperty } from '@nestjs/swagger'

export class UserRdo {
  @ApiProperty({ example: 'string' })
  id: string

  @ApiProperty({ example: 'string' })
  username: string
}
