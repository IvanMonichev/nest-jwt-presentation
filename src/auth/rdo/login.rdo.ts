import { ApiProperty } from '@nestjs/swagger'
import { Expose } from 'class-transformer'

export class LoginRdo {
  @ApiProperty({
    description: 'User ID',
    example: 'string'
  })
  @Expose()
  public _id: string
}
