import { ApiProperty } from '@nestjs/swagger'

export class RegisterUserDto {
  @ApiProperty({
    example: 'string',
    description: 'Username of the user'
  })
  username: string

  @ApiProperty({
    example: 'string',
    description: 'Raw password of the user'
  })
  password: string
}
