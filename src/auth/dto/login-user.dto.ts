import { ApiProperty } from '@nestjs/swagger'
import { IsString } from 'class-validator'

export class LoginUserDto {
  @ApiProperty({
    description: 'Unique username',
    example: 'string'
  })
  public username: string

  @ApiProperty({
    description: 'Password at account',
    example: 'string'
  })
  @IsString()
  public password: string
}
