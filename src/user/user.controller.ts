import {
  Controller,
  Get,
  NotFoundException,
  Param,
  UseGuards
} from '@nestjs/common'
import { UserService } from './user.service'
import { ApiCookieAuth, ApiParam, ApiResponse } from '@nestjs/swagger'
import { UserRdo } from './rdo/user.rdo'
import { RandomValueRdo } from './rdo/random.rdo'
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard'
import { CookieKey } from '../shared/constants/cookie-key.constant'

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @ApiCookieAuth(CookieKey.Access)
  @UseGuards(JwtAuthGuard)
  @ApiParam({ name: 'username', example: 'string' })
  @ApiResponse({
    status: 200,
    description: 'User information successfully retrieved',
    type: UserRdo
  })
  @ApiResponse({
    status: 404,
    description: 'User not found'
  })
  @Get(':username')
  public async getUser(@Param('username') username: string) {
    const user = await this.userService.findByUsername(username)

    if (!user) {
      throw new NotFoundException('User not found')
    }

    return user
  }

  @ApiCookieAuth(CookieKey.Access)
  @UseGuards(JwtAuthGuard)
  @ApiParam({ name: 'username', example: 'john_doe' })
  @ApiResponse({
    status: 200,
    description: 'Random number generated for user',
    type: RandomValueRdo
  })
  @Get(':username/random')
  public async getRandomValue(@Param('username') username: string) {
    const user = await this.userService.findByUsername(username)

    if (!user) {
      throw new NotFoundException('User not found')
    }

    // Имитируем бизнес-логику
    const random = Math.floor(Math.random() * 1000)

    return {
      username: user.username,
      random
    }
  }
}
