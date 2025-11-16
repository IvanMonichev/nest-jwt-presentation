import { registerAs } from '@nestjs/config'

function getConfig() {
  const config = {
    accessTokenSecret:
      process.env.JWT_ACCESS_TOKEN_SECRET ?? 'default-access-secret',
    accessTokenExpiresIn:
      Number(process.env.JWT_ACCESS_TOKEN_EXPIRES_IN) || 900_000,
    refreshTokenSecret:
      process.env.JWT_REFRESH_TOKEN_SECRET ?? 'default-refresh-secret',
    refreshTokenExpiresIn:
      Number(process.env.JWT_REFRESH_TOKEN_EXPIRES_IN) || 604_800_000
  }

  return config
}

export default registerAs('jwt', getConfig)
