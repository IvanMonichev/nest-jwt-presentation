import { registerAs } from '@nestjs/config'

async function getConfig() {
  const config = {
    host: process.env.MONGO_HOST ?? 'localhost',
    name: process.env.MONGO_DB ?? 'nest-db',
    port: Number(process.env.MONGO_PORT ?? 27017),
    user: process.env.MONGO_USER ?? 'admin',
    password: process.env.MONGO_PASSWORD ?? 'admin123',
    authBase: process.env.MONGO_AUTH_BASE ?? 'admin'
  }

  return config
}

export default registerAs('db', getConfig)
