import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import cookieParser from 'cookie-parser'
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger'
import { Logger, ValidationPipe } from '@nestjs/common'
import { CookieKey } from './shared/constants/cookie-key.constant'

async function bootstrap() {
  const app = await NestFactory.create(AppModule)

  const globalPrefix = 'api'

  app.setGlobalPrefix(globalPrefix)
  app.use(cookieParser())

  const config = new DocumentBuilder()
    .setTitle('Nest JWT Presentation')
    .setLicense('Ivan Monichev, Aleksey Moskalev', '')
    .setVersion('1.0.0')
    .addCookieAuth(CookieKey.Access, {
      type: 'apiKey',
      in: 'cookie'
    })
    .build()

  const document = SwaggerModule.createDocument(app, config)
  SwaggerModule.setup(globalPrefix, app, document)

  app.useGlobalPipes(
    new ValidationPipe({
      transform: true
    })
  )

  app.enableCors({
    origin: true,
    credentials: true
  })

  const port = process.env.PORT ?? 3000
  await app.listen(port)
  Logger.log(
    `🚀 Application User is running on: http://localhost:${port}/${globalPrefix}`
  )
}
bootstrap()
