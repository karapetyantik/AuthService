# AuthService

Микросервис аутентификации и авторизации платформы **Tapik**. Регистрация и вход по паролю, OAuth (Google, GitHub), двухфакторная аутентификация (TOTP), подтверждение email, восстановление и смена пароля, ротация refresh-токенов. Единственный источник истины по личности пользователя для остальных сервисов платформы.

## Роль в системе

AuthService — publisher, не consumer: сам ни на что не подписывается, но публикует `user.registered` в RabbitMQ (очередь `user_events`), которое разбирают UserService (создаёт профиль) и другие заинтересованные сервисы. Выданный им JWT (`JWT_SECRET`) проверяют все остальные сервисы платформы через собственный `JwtStrategy`.

## Технологии

- **NestJS 11** (TypeScript, HTTP-only, без микросервисных транспортов на вход)
- **PostgreSQL** через **Prisma** (`@prisma/adapter-pg`)
- **Redis** (ioredis) — коды подтверждения, rate-limit, TOTP anti-replay, блокировки, OAuth exchange-коды
- **RabbitMQ** — publisher `user.registered`
- **Passport** (`passport-jwt`, `passport-google-oauth20`, `passport-github2`)
- **otplib** + **qrcode** — TOTP 2FA
- **nodemailer** — транзакционные письма (SMTP или Ethereal-заглушка для локальной разработки)
- Path-алиасы: `@common/*`, `@modules/*`

## Возможности

- Регистрация/вход по email+паролю (`bcrypt`, 10 раундов).
- OAuth-вход через Google и GitHub с автоматическим связыванием по email или созданием нового аккаунта.
- Двухфакторная аутентификация по TOTP (генерация секрета + QR-код, anti-replay через Redis, блокировка на 24 часа после 5 неверных попыток).
- Подтверждение email кодом (6 цифр) или по ссылке (JWT-токен, 15 минут).
- Восстановление пароля с rate-limit (не более 3 писем в час на email) и защитой от email enumeration (единый ответ независимо от того, существует ли аккаунт).
- Ротация refresh-токенов: каждый `refresh` выдаёт новую пару и инвалидирует старый токен; токены хранятся в БД как SHA-256-хеш, не в открытом виде.
- Глобальный rate-limit через `ThrottlerGuard` (20 запросов/60 сек на IP по умолчанию), отдельные более жёсткие лимиты на `login`/`refresh` (5/мин) и OAuth-обмен (10/мин).

## API (`/auth/*`)

| Метод | Путь | Guard / Limit | Описание |
|---|---|---|---|
| `GET` | `/auth/google` | — | Инициирует OAuth-редирект на Google |
| `GET` | `/auth/google/callback` | — | Callback от Google → редирект на фронтенд с одноразовым кодом |
| `GET` | `/auth/github` | — | Инициирует OAuth-редирект на GitHub |
| `GET` | `/auth/github/callback` | — | Callback от GitHub → редирект на фронтенд с одноразовым кодом |
| `POST` | `/auth/oauth/exchange` | 10/мин | Обменять одноразовый код на `{ accessToken, refreshToken }` |
| `GET` | `/auth/profile` | JWT | Данные текущего пользователя из токена |
| `POST` | `/auth/register` | — | Регистрация по email/паролю |
| `POST` | `/auth/login` | 5/мин | Вход по email/паролю (или `requiresTotp: true` при включённой 2FA) |
| `POST` | `/auth/refresh` | 5/мин | Обновить пару токенов |
| `POST` | `/auth/forgot-password` | — | Запросить письмо для сброса пароля |
| `POST` | `/auth/reset-password` | — | Установить новый пароль по токену из письма |
| `POST` | `/auth/change-password` | JWT | Сменить пароль (текущий → новый) |
| `POST` | `/auth/logout` | 10/мин | Инвалидировать refresh-токен |
| `POST` | `/auth/verify-email` | — | Подтвердить email 6-значным кодом |
| `GET` | `/auth/verify-email/:token` | — | Подтвердить email по ссылке из письма |
| `POST` | `/auth/resend-verification` | — | Повторно отправить письмо подтверждения |
| `POST` | `/auth/totp/generate` | JWT | Сгенерировать секрет и QR-код для 2FA |
| `POST` | `/auth/totp/enable` | JWT | Включить 2FA (подтверждение кодом) |
| `POST` | `/auth/totp/disable` | JWT | Выключить 2FA (подтверждение кодом) |
| `POST` | `/auth/totp/login` | — | Завершить вход при включённой 2FA (`tempToken` + код) |

### Поток OAuth (Google / GitHub)

1. Клиент открывает `GET /auth/{google|github}` → редирект на страницу согласия провайдера.
2. Провайдер вызывает колбэк → `AuthService.oauthLogin()` находит/создаёт/связывает аккаунт, выпускает `{ accessToken, refreshToken }`.
3. Сервер кладёт токены в Redis под одноразовым кодом (TTL 60 сек) и редиректит на `${FRONTEND_URL}/oauth/callback?code=...` — **токены никогда не попадают в URL**.
4. Фронтенд немедленно вызывает `POST /auth/oauth/exchange { code }` и получает реальные токены. Код одноразовый — повторный обмен тем же кодом вернёт 401.

## Публикуемые события RabbitMQ

| Событие | Очередь | Когда | Payload |
|---|---|---|---|
| `user.registered` | `user_events` | Регистрация по паролю или первый вход через OAuth | `{ userId, email, username }` |

## Переменные окружения

| Переменная | Обязательна | Назначение |
|---|---|---|
| `PORT` | нет (3000) | HTTP-порт |
| `DATABASE_URL` | да | PostgreSQL |
| `JWT_SECRET` | да | Секрет для подписи access/temp-токенов |
| `JWT_ACCESS_EXPIRES_IN` | нет (`30m`) | Время жизни access-токена |
| `JWT_REFRESH_EXPIRES_IN` | нет (`15d`) | Время жизни refresh-токена |
| `REDIS_HOST` / `REDIS_PORT` | нет | Redis |
| `RABBITMQ_URL` | да | AMQP-подключение |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `GOOGLE_CALLBACK_URL` | да | Google OAuth |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` / `GITHUB_CALLBACK_URL` | да | GitHub OAuth |
| `FRONTEND_URL` | нет (`http://localhost:5173`) | Куда редиректить после OAuth и куда вести ссылку сброса пароля |
| `APP_URL` | нет (`http://localhost:3000`) | Базовый URL самого API — используется в ссылке подтверждения email |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_SECURE` / `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_FROM` | нет | Реальный SMTP. Если `SMTP_HOST` не задан — сервис использует тестовый аккаунт Ethereal (письма никуда не доставляются, только preview-ссылка в логах) |

## Структура проекта

```
src/
├── main.ts
├── app.module.ts
├── common/
│   ├── prisma/    # PrismaService
│   └── redis/     # RedisService
└── modules/
    ├── auth/
    │   ├── auth.controller.ts / auth.service.ts / auth.module.ts
    │   ├── dto/     # register, login, refresh, password-*, totp*, verify-email*
    │   ├── jwt/     # JwtStrategy, JwtAuthGuard, AuthenticatedRequest
    │   └── oauth/   # GoogleStrategy, GitHubStrategy, OauthUser
    └── email/       # EmailService (SMTP / Ethereal fallback)
```

## Запуск

```bash
npm install
npx prisma generate
npx prisma migrate deploy

npm run start:dev
npm run build && npm run start:prod
npm run test
npm run lint
```

## Безопасность

- Пароли — `bcrypt` (10 раундов), refresh-токены хранятся только как SHA-256-хеш.
- TOTP: anti-replay (нельзя дважды использовать один код), блокировка на 24 часа после 5 неверных попыток входа.
- OAuth-токены никогда не передаются через query-параметры — только через одноразовый обмен-код с TTL 60 секунд.
- Восстановление пароля не раскрывает существование аккаунта (единый ответ `{ success: true }` независимо от результата) и ограничено 3 письмами в час.
- Глобальный `ValidationPipe({ whitelist, forbidNonWhitelisted, transform })` и `ThrottlerGuard` на всех эндпоинтах.
