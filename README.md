# AuthService — подробная документация (все файлы)

Микросервис аутентификации и авторизации. Хранилище — PostgreSQL через Prisma. Отвечает за регистрацию/вход по паролю, вход через Google OAuth2, двухфакторную аутентификацию (TOTP), подтверждение email, восстановление и смену пароля, ротацию refresh-токенов и публикацию события `user.registered` для других сервисов.

---

## 1. Дерево модуля

```
src/
├── main.ts
├── app.module.ts / app.controller.ts / app.service.ts
├── common/
│   ├── prisma/ (prisma.module.ts, prisma.service.ts)
│   └── redis/  (redis.module.ts, redis.service.ts)
└── modules/
    ├── auth/
    │   ├── auth.module.ts
    │   ├── auth.controller.ts
    │   ├── auth.service.ts
    │   ├── dto/ (register, login, refresh, forgot-password, reset-password,
    │   │         change-password, totp, totp-login, verify-email-code,
    │   │         resend-verification)
    │   ├── jwt/ (jwt-auth.guard.ts, jwt.strategy.ts)
    │   └── oauth/ (google.strategy.ts)
    └── email/
        ├── email.module.ts
        └── email.service.ts
```

---

## 2. `main.ts` — точка входа

- Создаёт приложение Nest, подключает глобальный `ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })` — лишние поля в теле запроса отклоняются на уровне валидации.
- Слушает HTTP-порт из `PORT` (по умолчанию `3000`).
- Никаких микросервисных транспортов (RabbitMQ-consumer, gRPC) не поднимает — сервис **только publisher** событий (см. ниже), не подписчик.

## 3. `app.module.ts`

- Подключает `ConfigModule.forRoot({ isGlobal: true })`.
- Регистрирует `ThrottlerModule.forRoot([{ ttl: 60, limit: 20, blockDuration: 1800 }])` — глобальный rate-limit: 20 запросов/60 сек на IP по умолчанию, блокировка нарушителя на 30 минут (`blockDuration = 3600/2`).
- Подключает `PrismaModule`, `AuthModule`, `EmailModule`, `RedisModule`.
- Регистрирует `ThrottlerGuard` как глобальный `APP_GUARD` — throttling применяется ко **всем** эндпоинтам приложения, а не только к тем, где явно указан `@Throttle(...)` (последний лишь переопределяет лимит для конкретного роута, например `login`/`refresh` — 5/мин вместо общих 20/мин).

## 4. `common/prisma/` — `PrismaService`, `PrismaModule`

- `PrismaService` расширяет `PrismaClient`, использует `PrismaPg`-адаптер (`@prisma/adapter-pg`) с `connectionString` из `DATABASE_URL`.
- Подключается в `onModuleInit` (`$connect()`), отключается в `onModuleDestroy` (`$disconnect()`).
- Глобально экспортируется через `PrismaModule`.

## 5. `common/redis/` — `RedisService`, `RedisModule`

- Оборачивает клиент `ioredis` (`ioredis/built/Redis`), подключается по `REDIS_HOST`/`REDIS_PORT` (по умолчанию `localhost:6379`).
- `client` — публичное свойство, используется напрямую другими сервисами (не инкапсулирует конкретные операции — «сырой» доступ к Redis).

## 6. `modules/email/` — `EmailService`, `EmailModule`

- `EmailService.onModuleInit()` создаёт **тестовый** SMTP-аккаунт через `nodemailer.createTestAccount()` (сервис [Ethereal Email](https://ethereal.email)) и логирует его в консоль — то есть **реальные письма никуда не долетают**, это dev/staging-заглушка. В продакшене этот код потребует замены на реальный SMTP/провайдера транзакционных писем.
- `sendVerificationEmail(to, code, token)` — отправляет письмо с 6-значным кодом и ссылкой вида `http://localhost:3000/auth/verify-email/{token}` (URL захардкожен, не берётся из конфигурации).
- `sendPasswordResetEmail(to, token)` — аналогично, ссылка `http://localhost:3000/auth/reset-password/{token}` (обратите внимание: этот путь ведёт на **фронтенд**, а не на API, что логично для UX сброса пароля, но не совпадает по формату с `verify-email`, где ссылка ведёт напрямую в API — см. замечания).
- После отправки логирует `nodemailer.getTestMessageUrl(info)` — ссылку для предпросмотра письма в Ethereal (только для разработки).

## 7. `modules/auth/dto/*` — валидация запросов

| DTO | Поля и правила |
|---|---|
| `RegisterDto` | `email` (валидный email), `username` (строка 3–32 символа), `password` (строка, минимум 8 символов) |
| `LoginDto` | `email` (email), `password` (строка) |
| `RefreshDto` | `refreshToken` (строка) |
| `ForgotPasswordDto` | `email` (email) |
| `ResetPasswordDto` | `token` (строка), `newPassword` (строка, минимум 8) |
| `ChangePasswordDto` | `currentPassword` (строка), `newPassword` (строка, минимум 8) |
| `TotpCodeDto` | `code` — строка, регулярное выражение `^\d{6}$` (ровно 6 цифр) |
| `TotpLoginDto` | `tempToken` (строка), `code` (6 цифр, та же маска) |
| `VerifyEmailCodeDto` | `email` (email), `code` (6 цифр) |
| `ResendVerificationDto` | `email` (email) |

Замечание: в `reset-password.dto.ts` среди импортов присутствует неиспользуемая `isString` (функция, а не декоратор, с маленькой буквы) — вероятно, случайный лишний импорт, не влияющий на работу, но указывающий на неаккуратность кода (линтер должен был это отловить).

## 8. `modules/auth/jwt/` — JWT-стратегия и guard

- **`JwtStrategy`** (`passport-jwt`): извлекает токен из заголовка `Authorization: Bearer ...`, не игнорирует истечение срока действия (`ignoreExpiration: false`), секрет — `JWT_SECRET` (обязателен, `getOrThrow`). `validate(payload)` возвращает `{ userId: payload.sub, email: payload.email }`, что попадает в `req.user`.
- **`JwtAuthGuard`** — тонкая обёртка `AuthGuard('jwt')`, используется декоратором `@UseGuards(JwtAuthGuard)` на защищённых роутах.

## 9. `modules/auth/oauth/google.strategy.ts` — вход через Google

- `GoogleStrategy` (`passport-google-oauth20`), регистрируется под именем `'google'`.
- Конфигурация — `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_CALLBACK_URL` (все обязательны через `getOrThrow`), запрашиваемые scope — `['email', 'profile']`.
- `validate(accessToken, refreshToken, profile, done)` — не сохраняет `accessToken`/`refreshToken` Google (они просто не используются далее), извлекает из профиля `id` (→ `providerId`), первый email из `emails[0].value`, `displayName`, передаёт объект `{ providerId, email, displayName }` в `done()` — это то, что окажется в `req.user` внутри `googleAuthCallback`.

## 10. `modules/auth/auth.module.ts`

- Импортирует `PrismaModule`, `EmailModule`, `RedisModule`.
- Регистрирует `ClientsModule` с транспортом `RMQ` под именем `RABBITMQ_SERVICE`: очередь `user_events` (durable), URL — `RABBITMQ_URL`. Это **исходящий** канал — `AuthService` публикует сюда `user.registered`.
- Регистрирует `JwtModule.registerAsync`: секрет — `JWT_SECRET`, время жизни access-токена по умолчанию `expiresIn` из `JWT_ACCESS_EXPIRES_IN`, иначе `'30m'`.
- Providers: `AuthService`, `JwtStrategy`, `GoogleStrategy`. Controllers: `AuthController`.

## 11. `modules/auth/auth.controller.ts` — REST API (`/auth/*`)

| Метод | HTTP | Роут | Guard/Throttle | Делегирует |
|---|---|---|---|---|
| `googleAuth` | GET | `/auth/google` | `AuthGuard('google')` | — (инициирует OAuth-редирект на Google) |
| `googleAuthCallback` | GET | `/auth/google/callback` | `AuthGuard('google')` | `authService.oauthLogin(req.user)`, затем **редирект** на фронтенд |
| `getProfile` | GET | `/auth/profile` | `JwtAuthGuard` | возвращает `req.user` как есть |
| `register` | POST | `/auth/register` | — | `authService.register(dto)` |
| `login` | POST | `/auth/login` | `@Throttle` 5/мин | `authService.login(dto)` |
| `refresh` | POST | `/auth/refresh` | `@Throttle` 5/мин | `authService.refresh(dto.refreshToken)` |
| `forgotPassword` | POST | `/auth/forgot-password` | — | `authService.forgotPassword(dto.email)` |
| `resetPassword` | POST | `/auth/reset-password` | — | `authService.resetPassword(dto.token, dto.newPassword)` |
| `changePassword` | POST | `/auth/change-password` | `JwtAuthGuard` | `authService.changePassword(userId, current, new)` |
| `logout` | POST | `/auth/logout` | — | `authService.logout(dto.refreshToken)` |
| `verifyEmailByCode` | POST | `/auth/verify-email` | — | `authService.verifyEmailByCode(email, code)` |
| `verifyEmailByToken` | GET | `/auth/verify-email/:token` | — | `authService.verifyEmailByToken(token)` |
| `resendVerification` | POST | `/auth/resend-verification` | — | `authService.resendVerificationEmail(email)` |
| `generateTotpSecret` | POST | `/auth/totp/generate` | `JwtAuthGuard` | `authService.generateTotpSecret(userId)` |
| `enableTotp` | POST | `/auth/totp/enable` | `JwtAuthGuard` | `authService.enableTotp(userId, code)` |
| `disableTotp` | POST | `/auth/totp/disable` | `JwtAuthGuard` | `authService.disableTotp(userId, code)` |
| `verifyTotpLogin` | POST | `/auth/totp/login` | — | `authService.verifyTotpLogin(tempToken, code)` |

**Google OAuth flow:**
1. Клиент открывает `GET /auth/google` → Passport-стратегия перенаправляет на страницу согласия Google.
2. После согласия Google вызывает `GET /auth/google/callback` → guard прогоняет ответ через `GoogleStrategy.validate`, кладёт `{ providerId, email, displayName }` в `req.user`.
3. Контроллер вызывает `authService.oauthLogin(req.user)`, получает `{ accessToken, refreshToken }`.
4. Контроллер делает `res.redirect` на `${FRONTEND_URL}/oauth/callback?accessToken=...&refreshToken=...` — токены передаются во **фронтенд через query-параметры URL** (см. замечания — это потенциально небезопасно: попадает в историю браузера, логи сервера, `Referer`-заголовки).

## 12. `modules/auth/auth.service.ts` — бизнес-логика

### Зависимости
`PrismaService`, `JwtService`, `ConfigService`, `EmailService`, `RedisService`, `ClientProxy('RABBITMQ_SERVICE')`.

### 12.1. `register(dto)`
Как в базовой версии: проверка дубликата email/username → `bcrypt.hash` (10 rounds) → создание пользователя → письмо подтверждения → `rabbitClient.emit('user.registered', { userId, email, username })` → возврат пользователя без `passwordHash`.

### 12.2. `login(dto)`
Отличие от предыдущей версии: теперь учитывает пользователей, зарегистрированных через Google (`passwordHash` может быть `null`).
- Если пользователь не найден **или** `passwordHash` отсутствует — `UnauthorizedException` с разным текстом: `'Этот аккаунт использует вход через Google'` (если юзер есть, но без пароля) или `'Неверный email или пароль'` (если юзера нет). **Замечание:** это раскрывает существование аккаунта — то есть здесь (в отличие от `forgotPassword`) сообщение всё же различается в зависимости от того, найден пользователь или нет, что является небольшой информационной утечкой (email enumeration через различие сообщений «неверный email или пароль» vs «этот аккаунт использует вход через Google»).
- Далее — как раньше: `bcrypt.compare`, при включённой TOTP — временный токен, иначе — `issueTokens`.

### 12.3. `verifyTotpLogin(tempToken, code)`
Без изменений относительно ранее задокументированной версии: проверка временного токена, блокировка после 5 неверных попыток на 24 часа, anti-replay через `verifyTotpCode`.

### 12.4. `oauthLogin(googleUser)` — новый метод
1. Ищет пользователя по `providerId`.
2. Если не найден — ищет по `email`:
   - **если найден по email** — «привязывает» Google к существующему аккаунту: обновляет `provider: 'google'`, `providerId`, `isEmailVerified: true` (email через Google считается автоматически подтверждённым). Событие `user.registered` **не** публикуется повторно (пользователь уже существовал).
   - **если не найден вовсе** — генерирует уникальный `username` (`generateUniqueUsername`) на основе `displayName`, создаёт нового пользователя с `provider: 'google'`, `providerId`, `isEmailVerified: true`, публикует `user.registered`.
3. В обоих случаях (найден по `providerId` сразу, привязан по email, или создан заново) — выпускает токены (`issueTokens`).

**Замечание (безопасность):** автоматическая привязка Google-аккаунта к существующему пользователю **только по совпадению email**, без дополнительного подтверждения владения этим email через пароль или иной фактор, — потенциальный вектор атаки, если Google когда-либо вернёт непроверенный (`email_verified: false`) email для стороннего провайдера (для самого Google это маловероятно, но в целом такой паттерн привязки без доп. проверки считается рискованным).

### 12.5. `generateUniqueUsername(base)` — приватный метод
- Приводит `displayName` к нижнему регистру, убирает пробелы, обрезает до 20 символов.
- В цикле проверяет занятость через `findUnique({ where: { username } })`, при коллизии добавляет числовой суффикс (`name1`, `name2`, ...). Потенциально медленно при большом числе коллизий (последовательные запросы к БД в цикле), но для обычного распределения имён не критично.

### 12.6. `resendVerificationEmail`, `sendVerificationEmail`, `verifyEmailByCode`, `verifyEmailByToken`, `markEmailVerified`, `forgotPassword`
Идентичны ранее задокументированной версии (см. документацию первой версии `AuthService`): защита от email enumeration, коды/токены с TTL 15 минут, лимит попыток, rate-limit на `forgotPassword` (максимум 3 запроса в час на email).

### 12.7. `resetPassword(token, newPassword)` — изменение относительно базовой версии
Теперь проверка «пароль не должен совпадать со старым» выполняется **только если** у пользователя уже есть `passwordHash` (`if (user.passwordHash) { ... }`) — иначе (пользователь пришёл через Google и ещё не задавал пароль) проверка пропускается, так как сравнивать не с чем. Это, по сути, механизм **задать первый пароль** Google-пользователю через флоу восстановления пароля.

### 12.8. `changePassword(userId, currentPassword, newPassword)` — изменение
Теперь явно проверяет, что у пользователя есть `passwordHash`, прежде чем сравнивать текущий пароль: если пароля ещё нет (чистый Google-аккаунт) — `BadRequestException('У этого аккаунта ещё нет пароля (вход через Google) — используйте восстановление пароля, чтобы задать его')`. Логичное и явное сообщение, направляющее пользователя к `forgotPassword`/`resetPassword` как способу «завести» пароль.

### 12.9. `refresh`, `logout`, `issueTokens`, `hashToken`
Без изменений — SHA-256-хеш refresh-токена хранится в БД, сам токен — нет; ротация при каждом `refresh` (старый удаляется, выдаётся новый).

### 12.10. `generateTotpSecret`, `enableTotp`, `disableTotp`, `verifyTotpCode`
Без изменений относительно базовой версии — генерация секрета и QR (issuer `ChatApp`), anti-replay через Redis (`totp_last_step:{userId}`, TTL 5 мин).

---

## 13. Модель данных (реконструкция по Prisma-запросам)

Схема `.prisma` не входит в переданные файлы; ниже — поля, использованные в коде.

**`User`**
| Поле | Тип (предположительно) | Комментарий |
|---|---|---|
| `id` | string (PK) | |
| `email` | string, unique | |
| `username` | string, unique | |
| `passwordHash` | string \| null | `null` для чисто OAuth-аккаунтов |
| `provider` | string \| null | например `'google'` |
| `providerId` | string \| null, unique | ID пользователя у внешнего провайдера |
| `isEmailVerified` | boolean | автоматически `true` при входе через Google |
| `isTotpEnabled` | boolean | |
| `totpSecret` | string \| null | |

**`RefreshToken`**
| Поле | Комментарий |
|---|---|
| `id` | PK |
| `tokenHash` | unique, SHA-256 refresh-токена |
| `userId` | FK на `User` |
| `expiresAt` | дата истечения |

---

## 14. Публикуемые события RabbitMQ

| Событие | Очередь | Когда | Payload |
|---|---|---|---|
| `user.registered` | `user_events` | `register()`, `oauthLogin()` при создании нового пользователя | `{ userId, email, username }` |

`AuthService` не подписывается ни на одно событие — чистый publisher.

---

## 15. Сводные замечания по всему сервису

1. **`EmailService` использует Ethereal (тестовый SMTP)** — до продакшена потребуется замена на реальный почтовый провайдер; сейчас письма реально никуда, кроме тестового веб-инструмента, не доходят.
2. **URL в письмах захардкожены** (`http://localhost:3000/...`) — не читаются из конфигурации, что сломается при деплое на любой другой домен/окружение.
3. **Токены при Google-логине передаются через query-параметры redirect-URL** — стандартный, но не самый безопасный паттерн (риск утечки через логи прокси/CDN, `Referer`, историю браузера); более безопасная альтернатива — HttpOnly-cookie или одноразовый код обмена (authorization code flow на уровне собственного бэкенда).
4. **Автопривязка Google-аккаунта по email без дополнительного подтверждения** — см. п. 12.4.
5. **`login()` теперь различает «нет юзера» и «юзер есть, но без пароля» в тексте ошибки** — небольшая утечка информации о существовании аккаунта (в отличие от единообразного поведения `forgotPassword`/`resendVerificationEmail`).
6. **Неиспользуемый импорт `isString`** в `reset-password.dto.ts` — косметическая недоработка.
7. Все остальные замечания из первичной документации `AuthService` (закомментированная проверка `isEmailVerified` при логине, русскоязычные сообщения об ошибках без i18n) остаются актуальны и в этой версии.
