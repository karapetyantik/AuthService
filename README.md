# AuthService — документация

Сервис аутентификации и авторизации пользователей на базе NestJS. Инкапсулирует всю бизнес-логику работы с учётными записями: регистрацию, вход (включая двухфакторную аутентификацию по TOTP), подтверждение email, восстановление и смену пароля, а также управление refresh-токенами.

---

## 1. Общее описание

`AuthService` — `@Injectable()`-сервис, который используется контроллером `AuthController` для обработки HTTP-запросов, связанных с аутентификацией.

Сервис отвечает за:

- регистрацию новых пользователей и рассылку писем подтверждения email;
- вход по паролю с опциональным вторым фактором (TOTP);
- выпуск и обновление пары `accessToken` / `refreshToken`;
- подтверждение email по коду или по токену-ссылке;
- восстановление пароля по email (forgot/reset) и смену пароля авторизованным пользователем;
- включение/отключение двухфакторной аутентификации (TOTP);
- защиту от брутфорса через счётчики попыток в Redis.

### 1.1. Зависимости (внедряются через конструктор)

| Зависимость | Назначение |
|---|---|
| `PrismaService` | Доступ к БД (модели `user`, `refreshToken`) |
| `JwtService` (`@nestjs/jwt`) | Подпись и верификация JWT (access-токены, временные токены) |
| `ConfigService` | Чтение конфигурации (`JWT_REFRESH_EXPIRES_IN` и т.д.) |
| `EmailService` | Отправка писем (подтверждение регистрации, сброс пароля) |
| `RedisService` | Хранение временных данных: коды подтверждения, счётчики попыток, блокировки, TOTP-anti-replay |
| `ClientProxy` (`RABBITMQ_SERVICE`) | Публикация события `user.registered` в очередь RabbitMQ |

### 1.2. Используемые библиотеки

- `bcrypt` — хеширование паролей;
- `crypto` (`randomBytes`, `createHash`) — генерация случайных токенов и их хеширование (SHA-256);
- `ms` — парсинг строк длительности (`"15d"` → миллисекунды);
- `otplib` (`generateSecret`, `generateURI`, `verify`) — генерация и проверка TOTP-кодов;
- `qrcode` — генерация QR-кода для подключения приложения-аутентификатора.

---

## 2. Публичные методы

### 2.1. `register(dto: RegisterDto): Promise<SafeUser>`

Регистрирует нового пользователя.

**Логика:**
1. Проверяет, что пользователь с таким `email` или `username` ещё не существует — иначе `ConflictException`.
2. Хеширует пароль (`bcrypt`, salt rounds = 10).
3. Создаёт пользователя в БД.
4. Отправляет письмо с кодом/токеном подтверждения email (`sendVerificationEmail`).
5. Публикует событие `user.registered` в RabbitMQ с полями `userId`, `email`, `username`.
6. Возвращает пользователя без поля `passwordHash`.

**Исключения:**
- `ConflictException` — email или username уже заняты.

**Побочные эффекты:** запись в БД, письмо, сообщение в очередь.

---

### 2.2. `login(dto: LoginDto): Promise<{ accessToken, refreshToken } | { requiresTotp: true, tempToken }>`

Аутентифицирует пользователя по email и паролю.

**Логика:**
1. Ищет пользователя по `email`. Если не найден — `UnauthorizedException('Invalid email or password')`.
2. Проверка email verified закомментирована (см. раздел «Замечания», п. 6.1).
3. Сравнивает пароль через `bcrypt.compare`. Если неверный — та же ошибка `Invalid email or password` (намеренно не раскрывается, что именно неверно — email или пароль).
4. Если у пользователя включена TOTP (`isTotpEnabled`):
   - выпускает **временный** JWT (`purpose: 'totp-login'`) со сроком жизни 5 минут;
   - возвращает `{ requiresTotp: true, tempToken }`, не выдавая полноценные токены.
5. Если TOTP выключена — сразу вызывает `issueTokens` и возвращает пару токенов.

**Исключения:**
- `UnauthorizedException` — неверные email/пароль.

---

### 2.3. `verifyTotpLogin(tempToken: string, code: string): Promise<{ accessToken, refreshToken }>`

Второй шаг входа при включённой 2FA — подтверждение временного токена TOTP-кодом.

**Логика:**
1. Верифицирует `tempToken` (`jwtService.verifyAsync`). Ошибка подписи/срока → `UnauthorizedException` («сессия входа истекла»).
2. Проверяет `payload.purpose === 'totp-login'`, иначе — «неверный тип токена» (защита от подмены токена другого назначения).
3. Проверяет блокировку по ключу Redis `totp_blocked:{userId}` — если пользователь заблокирован после серии неверных попыток, вход запрещён.
4. Загружает пользователя, проверяет, что 2FA включена и `totpSecret` установлен.
5. Вызывает `verifyTotpCode`. Если код неверный:
   - инкрементирует счётчик `totp_attempts:{userId}` (TTL 15 минут при первой попытке);
   - при достижении 5 неудачных попыток — устанавливает блокировку `totp_blocked:{userId}` на 24 часа и сбрасывает счётчик;
   - иначе — `UnauthorizedException('Неверный код')`.
6. При успехе — сбрасывает счётчик попыток и выпускает токены через `issueTokens`.

**Исключения:**
- `UnauthorizedException` — истёкший/невалидный токен, неверный тип токена, блокировка, 2FA не включена, неверный код.

**Защита от брутфорса:** лимит 5 попыток / 15 минут → блокировка на 24 часа.

---

### 2.4. `resendVerificationEmail(email: string): Promise<{ success: true }>`

Повторно отправляет письмо подтверждения email.

**Логика:**
- Если пользователь не найден — возвращает `{ success: true }` **без ошибки** (защита от энумерации email-адресов).
- Если email уже подтверждён — `ConflictException`.
- Иначе — отправляет письмо заново.

---

### 2.5. `verifyEmailByCode(email: string, code: string): Promise<{ success, alreadyVerified? }>`

Подтверждение email коротким кодом (например, из письма).

**Логика:**
1. Если email уже подтверждён — сразу `{ success: true, alreadyVerified: true }`.
2. Сравнивает переданный `code` с кодом, хранящимся в Redis (`email_verification_code:{email}`, TTL 15 минут).
3. При несовпадении (или отсутствии пользователя) — инкрементирует `email_verification_attempts:{email}` (TTL 15 минут), при превышении 5 попыток — блокирует на 15 минут ошибкой `UnauthorizedException`.
4. При совпадении — удаляет счётчик попыток и код из Redis, помечает email подтверждённым.

**Исключения:**
- `UnauthorizedException` — неверный код или превышен лимит попыток.

---

### 2.6. `verifyEmailByToken(token: string): Promise<{ success, alreadyVerified? }>`

Подтверждение email по ссылке из письма (JWT-токен).

**Логика:**
1. Верифицирует JWT; ошибка → `UnauthorizedException` («ссылка недействительна или истекла»).
2. Проверяет `payload.purpose === 'verify-email'`.
3. Проверяет существование пользователя и текущий статус подтверждения.
4. Помечает email подтверждённым (`markEmailVerified`).

---

### 2.7. `forgotPassword(email: string): Promise<{ success: true }>`

Инициирует процесс восстановления пароля.

**Логика:**
1. Если пользователь не найден — возвращает `{ success: true }` (защита от энумерации email).
2. Инкрементирует `password_reset_attempts:{email}` (TTL 1 час); если запросов больше 3 за час — тихо возвращает успех, письмо не отправляется (rate-limit).
3. Генерирует случайный `resetToken` (32 байта → 64 hex-символа), сохраняет в Redis (`password_reset_token:{token}` → `email`, TTL 1 час).
4. Отправляет письмо со ссылкой сброса пароля.

**Важно:** метод **всегда** возвращает `{ success: true }`, независимо от того, существует ли пользователь — это стандартная практика против email enumeration.

---

### 2.8. `resetPassword(token: string, newPassword: string): Promise<{ success: true }>`

Завершает восстановление пароля по токену из письма.

**Логика:**
1. Получает `email` по `resetToken` из Redis. Нет записи → `UnauthorizedException` (токен недействителен/истёк).
2. Находит пользователя по email.
3. Проверяет, что новый пароль **не совпадает** с текущим (`bcrypt.compare`) — иначе `ConflictException`.
4. Хеширует и сохраняет новый пароль.
5. Удаляет **все** refresh-токены пользователя (принудительный разлогин на всех устройствах).
6. Удаляет использованный `resetToken` из Redis (одноразовость).

---

### 2.9. `changePassword(userId, currentPassword, newPassword): Promise<{ success: true }>`

Смена пароля авторизованным пользователем (требует `JwtAuthGuard` на уровне контроллера).

**Логика:**
1. Проверяет текущий пароль — иначе `UnauthorizedException`.
2. Проверяет, что новый пароль отличается от старого — иначе `ConflictException`.
3. Обновляет `passwordHash`.
4. Удаляет все refresh-токены пользователя (разлогин на всех устройствах).

---

### 2.10. `refresh(refreshToken: string): Promise<{ accessToken, refreshToken }>`

Обновляет пару токенов по refresh-токену (реализует **ротацию** refresh-токенов).

**Логика:**
1. Хеширует переданный refresh-токен (SHA-256) и ищет его в БД вместе с пользователем.
2. Если запись не найдена или срок истёк — `UnauthorizedException`.
3. Удаляет использованный refresh-токен (одноразовость / ротация).
4. Выпускает новую пару токенов через `issueTokens`.

**Замечание:** т.к. в БД хранится сразу хеш, сам refresh-токен нигде не сохраняется в открытом виде — компрометация БД не даёт возможности им воспользоваться.

---

### 2.11. `logout(refreshToken: string): Promise<{ success: true }>`

Инвалидирует refresh-токен (удаляет из БД по хешу). Не выбрасывает ошибку, если токен не найден — операция идемпотентна.

---

### 2.12. `generateTotpSecret(userId: string): Promise<{ qrCodeDataUrl, secret }>`

Первый шаг подключения 2FA.

**Логика:**
1. Проверяет существование пользователя и что 2FA ещё не включена (`ConflictException`, если уже включена).
2. Генерирует TOTP-секрет (`otplib.generateSecret`), сохраняет его в БД (`totpSecret`) — **до подтверждения кодом**, то есть секрет уже персистентен, но `isTotpEnabled` остаётся `false`.
3. Формирует `otpauth://` URI (issuer `ChatApp`, label — email пользователя) и кодирует его в QR-код (data URL).

**Возвращает:** объект для отображения пользователю (QR-код + текстовый секрет для ручного ввода).

---

### 2.13. `enableTotp(userId: string, code: string): Promise<{ success: true }>`

Подтверждает и активирует 2FA.

**Логика:**
1. Проверяет, что секрет сгенерирован ранее и 2FA ещё не включена.
2. Проверяет код через `verifyTotpCode`.
3. Устанавливает `isTotpEnabled = true`.

---

### 2.14. `disableTotp(userId: string, code: string): Promise<{ success: true }>`

Отключает 2FA (требует подтверждения текущим TOTP-кодом).

**Логика:**
1. Проверяет, что 2FA включена и секрет существует.
2. Проверяет код.
3. Очищает `isTotpEnabled` и `totpSecret`.

---

## 3. Приватные вспомогательные методы

### 3.1. `sendVerificationEmail(email: string): Promise<void>`

- Генерирует 6-значный числовой код (`100000`–`999999`).
- Сохраняет в Redis: `email_verification_code:{email}`, TTL 15 минут.
- Параллельно формирует JWT-токен (`purpose: 'verify-email'`, TTL 15 минут) для ссылки в письме.
- Отправляет письмо через `EmailService`, передавая **и код, и токен** — пользователь может подтвердить email либо переходом по ссылке, либо вводом кода вручную.

### 3.2. `markEmailVerified(userId: string): Promise<{ success: true }>`

Устанавливает `isEmailVerified = true` в БД.

### 3.3. `issueTokens(userId: string, email: string): Promise<{ accessToken, refreshToken }>`

Централизованная точка выпуска токенов.

- `accessToken` — подписанный JWT с payload `{ sub: userId, email }`. Срок жизни берётся из настроек `JwtModule` (в самом методе явно не переопределяется).
- `refreshToken` — случайные 40 байт (`randomBytes(40).toString('hex')`, 80 hex-символов), **не JWT**, а непрозрачный токен.
- В БД сохраняется **не сам токен**, а его SHA-256-хеш (`hashToken`) вместе с `userId` и `expiresAt`.
- Срок жизни refresh-токена берётся из `ConfigService` (`JWT_REFRESH_EXPIRES_IN`), по умолчанию `15d`, парсится библиотекой `ms`.

### 3.4. `hashToken(token: string): string`

Возвращает SHA-256-хеш строки в hex — используется для refresh-токенов, чтобы не хранить их в БД в открытом виде.

### 3.5. `verifyTotpCode(userId, secret, token): Promise<boolean>`

Проверка TOTP-кода с защитой от повторного использования (anti-replay):

1. Проверяет код через `otplib.verify` (учитывает стандартное окно допуска `delta`).
2. Если код невалиден — `false`.
3. Вычисляет номер текущего 30-секундного «шага» TOTP и, с учётом `delta`, номер шага, которому соответствует введённый код (`usedStep`).
4. Сравнивает с последним использованным шагом, сохранённым в Redis (`totp_last_step:{userId}`). Если `usedStep` уже был использован или меньше/равен последнему — код отклоняется (`false`), даже если он математически верный. Это предотвращает повторное использование перехваченного кода в течение окна действия.
5. При успехе сохраняет `usedStep` в Redis с TTL 5 минут.

---

## 4. Используемые ключи Redis

| Ключ | Назначение | TTL |
|---|---|---|
| `email_verification_code:{email}` | Код подтверждения email | 15 мин |
| `email_verification_attempts:{email}` | Счётчик неудачных попыток подтверждения email | 15 мин |
| `password_reset_token:{token}` | Связь одноразового токена сброса пароля с email | 1 час |
| `password_reset_attempts:{email}` | Счётчик запросов сброса пароля (rate limit) | 1 час |
| `totp_attempts:{userId}` | Счётчик неверных TOTP-кодов при логине | 15 мин |
| `totp_blocked:{userId}` | Флаг блокировки входа после превышения попыток TOTP | 24 часа |
| `totp_last_step:{userId}` | Anti-replay: последний использованный шаг TOTP | 5 мин |

---

## 5. Модель токенов

| Токен | Формат | Хранение | Срок жизни | Назначение |
|---|---|---|---|---|
| Access token | JWT (`sub`, `email`) | не хранится на сервере | из конфигурации `JwtModule` | авторизация запросов |
| Refresh token | случайные 40 байт (hex) | в БД хранится SHA-256-хеш | `JWT_REFRESH_EXPIRES_IN` (по умолчанию 15d) | обновление access-токена, ротируется при каждом использовании |
| Temp TOTP token | JWT (`sub`, `email`, `purpose: 'totp-login'`) | не хранится | 5 мин | промежуточный шаг логина при включённой 2FA |
| Email verify token | JWT (`email`, `purpose: 'verify-email'`) | не хранится | 15 мин | подтверждение email по ссылке |

---

## 6. Замечания и потенциальные риски

Эти пункты стоит держать в поле зрения при дальнейшей доработке — они не являются багами документации, а фиксируют текущее поведение кода «как есть».

1. **Проверка `isEmailVerified` при логине закомментирована.** Сейчас пользователь может войти в систему, даже не подтвердив email. Если это не задумано как временная мера — стоит раскомментировать блок в `login()`.
2. **`generateTotpSecret` сохраняет секрет в БД до подтверждения кодом.** Если пользователь сгенерировал секрет, но не завершил включение 2FA (`enableTotp`), секрет остаётся висеть в БД. Это не критично (2FA всё ещё выключена), но стоит учитывать при повторных вызовах — метод просто перезапишет старый секрет новым.
3. **Различие в обработке несуществующего пользователя.** `forgotPassword` и `resendVerificationEmail` намеренно не раскрывают, существует ли email (возвращают `success: true`), тогда как `login` тоже не раскрывает разницу между «нет пользователя» и «неверный пароль» — это единообразное и правильное поведение против enumeration-атак.
4. **`resetPassword`/`changePassword` инвалидируют все refresh-токены пользователя** — корректное поведение безопасности (разлогин на всех устройствах при смене пароля).
5. **Сообщения об ошибках на русском языке** зашиты прямо в сервисе (не вынесены в i18n-слой) — стоит учитывать при мультиязычности фронтенда.
6. **Rate limiting на уровне контроллера** (`@Throttle`) применён только к `login` и `refresh`; логика в самом сервисе (Redis-счётчики) покрывает дополнительно TOTP, подтверждение email и сброс пароля, но, например, `register` не имеет собственной защиты от брутфорса на уровне сервиса — полагается только на глобальный throttler, если он подключён.

---

## 7. Связанные эндпоинты (`AuthController`)

| Метод сервиса | HTTP | Роут | Guard |
|---|---|---|---|
| `register` | POST | `/auth/register` | — |
| `login` | POST | `/auth/login` | Throttle 5/мин |
| `verifyTotpLogin` | POST | `/auth/totp/login` | — |
| `refresh` | POST | `/auth/refresh` | Throttle 5/мин |
| `logout` | POST | `/auth/logout` | — |
| `forgotPassword` | POST | `/auth/forgot-password` | — |
| `resetPassword` | POST | `/auth/reset-password` | — |
| `changePassword` | POST | `/auth/change-password` | `JwtAuthGuard` |
| `verifyEmailByCode` | POST | `/auth/verify-email` | — |
| `verifyEmailByToken` | GET | `/auth/verify-email/:token` | — |
| `resendVerificationEmail` | POST | `/auth/resend-verification` | — |
| `generateTotpSecret` | POST | `/auth/totp/generate` | `JwtAuthGuard` |
| `enableTotp` | POST | `/auth/totp/enable` | `JwtAuthGuard` |
| `disableTotp` | POST | `/auth/totp/disable` | `JwtAuthGuard` |
| — (`req.user`) | GET | `/auth/profile` | `JwtAuthGuard` |
