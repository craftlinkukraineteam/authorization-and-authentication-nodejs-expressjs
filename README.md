### Authorization and Authentication

Невеликий фронтенд‑застосунок, створений на Node.js, який відповідає за реєстрацію та автентифікацію користовучів у системі "CraftLink Ukraine".
Застосунок взаємодіє з фронтенд‑мікросервісом (React.js) через REST API та використовує JWT (JSON Web Token) для аутентифікації.


### Використані технології
```properties
- Node.js;
- Express.js;
- TypeScript;
- BCrypt;
- Swagger UI;
- YAML;
- JWT (JSON Web Token);
```

### Логіка роботи
Серверний сервіс взаємодіє із клієнтським сервісом через такі API-ендпоінти:
```properties
POST   /auth/register
POST   /auth/login
POST   /auth/logout
POST   /auth/refresh
GET      /auth/profile
POST   /auth/forgot-password
POST   /auth/reset-password
POST   /auth/verify-email
```
