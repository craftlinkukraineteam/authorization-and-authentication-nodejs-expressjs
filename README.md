### Authorization and Authentication

Невеликий бекенд‑застосунок, створений на Node.js, який відповідає за реєстрацію та автентифікацію користовучів у системі.
Застосунок взаємодіє з клієнтом (Next.js) через REST API та використовує JWT (JSON Web Token) для аутентифікації.


### Використані технології
- Node.js;
- Express.js;
- TypeScript;
- BCrypt;
- Swagger UI;
- YAML;
- JWT (JSON Web Token);


### Логіка роботи
Серверний сервіс взаємодіє із клієнтським сервісом через такі API-ендпоінти:
```properties
POST   /auth/register
POST   /auth/login
POST   /auth/logout
POST   /auth/refresh
GET    /auth/profile
POST   /auth/forgot-password
POST   /auth/reset-password
POST   /auth/verify-email
```

### Cтруктура проєкту
```properties
├── .idea/
├── node_module/
├── README.md
├── package-lock.json
├── package.json
├── server.js
└── swagger.yaml
```

### Запуск
Запуск у IDE JetBrains WebStorm через консоль наступною командою:
```properties
node server.js
```

### Оновлення всіх залежностей npm до останніх версій
Запуск у IDE JetBrains WebStorm через консоль наступними командами:
```properties
npm install -g npm-check-updates
ncu -u
npm install
```

### Встановлення залежностей
Запуск у IDE JetBrains WebStorm через консоль наступною командою:
```properties
npm install
```
