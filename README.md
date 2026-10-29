# Crowd-source backend

| Module | Port | Role |
|---|---|---|
| eureka-server | 8761 | service discovery |
| user-service | 8002 | signup/login/refresh/logout, issues ES256 JWTs, publishes JWKS |
| event-service | 8003 | events + capacity (internal) |
| payment-service | 8004 | payments (internal only, no gateway route) |
| registration-service | 8005 | reserve -> pay -> confirm saga (new) |
| api-gateway | 8001 | only public entry point, validates JWT |
| security-shared-utility | - | library: trusts gateway-signed identity headers |

## Security flow
1. `POST /api/auth/v1/login` -> user-service sets HttpOnly cookies `access_token` (15 min, path `/`) and `refresh_token` (7 d, path `/api/auth/v1`).
2. Every request hits the gateway, which validates the JWT (ES256 via JWKS, expiry, issuer). Public: signup, login, refresh, logout.
3. `TokenRelayFilter` strips any client-sent identity headers, then sets `X-User-Id`, `X-User-Name`, `X-User-Authorities`, `X-Gateway-Timestamp`, `X-Gateway-Signature` (HMAC-SHA256 with `GATEWAY_SHARED_SECRET`). The JWT itself is not forwarded.
4. Services (shared lib) verify the signature (60 s window) and build the Authentication: principal = user id, details = e-mail. Everything is authenticated by default; `@PreAuthorize` does RBAC.
5. Refresh tokens are single-use (rotation); reusing a rotated token revokes all sessions of that user.

## Build & run
```
cd security-shared-utility && ./mvnw clean install && cd ..    # must be first
# then, each in its own terminal, in this order:
cd eureka-server && ./mvnw spring-boot:run
cd user-service && ./mvnw spring-boot:run
cd event-service && ./mvnw spring-boot:run
cd payment-service && ./mvnw spring-boot:run
cd registration-service && ./mvnw spring-boot:run
cd api-gateway && ./mvnw spring-boot:run
```
(or `mvn clean install` from this folder to build all). Dev demo users: `user@crowdsource.com/user`, `organizer@crowdsource.com/organizer`, `admin@crowdsource.com/admin`.

## Quick test
```
curl -i -c jar -H 'Content-Type: application/json' -d '{"username":"organizer@crowdsource.com","password":"organizer"}' localhost:8001/api/auth/v1/login
curl -b jar -H 'Content-Type: application/json' -d '{"title":"Meetup","eventDate":"2030-01-01T18:00:00","totalCapacity":50,"ticketPrice":10}' localhost:8001/api/v1/event
curl -b jar -X POST localhost:8001/api/v1/event/1/submit
# log in as admin (new jar), then: POST /api/v1/event/1/approve
# log in as user: POST /api/v1/registration {"eventId":1,"quantity":2}
# spoof test (must be 401): curl -H 'X-User-Id: 3' -H 'X-User-Authorities: ROLE_ADMIN' localhost:8003/v1/event
```

## Configuration
`GATEWAY_SHARED_SECRET` (>= 32 chars, same everywhere; dev default in yaml), `JWT_ISSUER`, `CORS_ALLOWED_ORIGINS`, `EUREKA_URL`.
Prod (`user-service` profile `prod`): key files via `JWT_PRIVATE_KEY_PATH`/`JWT_PUBLIC_KEY_PATH`, secure cookies, external DB (add driver + Flyway/Liquibase).
Keys: `openssl ecparam -name prime256v1 -genkey -noout -out ec.pem && openssl pkcs8 -topk8 -nocrypt -in ec.pem -out private.pem && openssl ec -in ec.pem -pubout -out public.pem`.
