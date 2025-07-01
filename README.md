# cloud-file-store-service-go

cloud-file-store/
│
├── cmd/
│   └── server/             # Main entry point for the app
│       └── main.go
│
├── internal/
│   ├── handlers/           # All HTTP handlers (e.g., user, auth)
│   │   ├── user_handler.go
│   │   └── auth_handler.go
│   │
│   ├── services/           # Business logic, token generation, etc.
│   │   ├── auth_service.go
│   │   └── user_service.go
│   │
│   ├── db/                 # Database access logic
│   │   ├── db.go
│   │   └── migrations.sql
│   │
│   ├── middleware/         # Custom middleware (auth, headers, rate limiting)
│   │   └── auth_middleware.go
│   │
│   ├── models/             # Structs for DB and request/response payloads
│   │   ├── user.go
│   │   └── auth.go
│   │
│   └── utils/              # Helper functions (e.g., password hashing, JWT)
│       └── crypto.go
│
├── routes/                 # Route registration for all endpoints
│   └── routes.go
│
├── config/                 # App configuration and loading from env/files
│   └── config.go
│
├── go.mod
└── go.sum
