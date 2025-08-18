package routes

import (
	"net/http"

	"github.com/ravigill3969/cloud-file-store/backend/handlers"
	middleware "github.com/ravigill3969/cloud-file-store/backend/middlewares"
	"github.com/redis/go-redis/v9"
)

func VideoRoutes(mux *http.ServeMux, v *handlers.VideoHandler, redis *redis.Client) {
	authMw := &middleware.RedisStruct{
		RedisClient: redis,
	}

	mux.Handle("POST /api/video/upload", authMw.AuthMiddleware((http.HandlerFunc(v.VideoUpload))))

}
