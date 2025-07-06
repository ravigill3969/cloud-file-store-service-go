package routes

import (
	"net/http"

	"github.com/ravigill3969/cloud-file-store/handlers"
	middleware "github.com/ravigill3969/cloud-file-store/middlewares"
	"github.com/redis/go-redis/v9"
)

func FileRoutes(mux *http.ServeMux, fh *handlers.FileHandler, redis *redis.Client) {
	authMw := &middleware.RedisStruct{
		RedisClient: redis,
	}
	mux.Handle("POST /api/file/upload", authMw.AuthMiddleware(http.HandlerFunc(fh.UploadFile)))
	mux.HandleFunc("POST /api/file/{secretKey}/secure/{publicKey}", fh.UploadAsThirdParty)
	mux.HandleFunc("POST /api/file/{id}/{publicKey}/?width={width}&height={height}", fh.GetFileEditStoreInS3ThenInPsqlWithWidthAndSize)
	mux.HandleFunc("GET /api/file/{id}/{publicKey}", fh.ServeFileWithID)
}
