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
	mux.HandleFunc("GET /api/file/get/{id}/{publicKey}/secure/{secretKey}", fh.ServeFileWithID)
	mux.HandleFunc("POST /api/file/upload/{publicKey}/secure/{secretKey}", fh.UploadAsThirdParty)
	mux.HandleFunc("POST /api/file/edit/{id}/{publicKey}/secure/{secretKey}", fh.GetFileEditStoreInS3ThenInPsqlWithWidthAndSize)
}
