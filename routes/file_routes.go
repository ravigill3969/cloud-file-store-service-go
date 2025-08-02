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
	mux.Handle("POST /api/file/upload", authMw.AuthMiddleware(http.HandlerFunc(fh.UploadFilesWithGoRoutines)))
	mux.Handle("GET /api/file/get-all", authMw.AuthMiddleware(http.HandlerFunc(fh.GetAllUserFiles)))
	mux.Handle("GET /api/file/download", authMw.AuthMiddleware(http.HandlerFunc(fh.DownloadFile)))
	mux.Handle("GET /api/file/deleted-images", authMw.AuthMiddleware(http.HandlerFunc(fh.GetAllImagesWithUserIDWhichAreDeletedEqFalse)))
	mux.Handle("DELETE /api/file/delete", authMw.AuthMiddleware(http.HandlerFunc(fh.DeleteImages)))

	// mux.HandleFunc("GET /api/file/get/{id}", fh.ServeFileWithIDForUI)
	mux.HandleFunc("GET /api/file/get-file/{id}", fh.ServeFileWithIDForThirdParty)
	mux.HandleFunc("POST /api/file/upload/{publicKey}/secure/{secretKey}", fh.UploadAsThirdParty)
	mux.HandleFunc("POST /api/file/edit/{id}/{publicKey}/secure/{secretKey}", fh.GetFileEditStoreInS3ThenInPsqlWithWidthAndSize)
}
