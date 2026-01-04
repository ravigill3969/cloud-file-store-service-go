package routes

import (
	"net/http"

	"github.com/ravigill3969/cloud-file-store/backend/handlers"
	middleware "github.com/ravigill3969/cloud-file-store/backend/middlewares"
	"github.com/redis/go-redis/v9"
)

func FileRoutes(mux *http.ServeMux, fh *handlers.FileHandler, redis *redis.Client) {
	authMw := &middleware.RedisStruct{
		RedisClient: redis,
	}
	mux.Handle("POST /api/file/edit/{id}/", authMw.AuthMiddleware(http.HandlerFunc(fh.HandleImageResizeRequestForUser)))

	mux.Handle("POST /api/file/upload", authMw.AuthMiddleware(http.HandlerFunc(fh.UploadFilesWithGoRoutines)))
	mux.Handle("POST /api/media/upload", authMw.AuthMiddleware(http.HandlerFunc(fh.UploadMedia)))

	mux.Handle("GET /api/file/get-all", authMw.AuthMiddleware(http.HandlerFunc(fh.GetAllUserFiles)))
	mux.Handle("GET /api/file/download", authMw.AuthMiddleware(http.HandlerFunc(fh.DownloadFile)))
	mux.Handle("GET /api/file/deleted-images", authMw.AuthMiddleware(http.HandlerFunc(fh.ListSoftDeletedImagesByUser)))
	mux.Handle("PATCH /api/file/recover", authMw.AuthMiddleware(http.HandlerFunc(fh.RecoverDeletedImage)))
	mux.Handle("DELETE /api/file/delete", authMw.AuthMiddleware(http.HandlerFunc(fh.DeleteImages)))
	mux.Handle("DELETE /api/file/delete-permanently", authMw.AuthMiddleware(http.HandlerFunc(fh.HardDeleteSoftDeletedImage)))

	// mux.HandleFunc("GET /api/file/get/{id}", fh.ServeFileWithIDForUI)
	mux.HandleFunc("GET /api/file/get-file/{id}", fh.ServeFileWithIDForThirdParty)
	mux.HandleFunc("POST /api/file/upload/{publicKey}/secure/{secretKey}", fh.UploadAsThirdParty)
	mux.HandleFunc("POST /api/file/edit/{id}/{publicKey}/secure/{secretKey}", fh.HandleImageResizeRequestForThirdParty)
	mux.HandleFunc("DELETE /api/file/delete/{id}/{publicKey}/secure/{secretKey}", fh.DeleteImageForThirdParty)

	mux.HandleFunc("POST /api/media/upload/{publicKey}/secure/{secretKey}", fh.UploadMediaForThirdParty)
	// Video Routes
	mux.Handle("POST /api/video/upload", authMw.AuthMiddleware(http.HandlerFunc(fh.VideoUpload)))
	mux.Handle("DELETE /api/video/delete", authMw.AuthMiddleware(http.HandlerFunc(fh.DeleteVideoWithUserID)))
	mux.Handle("GET /api/video/get-all", authMw.AuthMiddleware(http.HandlerFunc(fh.GetAllVideosWithUserID)))

	mux.HandleFunc("GET /api/video/watch/", fh.HandleMediaStreamingRequest)
	mux.HandleFunc("POST /api/video/upload/{publicKey}/secure/{secretKey}", fh.UploadVideoForThirdParty)
	mux.HandleFunc("DELETE /api/video/delete/{publicKey}/secure/{secretKey}/{vid}", fh.DeleteVideoForThirdParty)
}
	