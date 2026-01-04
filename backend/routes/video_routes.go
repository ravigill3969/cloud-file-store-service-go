package routes

// import (
// 	"net/http"

// 	"github.com/ravigill3969/cloud-file-store/backend/handlers"
// 	middleware "github.com/ravigill3969/cloud-file-store/backend/middlewares"
// 	"github.com/redis/go-redis/v9"
// )

// func VideoRoutes(mux *http.ServeMux, v *handlers.VideoHandler, redis *redis.Client) {
// 	authMw := &middleware.RedisStruct{
// 		RedisClient: redis,
// 	}

// 	mux.Handle("GET /api/video/get", authMw.AuthMiddleware((http.HandlerFunc(v.GetAllVideosWithUserID))))
// 	mux.Handle("POST /api/video/upload", authMw.AuthMiddleware((http.HandlerFunc(v.VideoUpload))))
// 	mux.HandleFunc("GET /api/video/watch/", v.GetVideoWithIDandServeItInChunks)
// 	mux.Handle("DELETE /api/video/delete", authMw.AuthMiddleware(http.HandlerFunc(v.DeleteVideoWithUserID)))

// 	mux.HandleFunc("POST /api/video/upload/{publicKey}/secret/{secretKey}", v.UploadVideoForThirdParty)
// 	mux.HandleFunc("DELETE /api/video/delete/{publicKey}/secret/{secretKey}/{vid}", v.DeleteVideoForThirdParty)

// }
