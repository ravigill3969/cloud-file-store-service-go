package routes

import (
	"net/http"

	"github.com/ravigill3969/cloud-file-store/handlers"
	middleware "github.com/ravigill3969/cloud-file-store/middlewares"
)

func FileRoutes(mux *http.ServeMux, fh *handlers.FileHandler) {
	mux.Handle("POST /api/file/upload", middleware.AuthMiddleware(http.HandlerFunc(fh.UploadFile)))
	mux.HandleFunc("POST /api/file/{secretKey}/secure/{publicKey}" ,  fh.UploadAsThirdParty)
}
