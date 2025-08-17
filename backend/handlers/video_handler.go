package handlers

import (
	"net/http"

	pb "github.com/ravigill3969/cloud-file-store-service-video-goGrpc/video"
	"github.com/redis/go-redis/v9"
)

type VideoHandler struct {
	VideoClient pb.VideoServiceClient
	RedisClient *redis.Client
}

func (v *VideoHandler) VideoUpload(w http.ResponseWriter, r *http.Request) {

	v.VideoClient.UploadVideo(r.Context(), &pb.UploadVideoRequest{ })
}
