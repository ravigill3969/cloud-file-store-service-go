package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"

	pb "github.com/grpc/video"
	"google.golang.org/grpc"
)	

// server implements pb.VideoServiceServer
type server struct {
	pb.UnimplementedVideoServiceServer
}

func (s *server) UploadVideo(ctx context.Context, req *pb.UploadVideoRequest) (*pb.UploadVideoResponse, error) {
	// For simplicity, save the file locally with the original filename
	// filename := fmt.Sprintf("./uploads/%s", req.OriginalFilename)
	// err := ioutil.WriteFile(filename, req.FileData, 0644)
	// if err != nil {
	// 	return &pb.UploadVideoResponse{
	// 		Success:      false,
	// 		ErrorMessage: fmt.Sprintf("failed to save file: %v", err),
	// 	}, nil
	// }

	// Construct a fake URL (replace with S3 URL in production)
	videoURL := fmt.Sprintf("http://localhost:8080/uploads/%s", req.OriginalFilename)

	return &pb.UploadVideoResponse{
		Success:  true,
		VideoUrl: videoURL,
	}, nil
}

func main() {
	// Make sure upload folder exists
	_ = ioutil.WriteFile("./uploads/.keep", []byte{}, 0644)

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterVideoServiceServer(s, &server{})

	log.Println("gRPC server running on :50051")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
