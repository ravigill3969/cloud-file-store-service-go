module github.com/ravigill3969/cloud-file-store

go 1.23.10

require (
	github.com/aws/aws-sdk-go v1.55.8
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/google/uuid v1.6.0
	github.com/joho/godotenv v1.5.1
	github.com/lib/pq v1.10.9
	github.com/ravigill3969/cloud-file-store-service-video-goGrpc v0.0.0-00010101000000-000000000000
	github.com/redis/go-redis/v9 v9.12.1
	github.com/stripe/stripe-go/v82 v82.3.0
	golang.org/x/crypto v0.39.0
	google.golang.org/grpc v1.74.2
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250528174236-200df99c418a // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)

replace github.com/ravigill3969/cloud-file-store-service-video-goGrpc => ./cloud-file-store-service-video-goGrpc
