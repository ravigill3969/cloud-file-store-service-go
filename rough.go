// type SuccessRes struct {
// 	Filename string
// 	URL      string
// }

// func uploadWorker(filename string, successCh chan SuccessRes, errCh chan error) {
// 	// Simulate a successful upload
// 	if filename == "badfile.txt" {
// 		errCh <- fmt.Errorf("upload failed: %s", filename)
// 		return
// 	}
// 	successCh <- SuccessRes{Filename: filename, URL: "https://example.com/" + filename}
// }

// func main() {
// 	files := []string{"file1.txt", "file2.txt", "badfile.txt"}

// 	successCh := make(chan SuccessRes, len(files))
// 	errCh := make(chan error, len(files))

// 	for _, f := range files {
// 		go uploadWorker(f, successCh, errCh)
// 	}

// 	for i := 0; i < len(files); i++ {
// 		select {
// 		case s := <-successCh:
// 			fmt.Println("Uploaded:", s)
// 		case err := <-errCh:
// 			fmt.Println("Error:", err)
// 		}
// 	}
// }


package cloudfilestoreservicego