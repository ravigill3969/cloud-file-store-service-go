````markdown
##   🌩️ CloudAPI – Developer Documentation

CloudAPI provides a **secure** and **scalable** REST interface for uploading, retrieving, and editing cloud-based image resources.

---

## ✨ Features

- **Secure API-key authentication**
- **Multi-format support**: `jpg`, `jpeg`, `png`, `gif`
- **Cloud-native design**

---

## 🔐 Authentication

Sign up to receive your unique keys:

- **publicKey**
- **secretKey**

Both keys are **required** for every upload and edit request.

---

## 📤 Upload Image

**`POST`** `/api/file/upload/{publicKey}/secure/{secretKey}`

Upload a single image with `multipart/form-data`.

### ✅ Supported MIME Types

- `image/jpeg`
- `image/png`
- `image/gif`

### 📦 Request

- **Form field:** `file`
- **Max size:** `5 MB`

### 🟢 Success Response

```json
{
  "url": "https://<your-backend-url>/api/file/get-file/<file_id>"
}
```
````

### 🔴 Error Responses

| Code  | Message                               | Cause                  |
| ----- | ------------------------------------- | ---------------------- |
| `400` | Could not parse multipart form        | Bad request format     |
| `400` | File not provided                     | Missing form field     |
| `400` | Image size exceeds 5MB limit          | File too large         |
| `400` | Filename missing in upload            | Form missing filename  |
| `400` | Invalid path                          | URL formatting issue   |
| `401` | Invalid public or secret key          | Auth key mismatch      |
| `401` | Post req limit reached for this month | Monthly quota exceeded |
| `415` | Unsupported media type                | Invalid file MIME type |
| `500` | Error reading file                    | File read failed       |
| `500` | Failed to generate presigned URL      | S3 config error        |
| `500` | Failed to upload file to S3           | Network/S3 issue       |
| `500` | Unable to save data                   | Database insert failed |

---

## 📥 Retrieve Image

**`GET`** `/api/file/get-file/{id}`

Fetch a previously uploaded image.

### 🟢 Success

Returns the image data directly.

### 🔴 Error Responses

| Code  | Message               | Cause                 |
| ----- | --------------------- | --------------------- |
| `400` | Invalid URL structure | Improper route format |
| `400` | Invalid id            | ID missing or invalid |
| `404` | File not found        | ID not found in DB    |

---

## ✏️ Edit Image

**`POST`** `/api/file/edit/{id}/{publicKey}/secure/{secretKey}`

Resize an uploaded image.

### 🔍 Query Parameters

| Param    | Description           |
| -------- | --------------------- |
| `width`  | New width (required)  |
| `height` | New height (required) |

### 🟢 Success Response

```json
{
  "url": "https://<your-backend-url>/api/file/get-file/<new_file_id>",
}
```

### 🔴 Error Responses

| Code  | Message                       | Cause                  |
| ----- | ----------------------------- | ---------------------- |
| `400` | Invalid URL                   | Malformed edit route   |
| `400` | Width and height are required | Missing query params   |
| `404` | Image not found               | ID doesn’t exist in DB |
| `403` | Insufficient quota            | Edit quota exceeded    |
| `500` | Image resize failed           | Resize process failed  |
| `500` | Failed to insert image        | Database save failed   |
| `500` | Server error                  | Unknown backend error  |

---

## 🛠️ Contact & Support

- **Support Portal** – [Visit](https://cloudapi.dev/support)
- **Email** – support@cloudapi.dev

---

> Built for developers. Powered by the cloud. ☁️

```

```
