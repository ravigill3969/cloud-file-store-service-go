# 🌩️ CloudAPI - Developer Docs

**CloudAPI** offers a secure and scalable interface to interact with cloud resources. Use the endpoints below to upload, retrieve, and modify image files using your generated API keys.

---

## 🔐 Authentication

To use the API, sign up on the platform to obtain:

* `publicKey`
* `secretKey`

These keys are required for all file upload and editing endpoints.

---

## 📁 API Endpoints

### 1. ✅ **Upload Image**

Upload a single image securely to the platform.

```
POST /api/file/upload/{publicKey}/secure/{secretKey}
```

#### Headers

```http
Content-Type: multipart/form-data
```

#### Body

* `file`: (form-data) **Single image file**

#### Example (cURL)

```bash
curl -X POST \
  -F "file=@/path/to/image.jpg" \
  https://yourdomain.com/api/file/upload/YOUR_PUBLIC_KEY/secure/YOUR_SECRET_KEY
```

#### Response

```json
{
  "status": "success",
  "fileId": "abc123",
  "message": "File uploaded successfully"
}
```

---



### 2. ✏️ **Edit Image (Resize)**

Resize an existing image (e.g., to specific width or scale) and save it.

```
POST /api/file/edit/{id}/{publicKey}/secure/{secretKey}
```

#### Headers

```http
Content-Type: application/json
```

#### Body

```json
{
  "width": 800,
  "size": "medium" // optional - can represent preset sizes if defined
}
```

#### Example (cURL)

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"width":800, "height":"800"}' \
  https://yourdomain.com/api/file/edit/abc123/YOUR_PUBLIC_KEY/secure/YOUR_SECRET_KEY
```

#### Response

```json
{
  "status": "success",
  "message": "Image resized and stored successfully"
}
```

---

## 📌 Rules & Notes

* 📸 Only **one image file** can be uploaded per request.
* 🔐 Keep your `secretKey` secure. Never expose it in public repositories or client-side code.
* 🗂️ All files are securely stored in S3, with metadata in PostgreSQL.
* 📦 File IDs are returned in responses and must be used for access or editing.

---

## 🔄 Status Codes

| Code  | Meaning                                |
| ----- | -------------------------------------- |
| `200` | Success                                |
| `400` | Bad request (invalid file or keys)     |
| `403` | Unauthorized (bad or missing API keys) |
| `404` | File not found                         |
| `500` | Internal server error                  |

---

## 🚀 Future Plans

* Support for image format conversion (`jpg`, `png`, `webp`)
* Rate limiting and API usage tracking
* Optional webhook notifications on file events

---
