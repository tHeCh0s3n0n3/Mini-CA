# Docker Push Instructions

To deploy the Mini CA images to a container registry, follow these steps:

### 1. Build the images
Build the images using Docker Compose:
```bash
docker compose build
```

### 2. Tag the images
Tag the images with your registry path. Assuming your project directory is named `mini-ca`, Docker Compose will name the images `mini-ca-backend` and `mini-ca-frontend`:

```bash
docker tag mini-ca-backend:latest <your-registry-url>/mini-ca-backend:latest
docker tag mini-ca-frontend:latest <your-registry-url>/mini-ca-frontend:latest
```

### 3. Log in to your registry
```bash
docker login <your-registry-url>
```

### 4. Push the images
```bash
docker push <your-registry-url>/mini-ca-backend:latest
docker push <your-registry-url>/mini-ca-frontend:latest
```
