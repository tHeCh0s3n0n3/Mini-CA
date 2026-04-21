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

#### Generic Registry:
```bash
docker login <your-registry-url>
```

#### GitHub Container Registry (GHCR):
1.  Create a **Personal Access Token (classic)** with `write:packages` scope.
2.  Authenticate via CLI:
```bash
echo $CR_PAT | docker login ghcr.io -u <your-github-username> --password-stdin
```

### 4. Push the images

#### Generic Registry:
```bash
docker push <your-registry-url>/mini-ca-backend:latest
docker push <your-registry-url>/mini-ca-frontend:latest
```

#### GitHub Container Registry (GHCR):
Assuming your GitHub organization or username is `my-org`:
```bash
# Tag for GHCR
docker tag mini-ca-backend:latest ghcr.io/my-org/mini-ca-backend:latest
docker tag mini-ca-frontend:latest ghcr.io/my-org/mini-ca-frontend:latest

# Push to GHCR
docker push ghcr.io/my-org/mini-ca-backend:latest
docker push ghcr.io/my-org/mini-ca-frontend:latest
```
