# Docker Development Environment

This directory contains Dockerfiles for building persistent development environments for pysymex across multiple Python versions.

## Overview

The Docker setup provides pre-built images with all dependencies installed, eliminating the need to reinstall packages on every container restart. This significantly speeds up development and testing workflows.

## Available Images

- **Dockerfile.311**: Python 3.11 environment with pysymex and dev dependencies
- **Dockerfile.312**: Python 3.12 environment with pysymex and dev dependencies
- **Dockerfile.313**: Python 3.13 environment with pysymex and dev dependencies

## Usage

### Start all containers

```bash
docker-compose up -d
```

### Stop all containers

```bash
docker-compose down
```

### Rebuild images (after dependency changes)

```bash
docker-compose build
```

### Run tests in all Python versions

Use the provided test script from the project root:

```bash
python tests/docker.py
```

This will run pytest in parallel across all three Python versions and display aggregated results.

### Execute commands in specific containers

```bash
# Python 3.11
docker exec pysymex-python311 python -m pytest

# Python 3.12
docker exec pysymex-python312 python -m pytest

# Python 3.13
docker exec pysymex-python313 python -m pytest
```

## Container Persistence

Containers are configured with `restart: unless-stopped`, meaning they will:
- Start automatically when Docker starts
- Restart automatically if they crash
- Persist across system reboots

To stop containers permanently, use `docker-compose down`.

## Volume Mounts

The project directory is mounted at `/workspace` in each container, allowing live code editing without rebuilding images.

## System Dependencies

Each image includes:
- `gcc` and `g++` for compiling native extensions (numba, llvmlite)
- Python package build tools (pip, setuptools, wheel)
- All pysymex dependencies from `pyproject.toml`

## Troubleshooting

### Container won't start

Check if ports are in use or if Docker daemon is running:

```bash
docker ps
docker-compose logs python311
```

### Dependencies outdated

Rebuild the images:

```bash
docker-compose build --no-cache
```

### Tests failing in container but passing locally

This may be due to environment differences. Check container logs:

```bash
docker-compose logs python311
```
