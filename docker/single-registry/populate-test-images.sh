#!/bin/bash

# Script to populate test registries with popular Docker images
# This creates a realistic test environment with multiple images and tags

set -e

REGISTRY="localhost:5000"

echo "=========================================="
echo "Populating Test Registries with Images"
echo "Registry: $REGISTRY"
echo "=========================================="

# Popular small images with multiple versions
IMAGES=(
    "alpine:3.18 alpine:3.17 alpine:3.16 alpine:latest"
    "nginx:1.25 nginx:1.24 nginx:1.23 nginx:alpine nginx:latest"
    "redis:7.2 redis:7.0 redis:6.2 redis:alpine redis:latest"
    "postgres:16 postgres:15 postgres:14 postgres:13 postgres:alpine"
    "node:20 node:18 node:16 node:20-alpine node:18-alpine"
    "python:3.11 python:3.10 python:3.9 python:3.11-slim python:3.10-alpine"
    "busybox:1.36 busybox:1.35 busybox:latest busybox:musl"
    "ubuntu:22.04 ubuntu:20.04 ubuntu:18.04 ubuntu:latest"
    "mysql:8.0 mysql:5.7 mysql:latest"
    "mongo:7.0 mongo:6.0 mongo:5.0 mongo:latest"
)

pull_tag_push() {
    local source=$1
    local target_registry=$2
    local target_repo=$3
    local target_tag=$4

    echo "  → Pulling $source..."
    docker pull $source --quiet

    echo "  → Tagging as $target_registry/$target_repo:$target_tag..."
    docker tag $source $target_registry/$target_repo:$target_tag

    echo "  → Pushing to $target_registry/$target_repo:$target_tag..."
    docker push $target_registry/$target_repo:$target_tag --quiet

    echo "  ✓ Completed $target_repo:$target_tag"
}


# Populate Registry with subset
echo ""
echo "Populating Registry ($REGISTRY)..."
echo "=========================================="

REGISTRY_IMAGES=(
    "alpine:3.18 alpine:latest"
    "nginx:1.25 nginx:alpine"
    "redis:7.2 redis:alpine"
    "postgres:16 postgres:alpine"
    "node:20 node:20-alpine"
    "python:3.13-alpine3.23 python:3.13-alpine3.22"
)

for image_set in "${REGISTRY_IMAGES[@]}"; do
    read -ra tags <<< "$image_set"
    base_image=$(echo ${tags[0]} | cut -d: -f1)

    echo ""
    echo "Processing $base_image..."

    for tag in "${tags[@]}"; do
        version=$(echo $tag | cut -d: -f2)
        pull_tag_push "$tag" "$REGISTRY" "$base_image" "$version"
    done
done

echo ""
echo "=========================================="
echo "✓ Test registries populated successfully!"
echo "=========================================="
echo ""
echo "Registry ($REGISTRY): ~10+ images"
echo ""
echo "You can now test:"
echo "  - Browse repositories and tags"
echo "  - Filter and sort tags"
echo "  - Bulk operations with age filters"
echo "  - Delete operations"
echo "  - Analytics and statistics"
echo ""
