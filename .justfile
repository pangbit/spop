# Set the image name
IMAGE_NAME := "haproxy-spoe"
CONTAINER_NAME := "haproxy"

# Run HAProxy container with port 5000 exposed
run: build
    podman run -d --name {{CONTAINER_NAME}} --network=host {{IMAGE_NAME}}

# Build the HAProxy image
build:
    podman build -t {{IMAGE_NAME}} .

# Stop and remove HAProxy container
stop:
    podman stop {{CONTAINER_NAME}} || true
    podman rm {{CONTAINER_NAME}} || true

# Restart the container (stop -> build -> run)
restart:
    just stop
    just build
    just run

# Check HAProxy logs
logs:
    podman logs -f {{CONTAINER_NAME}}

# Test the HAProxy response
test:
    curl -v http://0:5000

# Attach to the running container for debugging
shell:
    podman exec -it {{CONTAINER_NAME}} bash

clippy: fmt
  cargo clippy --all -- -W clippy::all -W clippy::nursery -D warnings

fmt:
  cargo fmt --all -- --check

# Run the example
agent:
  cargo watch -x 'run --example agent'
