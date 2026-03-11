example-image: image
	docker build -t io-example ./example

volume:
	docker volume create io-example

example: example-image volume
	docker run --privileged --ulimit nofile=5000:5000 -v io-example:/var/run/test -v /tmp:/tmp -it io-example /main-app

debug:
	cargo build

image:
	DOCKER_BUILDKIT=1 docker build --build-arg HTTP_PROXY=${HTTP_PROXY} --build-arg HTTPS_PROXY=${HTTPS_PROXY} . -t chaos-mesh/toda

# Build for the current host architecture and copy the binary out.
release: image
	docker run -v ${PWD}:/opt/mount:z --rm --entrypoint cp chaos-mesh/toda /toda /opt/mount/toda

# Build a multi-architecture image for both amd64 and arm64 using buildx.
# Requires Docker Buildx and QEMU support (docker run --privileged tonistiigi/binfmt --install all).
image-multiarch:
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--build-arg HTTP_PROXY=${HTTP_PROXY} \
		--build-arg HTTPS_PROXY=${HTTPS_PROXY} \
		. -t chaos-mesh/toda

# Extract the aarch64 binary from the arm64 image.
release-arm64:
	DOCKER_BUILDKIT=1 docker build --build-arg HTTP_PROXY=${HTTP_PROXY} --build-arg HTTPS_PROXY=${HTTPS_PROXY} \
		--platform linux/arm64 . -t chaos-mesh/toda:arm64
	docker run --platform linux/arm64 -v ${PWD}:/opt/mount:z --rm --entrypoint cp chaos-mesh/toda:arm64 /toda /opt/mount/toda
