#Dockerfile vars

#vars
IMAGENAME=go-docker-proxy
APP_NAME=go-docker-proxy
TAG=v0.1.0
BUILDDATE=${shell date -u +%Y-%m-%dT%H:%M:%SZ}
BRANCHSHORT=$(shell echo ${BRANCH} | awk -F. '{ print $$1"."$$2 }')
IMAGEFULLNAME=avhost/${IMAGENAME}
BRANCH=${TAG}
LASTCOMMIT=$(shell git log -1 --pretty=short | tail -n 1 | tr -d " " | tr -d "UPDATE:")


.DEFAULT_GOAL := all

build:
	@echo ">>>> Build docker image: " latest
	@docker build --build-arg TAG=${TAG} --build-arg BUILDDATE=${BUILDDATE} -t ${IMAGEFULLNAME}:latest .

build-bin:
	@echo ">>>> Build binary"
	@CGO_ENABLED=0 GOOS=linux go build -o ${APP_NAME} -a -installsuffix cgo -ldflags "-X main.BuildVersion=${BUILDDATE} -X main.GitVersion=${TAG} -extldflags \"-static\"" .

push:
	@echo ">>>> Publish oci image: " ${BRANCH} ${BRANCHSHORT}
	-docker buildx create --use --name buildkit
	@docker buildx build --sbom=true --provenance=true --platform linux/arm64,linux/amd64 --push --build-arg TAG=${TAG} --build-arg BUILDDATE=${BUILDDATE} -t ${IMAGEFULLNAME}:${BRANCH} .
	@docker buildx build --sbom=true --provenance=true --platform linux/arm64,linux/amd64 --push --build-arg TAG=${TAG} --build-arg BUILDDATE=${BUILDDATE} -t ${IMAGEFULLNAME}:${BRANCHSHORT} .
	@docker buildx build --sbom=true --provenance=true --platform linux/arm64,linux/amd64 --push --build-arg TAG=${TAG} --build-arg BUILDDATE=${BUILDDATE} -t ${IMAGEFULLNAME}:latest .
	-docker buildx rm buildkit

update-gomod:
	go get -u
	go mod tidy

sboom:
	syft dir:. > sbom.txt
	syft dir:. -o json > sbom.json

seccheck:
	grype --add-cpes-if-none .

imagecheck:
	grype --add-cpes-if-none ${IMAGEFULLNAME}:latest > cve-report.md

go-fmt:
	@gofmt -w .

check: go-fmt sboom seccheck
all: build check build-bin imagecheck
