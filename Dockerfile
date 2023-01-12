FROM golang:alpine as builder

WORKDIR /build

COPY . /build/

RUN apk add git && \
    go get -d

RUN go mod vendor; CGO_ENABLED=0 GOOS=linux go build -mod=vendor -a -installsuffix cgo -ldflags "-X main.MinVersion=`date -u +%Y%m%d%.H%M%S` -extldflags \"-static\"" -o main .


FROM alpine
LABEL maintainer="Andreas Peters <support@aventer.biz>"

ENV API_PROXYPORT=10777 
ENV API_PROXYBIND=0.0.0.0
ENV TARGET_URL=http://test
ENV SKIP_SSL=false
ENV LOG_LEVEL=info

RUN apk add --no-cache ca-certificates
RUN adduser -S -D -H -h /app appuser


COPY --from=builder /build/main /app/

RUN mkdir -p /app/cache
RUN chown -R appuser: /app

USER appuser

EXPOSE 10777

WORKDIR "/app"

CMD ["./main"]
