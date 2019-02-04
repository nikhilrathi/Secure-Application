FROM golang:1.11.5 as stage1
LABEL maintainer="Nikhil Rathi <contact@nikhilrathi.com>"
WORKDIR $GOPATH/src/secure_application
ENV GO111MODULE=on
RUN go mod init
COPY . $GOPATH/src/secure_application 
RUN go get -d -v ./...
RUN CGO_ENABLED=1 GOOS=linux go build -installsuffix cgo -ldflags "-linkmode external -extldflags -static" -tags netgo -o /go/bin/secure_application .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=stage1 /go/bin/secure_application .
COPY . .
EXPOSE 8080
cmd ["./secure_application"]
