build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -o cisco-socks-server cmd/*
	chmod +x cisco-socks-server

build:
	go build -o cisco-socks-server cmd/*
	chmod +x cisco-socks-server