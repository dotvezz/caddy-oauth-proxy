-include .env
export
export COOKIE_SECRET=$(shell openssl rand -hex 16)

install:
	go install github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.5
	go install github.com/go-delve/delve/cmd/dlv@v1.27.0

clean:
	rm caddy

build: install
	XCADDY_DEBUG=1 xcaddy build --with $(shell awk '/^module/ {print $$2}' go.mod)=$(PWD)

debug: build
	dlv --listen=:2345 --headless=true --api-version=2 --accept-multiclient exec ./caddy run

run: build
	./caddy run

test:
	go test -v ./...

env:
	echo $$OAUTH2_PROXY_CLIENT_SECRET
	echo $$COOKIE_SECRET
