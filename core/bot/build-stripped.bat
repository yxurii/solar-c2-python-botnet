@echo off
set GOOS=linux
set GOARCH=mipsle
set CGO_ENABLED=0
go build -ldflags "-s -w" -o bot-mipsle-stripped .
