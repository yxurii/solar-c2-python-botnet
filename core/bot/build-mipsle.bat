@echo off
set GOOS=linux
set CGO_ENABLED=0
set GOARCH=mipsle
go build -ldflags "-s -w" -o bot-mipsle .
