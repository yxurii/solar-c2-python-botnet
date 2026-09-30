@echo off
setlocal

set GOOS=linux
set CGO_ENABLED=0

echo Building mipsle...
set GOARCH=mipsle
go build -ldflags "-s -w" -o bot-mipsle .

echo Building mips...
set GOARCH=mips
go build -ldflags "-s -w" -o bot-mips .

echo Building arm...
set GOARCH=arm
go build -ldflags "-s -w" -o bot-arm .

echo Building arm64...
set GOARCH=arm64
go build -ldflags "-s -w" -o bot-arm64 .

echo Building 386...
set GOARCH=386
go build -ldflags "-s -w" -o bot-386 .

echo Building amd64...
set GOARCH=amd64
go build -ldflags "-s -w" -o bot-amd64 .

echo Done.
dir /b /s bot-*.*.exe bot-mips**.exe bot-arm* 2>nul
dir bot-*.* /b
