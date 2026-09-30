@echo off
setlocal
set CGO_ENABLED=0
set GOOS=linux

for %%a in (mipsle mips arm arm64 386 amd64) do (
    echo Building %%a...
    set GOARCH=%%a
    go build -ldflags "-s -w" -o bot-%%a .
)
echo Done.
