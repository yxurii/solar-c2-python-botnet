//go:build linux || darwin || freebsd || openbsd || netbsd

package main

func rawFD(fd uintptr) int { return int(fd) }
