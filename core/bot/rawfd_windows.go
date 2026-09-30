//go:build windows

package main

import "syscall"

func rawFD(fd uintptr) syscall.Handle { return syscall.Handle(fd) }
