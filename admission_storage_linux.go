//go:build linux

package main

import (
	"errors"
	"math"
	"os"
	"syscall"
)

func availableAdmissionBytes(path string) (int64, error) {
	var value syscall.Statfs_t
	if err := syscall.Statfs(path, &value); err != nil {
		return 0, err
	}
	if value.Bsize <= 0 {
		return 0, errors.New("invalid filesystem block size")
	}
	if value.Bavail > uint64(math.MaxInt64)/uint64(value.Bsize) {
		return math.MaxInt64, nil
	}
	return int64(value.Bavail) * int64(value.Bsize), nil
}

func readAdmissionFreeSpace(config AdmissionConfig) (admissionFreeSpace, error) {
	registry, err := os.Lstat(registryDir)
	if err != nil {
		return admissionFreeSpace{}, err
	}
	outbox, err := os.Lstat(config.OutboxDir)
	if err != nil {
		return admissionFreeSpace{}, err
	}
	if !outbox.IsDir() || outbox.Mode().Perm()&0o027 != 0 || !admissionOwnedBy(outbox, config.ProducerUID, config.OutboxGID) {
		return admissionFreeSpace{}, errors.New("outbox identity/mode changed")
	}
	r, rok := registry.Sys().(*syscall.Stat_t)
	o, ook := outbox.Sys().(*syscall.Stat_t)
	if !rok || !ook {
		return admissionFreeSpace{}, errors.New("filesystem identities unavailable")
	}
	registryFree, err := availableAdmissionBytes(registryDir)
	if err != nil {
		return admissionFreeSpace{}, err
	}
	outboxFree, err := availableAdmissionBytes(config.OutboxDir)
	if err != nil {
		return admissionFreeSpace{}, err
	}
	return admissionFreeSpace{Registry: registryFree, Outbox: outboxFree, Shared: r.Dev == o.Dev}, nil
}

var admissionSpace = readAdmissionFreeSpace
