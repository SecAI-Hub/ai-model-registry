//go:build linux

package main

import (
	"errors"
	"math"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

type admissionTime struct {
	BootID string
	NS     int64
}

// Read only Linux CLOCK_BOOTTIME: wall time and Go's suspend-excluding
// monotonic clock cannot establish this lease's validity.
func readAdmissionClock() (admissionTime, error) {
	var value syscall.Timespec
	// #nosec G103 -- fixed kernel clock request; pointer is to this live Timespec.
	_, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 7, uintptr(unsafe.Pointer(&value)), 0)
	if errno != 0 {
		return admissionTime{}, errno
	}
	if value.Sec < 0 || value.Sec > (math.MaxInt64-int64(admissionLifetime))/1_000_000_000 || value.Nsec < 0 || value.Nsec >= 1_000_000_000 {
		return admissionTime{}, errors.New("invalid suspend-inclusive clock")
	}
	path := os.Getenv("ADMISSION_BOOT_ID_PATH")
	if path == "" {
		path = "/proc/sys/kernel/random/boot_id"
	}
	data, err := trustedAdmissionFile(path, 64)
	if err != nil {
		return admissionTime{}, errors.New("trusted per-boot identity unavailable")
	}
	boot := strings.TrimSpace(string(data))
	if !admissionBoot.MatchString(boot) {
		return admissionTime{}, errors.New("invalid per-boot identity")
	}
	return admissionTime{BootID: boot, NS: int64(value.Sec)*1_000_000_000 + int64(value.Nsec)}, nil
}

var admissionNow = readAdmissionClock

func validAdmissionLifetime(receipt AdmissionReceipt, now admissionTime) error {
	if !admissionBoot.MatchString(now.BootID) || now.NS < 0 || receipt.BootID != now.BootID || now.NS >= receipt.ExpiresBootNS {
		return errors.New("preparation expired or belongs to a different boot")
	}
	return nil
}
