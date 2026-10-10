//go:build linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAdmissionClockActualAndBoundaries(t *testing.T) {
	t.Setenv("ADMISSION_BOOT_ID_PATH", "")
	before, err := readAdmissionClock()
	if err != nil {
		t.Fatal(err)
	}
	after, err := readAdmissionClock()
	if err != nil {
		t.Fatal(err)
	}
	if before.BootID != after.BootID || before.NS <= 0 || after.NS < before.NS {
		t.Fatal("invalid real CLOCK_BOOTTIME evidence")
	}
	receipt := AdmissionReceipt{BootID: before.BootID, ExpiresBootNS: after.NS + 1}
	if validAdmissionLifetime(receipt, after) != nil {
		t.Fatal("unexpired preparation refused")
	}
	after.NS = receipt.ExpiresBootNS
	if validAdmissionLifetime(receipt, after) == nil {
		t.Fatal("expiry boundary refreshed authority")
	}
	after.NS = 0
	after.BootID = "00000000-0000-0000-0000-000000000000"
	if validAdmissionLifetime(receipt, after) == nil {
		t.Fatal("reboot refreshed authority")
	}
}

func TestAdmissionControlFilesRejectSpecialLinksAndWritableFiles(t *testing.T) {
	directory := t.TempDir()
	regular := filepath.Join(directory, "regular")
	if err := os.WriteFile(regular, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedAdmissionFile(regular, 64); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "symlink")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedAdmissionFile(link, 64); err == nil {
		t.Fatal("symlink control input accepted")
	}
	fifo := filepath.Join(directory, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedAdmissionFile(fifo, 64); err == nil {
		t.Fatal("special control input accepted")
	}
	if err := os.Link(regular, filepath.Join(directory, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedAdmissionFile(regular, 64); err == nil {
		t.Fatal("multiply linked control input accepted")
	}
	writable := filepath.Join(directory, "writable")
	if err := os.WriteFile(writable, []byte("synthetic"), 0660); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0660); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedAdmissionFile(writable, 64); err == nil {
		t.Fatal("group-writable control input accepted")
	}
}
