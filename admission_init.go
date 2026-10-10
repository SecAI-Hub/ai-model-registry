package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Initialization is an explicit new-only operator action, never daemon startup.
// Every failure retains its new directory/files. Existing targets are refused;
// neither ownership nor contents of an existing directory are changed.
func initializeAdmissionTarget(kind, path string) error {
	if kind != "registry" && kind != "outbox" {
		return errors.New("kind must be registry or outbox")
	}
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("new target must be a clean absolute path")
	}
	parent, name := filepath.Dir(path), filepath.Base(path)
	if !admissionNames.MatchString(name) {
		return errors.New("invalid new target basename")
	}
	if err := checkedAdmissionDirectory(parent); err != nil {
		return err
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || parentInfo.Mode().Perm()&0o007 != 0 || !checkpointTrustedOwner(parentInfo) {
		return errors.New("explicit private parent required")
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := root.Lstat(name); !os.IsNotExist(err) {
		return errors.New("initializer refuses every existing target")
	}
	mode := os.FileMode(0700)
	if kind == "outbox" {
		mode = 0750
	}
	if err := root.Mkdir(name, mode); err != nil {
		return err
	}
	created, err := root.Lstat(name)
	if err != nil {
		return err
	}
	child, err := root.OpenRoot(name)
	if err != nil {
		return err
	}
	defer child.Close()
	named, err := os.Lstat(path)
	if err != nil || !os.SameFile(created, named) || !admissionOwnedBy(named, os.Geteuid(), os.Getegid()) {
		return errors.New("new target identity changed")
	}
	if kind == "registry" {
		data, err := json.MarshalIndent(Manifest{Version: 1, Models: []Artifact{}}, "", "  ")
		if err != nil {
			return err
		}
		file, err := child.OpenFile("manifest.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			return err
		}
		n, writeErr := manifestPersistence.write(file, data)
		if writeErr == nil && n != len(data) {
			writeErr = io.ErrShortWrite
		}
		if writeErr == nil {
			writeErr = manifestPersistence.syncFile(file)
		}
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if err := manifestPersistence.syncDirectory(path); err != nil {
		return err
	}
	currentParent, err := os.Lstat(parent)
	if err != nil || !os.SameFile(parentInfo, currentParent) {
		return errors.New("initializer parent identity changed")
	}
	if err := manifestPersistence.syncDirectory(parent); err != nil {
		return err
	}
	final, err := root.Lstat(name)
	if err != nil || !os.SameFile(created, final) {
		return errors.New("new target changed during initialization")
	}
	named, err = os.Lstat(path)
	if err != nil || !os.SameFile(created, named) {
		return errors.New("new target path changed during initialization")
	}
	return nil
}

func runAdmissionCommand(args []string) (int, bool) {
	if len(args) == 0 || args[0] != "admission-init" {
		return 0, false
	}
	parser := flag.NewFlagSet("admission-init", flag.ContinueOnError)
	kind := parser.String("kind", "", "registry or outbox")
	path := parser.String("path", "", "nonexistent absolute child of a prepared private parent")
	if err := parser.Parse(args[1:]); err != nil || parser.NArg() != 0 {
		return 2, true
	}
	if err := initializeAdmissionTarget(*kind, *path); err != nil {
		fmt.Fprintln(os.Stderr, "admission initialization refused/failed; retain target:", err)
		return 1, true
	}
	fmt.Println("new admission target initialized:", *kind, *path)
	return 0, true
}

var admissionStoreLock *os.File

func lockAdmissionStore() error {
	if err := checkedAdmissionDirectory(registryDir); err != nil {
		return err
	}
	file, err := os.OpenFile(registryDir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return errors.New("another helper-v2 writer owns this registry directory")
	}
	admissionStoreLock = file
	return nil
}

func admissionStoreCurrent() bool {
	if admissionStoreLock == nil {
		return false
	}
	opened, err := admissionStoreLock.Stat()
	if err != nil {
		return false
	}
	current, err := os.Lstat(registryDir)
	return err == nil && os.SameFile(opened, current) && current.IsDir() && current.Mode().Perm()&0o022 == 0
}
