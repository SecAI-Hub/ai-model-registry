package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
)

type admissionCopyIntent struct {
	Version              int                 `json:"version"`
	AdmissionID          string              `json:"admission_id"`
	RequestSHA256        string              `json:"request_sha256"`
	PrepareReceiptSHA256 string              `json:"prepare_receipt_sha256"`
	ObjectPath           string              `json:"object_path"`
	Evidence             []AdmissionEvidence `json:"evidence"`
}

func admissionSameFile(before, after os.FileInfo) bool {
	return os.SameFile(before, after) && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime()) &&
		before.Mode() == after.Mode() && fileLinkCount(after) == 1
}

func admissionCheckSourceDirs(root *os.Root, id, child string, config AdmissionConfig) error {
	for _, name := range []string{id, filepath.Join(id, child)} {
		info, err := root.Lstat(name)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o027 != 0 || !admissionOwnedBy(info, config.ProducerUID, config.OutboxGID) {
			return errors.New("private producer directory identity/mode invalid")
		}
	}
	return nil
}

func admissionOpenSource(root *os.Root, rel string, size int64, config AdmissionConfig) (*os.File, os.FileInfo, error) {
	before, err := root.Lstat(rel)
	if err != nil {
		return nil, nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0o222 != 0 || fileLinkCount(before) != 1 || before.Size() != size || !admissionOwnedBy(before, config.ProducerUID, config.OutboxGID) {
		return nil, nil, errors.New("producer file identity/mode/size invalid")
	}
	file, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	opened, err := file.Stat()
	if err != nil || !admissionSameFile(before, opened) {
		file.Close()
		return nil, nil, errors.New("producer file changed while opening")
	}
	return file, opened, nil
}

func admissionStream(source *os.File, before os.FileInfo, target io.Writer, expected string, check func() error) error {
	hash := sha256.New()
	writer := io.MultiWriter(target, hash)
	buffer := make([]byte, 64<<10)
	remaining := before.Size()
	for remaining > 0 {
		if err := check(); err != nil {
			return err
		}
		amount := int64(len(buffer))
		if amount > remaining {
			amount = remaining
		}
		n, err := io.ReadFull(source, buffer[:int(amount)])
		if err != nil {
			return err
		}
		written, err := writer.Write(buffer[:n])
		if err != nil {
			return err
		}
		if written != n {
			return io.ErrShortWrite
		}
		remaining -= int64(n)
	}
	var extra [1]byte
	if n, err := source.Read(extra[:]); n != 0 || err != io.EOF {
		return errors.New("source grew while copying")
	}
	after, err := source.Stat()
	if err != nil || !admissionSameFile(before, after) {
		return errors.New("source changed while copying")
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected {
		return errors.New("copied bytes do not match admitted digest")
	}
	return check()
}

func admissionVerifyRetained(root *os.Root, rel, digest string, size int64, check func() error) error {
	before, err := root.Lstat(rel)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o222 != 0 || fileLinkCount(before) != 1 || before.Size() != size || !checkpointTrustedOwner(before) {
		return errors.New("retained immutable file unavailable")
	}
	file, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !admissionSameFile(before, opened) {
		return errors.New("retained file changed")
	}
	if err := admissionStream(file, opened, io.Discard, digest, check); err != nil {
		return err
	}
	named, err := root.Lstat(rel)
	if err != nil || !admissionSameFile(opened, named) {
		return errors.New("retained path changed")
	}
	return nil
}

func admissionCreateFile(root *os.Root, name string, raw []byte, check func() error) error {
	if err := check(); err != nil {
		return err
	}
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0400)
	if err != nil {
		return err
	}
	// Failed/uncertain new data is retained, not deleted or overwritten.
	n, err := file.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return check()
}

func admissionReadRetained(root *os.Root, name string, limit int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit || info.Mode().Perm()&0o222 != 0 || fileLinkCount(info) != 1 || !checkpointTrustedOwner(info) {
		return nil, errors.New("retained control input invalid")
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !admissionSameFile(info, opened) {
		return nil, errors.New("retained control input changed")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) != info.Size() {
		return nil, errors.New("retained control input read failed")
	}
	after, err := file.Stat()
	named, nameErr := root.Lstat(name)
	if err != nil || nameErr != nil || !admissionSameFile(info, after) || !admissionSameFile(after, named) {
		return nil, errors.New("retained control identity changed")
	}
	return raw, nil
}

func admissionOwnedDir(root *os.Root, name string) error {
	path := ""
	for _, part := range stringsSplitPath(name) {
		path = filepath.Join(path, part)
		createErr := root.Mkdir(path, 0700)
		if createErr != nil && !os.IsExist(createErr) {
			return createErr
		}
		info, err := root.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !checkpointTrustedOwner(info) {
			return errors.New("registry private directory unsafe")
		}
		if createErr == nil {
			if err := manifestPersistence.syncDirectory(filepath.Join(registryDir, path)); err != nil {
				return err
			}
			if err := manifestPersistence.syncDirectory(filepath.Join(registryDir, filepath.Dir(path))); err != nil {
				return err
			}
		}
	}
	return nil
}

func stringsSplitPath(name string) []string {
	var reversed []string
	for name != "." && name != "" {
		reversed = append(reversed, filepath.Base(name))
		name = filepath.Dir(name)
	}
	result := make([]string, len(reversed))
	for index, value := range reversed {
		result[len(result)-1-index] = value
	}
	return result
}

func admissionCopyBundle(artifact Artifact, request AdmissionCommitRequest, requestSHA string, check func() error) (AdmissionReport, string, error) {
	var report AdmissionReport
	config := *configuredAdmission
	record := artifact.Admission
	id := request.AdmissionID
	object, err := contentAddressedObjectRel(artifact.SHA256, artifact.Format)
	if err != nil {
		return report, "", err
	}
	intent := admissionCopyIntent{Version: 2, AdmissionID: id, RequestSHA256: requestSHA, PrepareReceiptSHA256: record.PrepareReceipt.SHA256, ObjectPath: object, Evidence: request.Evidence}
	intentRaw, err := json.Marshal(intent)
	if err != nil {
		return report, "", err
	}
	total := int64(len(intentRaw) + 64)
	for _, item := range request.Evidence {
		total += item.SizeBytes
	}
	if total > record.Prepare.EvidenceBudgetBytes {
		return report, "", errors.New("evidence and intent exceed prepared byte budget")
	}
	root, err := os.OpenRoot(registryDir)
	if err != nil {
		return report, "", err
	}
	defer root.Close()
	if err := admissionOwnedDir(root, "admission-data"); err != nil {
		return report, "", err
	}
	directory := filepath.Join("admission-data", id)
	fresh := false
	if err := root.Mkdir(directory, 0700); err == nil {
		fresh = true
	} else if !os.IsExist(err) {
		return report, "", err
	}
	info, err := root.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !checkpointTrustedOwner(info) {
		return report, "", errors.New("admission data directory unsafe")
	}
	held, err := root.OpenRoot(directory)
	if err != nil {
		return report, "", err
	}
	defer held.Close()
	if fresh {
		if err := admissionCreateFile(held, "intent.json", intentRaw, check); err != nil {
			return report, "", err
		}
		if err := manifestPersistence.syncDirectory(filepath.Join(registryDir, directory)); err != nil {
			return report, "", err
		}
		if err := manifestPersistence.syncDirectory(filepath.Join(registryDir, "admission-data")); err != nil {
			return report, "", err
		}
		if err := manifestPersistence.syncDirectory(registryDir); err != nil {
			return report, "", err
		}
	} else {
		raw, err := admissionReadRetained(held, "intent.json", admissionBodyLimit)
		if err != nil {
			return report, "", errors.New("existing admission data lacks a complete owned intent; retained for maintenance")
		}
		var previous admissionCopyIntent
		if decodeAdmissionJSON(raw, admissionBodyLimit, &previous) != nil || !reflect.DeepEqual(previous, intent) {
			return report, "", errors.New("existing retained intent differs; no adoption/overwrite")
		}
		ready, err := admissionReadRetained(held, "ready", 64)
		if err != nil || string(ready) != requestSHA {
			return report, "", errors.New("incomplete retained copy requires maintenance; no overwrite")
		}
	}
	source, err := os.OpenRoot(config.OutboxDir)
	if err != nil {
		return report, "", err
	}
	defer source.Close()
	if fresh {
		if err := admissionCheckSourceDirs(source, id, "input", config); err != nil {
			return report, "", err
		}
		if err := admissionCheckSourceDirs(source, id, "evidence", config); err != nil {
			return report, "", err
		}
		if err := admissionOwnedDir(root, filepath.Dir(object)); err != nil {
			return report, "", err
		}
		if _, err := root.Lstat(object); os.IsNotExist(err) {
			input, inputInfo, err := admissionOpenSource(source, filepath.Join(id, "input", artifact.Filename), artifact.SizeBytes, config)
			if err != nil {
				return report, "", err
			}
			target, err := root.OpenFile(object, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0400)
			if err != nil {
				input.Close()
				return report, "", err
			}
			copyErr := admissionStream(input, inputInfo, target, artifact.SHA256, check)
			if named, nameErr := source.Lstat(filepath.Join(id, "input", artifact.Filename)); copyErr == nil && (nameErr != nil || !admissionSameFile(inputInfo, named)) {
				copyErr = errors.New("producer artifact path changed during copy")
			}
			input.Close()
			if copyErr == nil {
				copyErr = target.Sync()
			}
			closeErr := target.Close()
			if copyErr != nil {
				return report, "", copyErr
			}
			if closeErr != nil {
				return report, "", closeErr
			}
			if err := manifestPersistence.syncDirectory(filepath.Join(registryDir, filepath.Dir(object))); err != nil {
				return report, "", err
			}
		} else if err != nil {
			return report, "", err
		}
		if err := admissionVerifyRetained(root, object, artifact.SHA256, artifact.SizeBytes, check); err != nil {
			return report, "", err
		}
		for _, item := range request.Evidence {
			input, inputInfo, err := admissionOpenSource(source, filepath.Join(id, "evidence", item.Filename), item.SizeBytes, config)
			if err != nil {
				return report, "", err
			}
			target, err := held.OpenFile(item.Filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0400)
			if err != nil {
				input.Close()
				return report, "", err
			}
			copyErr := admissionStream(input, inputInfo, target, item.SHA256, check)
			if named, nameErr := source.Lstat(filepath.Join(id, "evidence", item.Filename)); copyErr == nil && (nameErr != nil || !admissionSameFile(inputInfo, named)) {
				copyErr = errors.New("producer evidence path changed during copy")
			}
			input.Close()
			if copyErr == nil {
				copyErr = target.Sync()
			}
			closeErr := target.Close()
			if copyErr != nil {
				return report, "", copyErr
			}
			if closeErr != nil {
				return report, "", closeErr
			}
		}
		if err := manifestPersistence.syncDirectory(filepath.Join(registryDir, directory)); err != nil {
			return report, "", err
		}
		if err := admissionCreateFile(held, "ready", []byte(requestSHA), check); err != nil {
			return report, "", err
		}
		if err := manifestPersistence.syncDirectory(filepath.Join(registryDir, directory)); err != nil {
			return report, "", err
		}
	}
	if err := admissionVerifyRetained(root, object, artifact.SHA256, artifact.SizeBytes, check); err != nil {
		return report, "", err
	}
	guard := ""
	for _, item := range request.Evidence {
		if err := admissionVerifyRetained(held, item.Filename, item.SHA256, item.SizeBytes, check); err != nil {
			return report, "", err
		}
		if item.Role == "pipeline-report" {
			raw, err := admissionReadRetained(held, item.Filename, admissionEvidenceLimit)
			if err != nil {
				return report, "", err
			}
			if err := decodeAdmissionJSON(raw, admissionEvidenceLimit, &report); err != nil {
				return report, "", err
			}
		} else if item.Role == "gguf-integrity" {
			guard = filepath.Join(directory, item.Filename)
		}
	}
	if artifact.Format == "gguf" && guard == "" {
		return report, "", errors.New("GGUF integrity evidence required")
	}
	if artifact.Format != "gguf" && guard != "" {
		return report, "", errors.New("unexpected GGUF integrity evidence")
	}
	if err := validateAdmissionReport(report, record.Prepare, record.Context); err != nil {
		return report, "", fmt.Errorf("pipeline report rejected: %w", err)
	}
	return report, guard, check()
}
