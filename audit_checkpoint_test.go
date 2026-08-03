package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func nonCanonicalCheckpointPath(path string) string {
	separator := string(os.PathSeparator)
	return filepath.Dir(path) + separator + "." + separator + filepath.Base(path)
}

func registryManifestFixture(t *testing.T, path string) ([]byte, string) {
	t.Helper()
	artifact := Artifact{
		Name:      "checkpoint-model",
		Format:    "gguf",
		Filename:  "checkpoint-model.gguf",
		SHA256:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SizeBytes: 42,
		State:     StateAcquired,
	}
	event := RegistryAuditEvent{
		Sequence:  1,
		Timestamp: time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
		Action:    "acquire",
		Name:      artifact.Name,
		ToState:   StateAcquired,
		SHA256:    artifact.SHA256,
		Artifact:  artifact,
		PrevHash:  "genesis",
	}
	event.Hash = hashRegistryEvent(event)
	candidate := Manifest{Version: 1, Models: []Artifact{artifact}, Events: []RegistryAuditEvent{event}}
	payload, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return payload, event.Hash
}

func TestRegistryCheckpointExportVerifyAndTamperDetection(t *testing.T) {
	dir := t.TempDir()
	privateKey := filepath.Join(dir, "checkpoint.key")
	publicKey := filepath.Join(dir, "checkpoint.pub")
	if err := generateRegistryCheckpointKeypair(privateKey, publicKey); err != nil {
		t.Fatal(err)
	}
	manifestSource := filepath.Join(dir, "manifest.json")
	_, chainHead := registryManifestFixture(t, manifestSource)
	checkpointPath := filepath.Join(dir, "checkpoint.json")
	for _, testCase := range []struct {
		name      string
		path      string
		publicKey bool
	}{
		{name: "relative source", path: filepath.Base(manifestSource)},
		{name: "noncanonical source", path: nonCanonicalCheckpointPath(manifestSource)},
		{name: "relative private key", path: filepath.Base(privateKey)},
		{name: "noncanonical private key", path: nonCanonicalCheckpointPath(privateKey)},
		{name: "relative public key", path: filepath.Base(publicKey), publicKey: true},
		{name: "noncanonical public key", path: nonCanonicalCheckpointPath(publicKey), publicKey: true},
	} {
		var err error
		if testCase.publicKey {
			_, err = readCheckpointPublicKeyFile(testCase.path, 4096)
		} else {
			_, err = readCheckpointOwnerOnlyFile(testCase.path, maxManifestBytes)
		}
		if err == nil {
			t.Fatalf("%s must be rejected", testCase.name)
		}
	}

	checkpoint, err := exportRegistryCheckpoint(manifestSource, privateKey, checkpointPath)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(checkpointPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("checkpoint must be owner-only: info=%v err=%v", info, err)
	}
	if checkpoint.EntryCount != 1 || checkpoint.ChainHead != chainHead {
		t.Fatalf("unexpected checkpoint summary: %#v", checkpoint)
	}
	if _, _, err := loadAndVerifyRegistryCheckpoint(checkpointPath, publicKey, chainHead); err != nil {
		t.Fatalf("verify checkpoint against retained anchor: %v", err)
	}
	otherPrivateKey := filepath.Join(dir, "other-checkpoint.key")
	otherPublicKey := filepath.Join(dir, "other-checkpoint.pub")
	if err := generateRegistryCheckpointKeypair(otherPrivateKey, otherPublicKey); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadAndVerifyRegistryCheckpoint(checkpointPath, otherPublicKey, ""); err == nil {
		t.Fatal("checkpoint must not trust its embedded public key")
	}
	if err := os.Chmod(publicKey, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadAndVerifyRegistryCheckpoint(checkpointPath, publicKey, ""); err == nil {
		t.Fatal("group/world-writable trusted public key must be rejected")
	}
	if err := os.Chmod(publicKey, 0o644); err != nil {
		t.Fatal(err)
	}
	publicLink := filepath.Join(dir, "checkpoint-link.pub")
	if err := os.Symlink(publicKey, publicLink); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadAndVerifyRegistryCheckpoint(checkpointPath, publicLink, ""); err == nil {
		t.Fatal("symlinked trusted public key must be rejected")
	}
	unsafeTrustDir := filepath.Join(dir, "unsafe-trust")
	if err := os.Mkdir(unsafeTrustDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeTrustDir, 0o777); err != nil {
		t.Fatal(err)
	}
	publicBytes, err := os.ReadFile(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	unsafePublicKey := filepath.Join(unsafeTrustDir, "checkpoint.pub")
	if err := os.WriteFile(unsafePublicKey, publicBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadAndVerifyRegistryCheckpoint(checkpointPath, unsafePublicKey, ""); err == nil {
		t.Fatal("trusted public key in a group/world-writable directory must be rejected")
	}
	if err := os.Chmod(privateKey, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := exportRegistryCheckpoint(manifestSource, privateKey, filepath.Join(dir, "unsafe-key-checkpoint.json")); err == nil {
		t.Fatal("non-owner-only checkpoint private key must be rejected")
	}
	if err := os.Chmod(privateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	unsafeDir := filepath.Join(dir, "unsafe-output")
	if err := os.Mkdir(unsafeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := exportRegistryCheckpoint(manifestSource, privateKey, filepath.Join(unsafeDir, "checkpoint.json")); err == nil {
		t.Fatal("checkpoint export into a group/world-writable directory must fail")
	}
	if _, err := exportRegistryCheckpoint(manifestSource, privateKey, checkpointPath); err == nil {
		t.Fatal("checkpoint export must not overwrite an existing file")
	}

	encoded, err := os.ReadFile(checkpointPath)
	if err != nil {
		t.Fatal(err)
	}
	var tampered AuditCheckpoint
	if err := json.Unmarshal(encoded, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Payload[0] ^= 1
	tamperedBytes, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPath := filepath.Join(dir, "tampered.json")
	if err := os.WriteFile(tamperedPath, tamperedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadAndVerifyRegistryCheckpoint(tamperedPath, publicKey, ""); err == nil {
		t.Fatal("tampered checkpoint payload must fail verification")
	}
}

func TestRegistryCheckpointRejectsPayloadAboveManifestLimit(t *testing.T) {
	checkpoint := AuditCheckpoint{Payload: make([]byte, maxManifestBytes+1)}
	if err := validateRegistryCheckpointMetadata(checkpoint); err == nil {
		t.Fatal("decoded payload above the runtime manifest limit must be rejected")
	}
}

func TestRegistryCheckpointPublicationCleansPartialTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "checkpoint.json")
	content := []byte("complete checkpoint")
	injectedFailure := errors.New("injected write failure")
	err := writeRegistryExclusiveFileWithWriter(output, content, 0o600, func(file *os.File, data []byte) error {
		if _, err := file.Write(data[:1]); err != nil {
			return err
		}
		return injectedFailure
	})
	if err == nil {
		t.Fatal("injected partial write must fail")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("failed publication left a final output: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed publication left temporary entries: %v", entries)
	}
	if err := writeRegistryExclusiveFile(output, content, 0o600); err != nil {
		t.Fatalf("retry after cleanup failed: %v", err)
	}
	actual, err := os.ReadFile(output)
	if err != nil || string(actual) != string(content) {
		t.Fatalf("published bytes differ: %q err=%v", actual, err)
	}
	if err := writeRegistryExclusiveFile("relative-checkpoint.json", content, 0o600); err == nil {
		t.Fatal("relative checkpoint output must be rejected")
	}
	if err := writeRegistryExclusiveFile(nonCanonicalCheckpointPath(filepath.Join(dir, "other.json")), content, 0o600); err == nil {
		t.Fatal("noncanonical checkpoint output must be rejected")
	}
}

func TestRegistryUnknownSubcommandFailsClosed(t *testing.T) {
	if exitCode, handled := runRegistryCheckpointCommand(nil); handled || exitCode != 0 {
		t.Fatalf("argument-free server startup must remain unhandled: handled=%v code=%d", handled, exitCode)
	}
	exitCode, handled := runRegistryCheckpointCommand([]string{"definitely-not-a-registry-command"})
	if !handled || exitCode == 0 {
		t.Fatalf("unknown command must be handled as an error: handled=%v code=%d", handled, exitCode)
	}
}

func TestRegistryCheckpointRecoveryRequiresIndependentAnchorAndNewPath(t *testing.T) {
	dir := t.TempDir()
	privateKey := filepath.Join(dir, "checkpoint.key")
	publicKey := filepath.Join(dir, "checkpoint.pub")
	if err := generateRegistryCheckpointKeypair(privateKey, publicKey); err != nil {
		t.Fatal(err)
	}
	manifestSource := filepath.Join(dir, "manifest.json")
	payload, chainHead := registryManifestFixture(t, manifestSource)
	checkpointPath := filepath.Join(dir, "checkpoint.json")
	if _, err := exportRegistryCheckpoint(manifestSource, privateKey, checkpointPath); err != nil {
		t.Fatal(err)
	}

	recovered := filepath.Join(dir, "recovered-manifest.json")
	if err := recoverRegistryCheckpoint(checkpointPath, publicKey, recovered, ""); err == nil {
		t.Fatal("recovery without an independent anchor must fail")
	}
	if err := recoverRegistryCheckpoint(checkpointPath, publicKey, recovered, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); err == nil {
		t.Fatal("recovery with an absent anchor must fail")
	}
	if err := recoverRegistryCheckpoint(checkpointPath, publicKey, recovered, chainHead); err != nil {
		t.Fatal(err)
	}
	recoveredBytes, err := os.ReadFile(recovered)
	if err != nil {
		t.Fatal(err)
	}
	if string(recoveredBytes) != string(payload) {
		t.Fatal("recovered manifest differs from signed checkpoint payload")
	}
	if info, err := os.Stat(recovered); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("recovered manifest must be owner-only: info=%v err=%v", info, err)
	}
	if err := recoverRegistryCheckpoint(checkpointPath, publicKey, recovered, chainHead); err == nil {
		t.Fatal("recovery must not overwrite an existing destination")
	}
}
