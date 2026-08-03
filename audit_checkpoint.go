package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	registryCheckpointVersion = 1
	registryCheckpointService = "ai-model-registry"
	registryCheckpointPayload = "manifest.json"
	maxRegistryCheckpointSize = 24 << 20
)

// AuditCheckpoint is a portable signed envelope around a complete registry
// manifest and its replayable audit history. encoding/json base64-encodes the
// payload. Verification recomputes the digest, event replay, and chain summary.
type AuditCheckpoint struct {
	Version       int    `json:"version"`
	Service       string `json:"service"`
	CreatedAt     string `json:"created_at"`
	PayloadName   string `json:"payload_name"`
	Payload       []byte `json:"payload,omitempty"`
	PayloadSize   int64  `json:"payload_size"`
	PayloadSHA256 string `json:"payload_sha256"`
	EntryCount    int    `json:"entry_count"`
	ChainHead     string `json:"chain_head,omitempty"`
	PublicKey     string `json:"public_key"`
	Signature     string `json:"signature,omitempty"`
}

type registryCheckpointSummary struct {
	EntryCount int
	ChainHead  string
	Hashes     map[string]struct{}
}

func summarizeRegistryManifestBytes(data []byte) (registryCheckpointSummary, error) {
	var candidate Manifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&candidate); err != nil {
		return registryCheckpointSummary{}, fmt.Errorf("decode manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return registryCheckpointSummary{}, fmt.Errorf("manifest must contain exactly one JSON value")
	}
	if err := validateManifest(candidate); err != nil {
		return registryCheckpointSummary{}, err
	}
	if len(candidate.Models) != 0 && len(candidate.Events) == 0 {
		return registryCheckpointSummary{}, fmt.Errorf("runtime manifest lacks replayable audit history")
	}
	summary := registryCheckpointSummary{
		EntryCount: len(candidate.Events),
		Hashes:     make(map[string]struct{}, len(candidate.Events)),
	}
	for _, event := range candidate.Events {
		summary.Hashes[event.Hash] = struct{}{}
		summary.ChainHead = event.Hash
	}
	return summary, nil
}

func registryCheckpointSignablePayload(checkpoint AuditCheckpoint) ([]byte, error) {
	checkpoint.Payload = nil
	checkpoint.Signature = ""
	return json.Marshal(checkpoint)
}

func exportRegistryCheckpoint(sourcePath, keyPath, outputPath string) (AuditCheckpoint, error) {
	data, err := readCheckpointOwnerOnlyFile(sourcePath, maxManifestBytes)
	if err != nil {
		return AuditCheckpoint{}, fmt.Errorf("read registry manifest: %w", err)
	}
	summary, err := summarizeRegistryManifestBytes(data)
	if err != nil {
		return AuditCheckpoint{}, err
	}
	keyData, err := readCheckpointOwnerOnlyFile(keyPath, 4096)
	if err != nil {
		return AuditCheckpoint{}, fmt.Errorf("read checkpoint signing key: %w", err)
	}
	privateBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyData)))
	if err != nil || len(privateBytes) != ed25519.PrivateKeySize {
		return AuditCheckpoint{}, fmt.Errorf("invalid Ed25519 checkpoint signing key")
	}
	privateKey := ed25519.PrivateKey(privateBytes)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(data)
	checkpoint := AuditCheckpoint{
		Version:       registryCheckpointVersion,
		Service:       registryCheckpointService,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		PayloadName:   registryCheckpointPayload,
		Payload:       data,
		PayloadSize:   int64(len(data)),
		PayloadSHA256: hex.EncodeToString(digest[:]),
		EntryCount:    summary.EntryCount,
		ChainHead:     summary.ChainHead,
		PublicKey:     base64.StdEncoding.EncodeToString(publicKey),
	}
	signable, err := registryCheckpointSignablePayload(checkpoint)
	if err != nil {
		return AuditCheckpoint{}, err
	}
	checkpoint.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, signable))
	encoded, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		return AuditCheckpoint{}, err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxRegistryCheckpointSize {
		return AuditCheckpoint{}, fmt.Errorf("checkpoint exceeds %d-byte limit", maxRegistryCheckpointSize)
	}
	if err := writeRegistryExclusiveFile(outputPath, encoded, 0o600); err != nil {
		return AuditCheckpoint{}, fmt.Errorf("write checkpoint: %w", err)
	}
	return checkpoint, nil
}

func loadAndVerifyRegistryCheckpoint(checkpointPath, publicKeyPath, requiredHead string) (AuditCheckpoint, registryCheckpointSummary, error) {
	data, err := readRegularBounded(checkpointPath, maxRegistryCheckpointSize)
	if err != nil {
		return AuditCheckpoint{}, registryCheckpointSummary{}, fmt.Errorf("read checkpoint: %w", err)
	}
	var checkpoint AuditCheckpoint
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&checkpoint); err != nil {
		return AuditCheckpoint{}, registryCheckpointSummary{}, fmt.Errorf("decode checkpoint: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return AuditCheckpoint{}, registryCheckpointSummary{}, fmt.Errorf("checkpoint must contain exactly one JSON value")
	}
	if err := validateRegistryCheckpointMetadata(checkpoint); err != nil {
		return AuditCheckpoint{}, registryCheckpointSummary{}, err
	}
	digest := sha256.Sum256(checkpoint.Payload)
	if checkpoint.PayloadSHA256 != hex.EncodeToString(digest[:]) {
		return AuditCheckpoint{}, registryCheckpointSummary{}, fmt.Errorf("checkpoint payload digest mismatch")
	}
	summary, err := summarizeRegistryManifestBytes(checkpoint.Payload)
	if err != nil {
		return AuditCheckpoint{}, registryCheckpointSummary{}, err
	}
	if checkpoint.EntryCount != summary.EntryCount || checkpoint.ChainHead != summary.ChainHead {
		return AuditCheckpoint{}, registryCheckpointSummary{}, fmt.Errorf("checkpoint chain summary mismatch")
	}
	if requiredHead != "" {
		if !sha256Pattern.MatchString(requiredHead) {
			return AuditCheckpoint{}, registryCheckpointSummary{}, fmt.Errorf("required head must be a lowercase SHA-256 digest")
		}
		if _, ok := summary.Hashes[requiredHead]; !ok {
			return AuditCheckpoint{}, registryCheckpointSummary{}, fmt.Errorf("checkpoint does not contain required anchored head")
		}
	}
	publicData, err := readCheckpointPublicKeyFile(publicKeyPath, 4096)
	if err != nil {
		return AuditCheckpoint{}, registryCheckpointSummary{}, fmt.Errorf("read trusted public key: %w", err)
	}
	publicBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(publicData)))
	if err != nil || len(publicBytes) != ed25519.PublicKeySize {
		return AuditCheckpoint{}, registryCheckpointSummary{}, fmt.Errorf("invalid trusted Ed25519 public key")
	}
	if checkpoint.PublicKey != base64.StdEncoding.EncodeToString(publicBytes) {
		return AuditCheckpoint{}, registryCheckpointSummary{}, fmt.Errorf("checkpoint public key does not match trusted key")
	}
	signature, err := base64.StdEncoding.DecodeString(checkpoint.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return AuditCheckpoint{}, registryCheckpointSummary{}, fmt.Errorf("invalid checkpoint signature")
	}
	signable, err := registryCheckpointSignablePayload(checkpoint)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicBytes), signable, signature) {
		return AuditCheckpoint{}, registryCheckpointSummary{}, fmt.Errorf("checkpoint signature verification failed")
	}
	return checkpoint, summary, nil
}

func validateRegistryCheckpointMetadata(checkpoint AuditCheckpoint) error {
	if int64(len(checkpoint.Payload)) > maxManifestBytes {
		return fmt.Errorf("checkpoint payload exceeds %d-byte registry manifest limit", maxManifestBytes)
	}
	if checkpoint.Version != registryCheckpointVersion || checkpoint.Service != registryCheckpointService ||
		checkpoint.PayloadName != registryCheckpointPayload || checkpoint.PayloadSize != int64(len(checkpoint.Payload)) ||
		!sha256Pattern.MatchString(checkpoint.PayloadSHA256) || checkpoint.EntryCount < 0 {
		return fmt.Errorf("invalid checkpoint metadata")
	}
	if _, err := time.Parse(time.RFC3339Nano, checkpoint.CreatedAt); err != nil {
		return fmt.Errorf("invalid checkpoint timestamp")
	}
	return nil
}

func recoverRegistryCheckpoint(checkpointPath, publicKeyPath, outputPath, requiredHead string) error {
	if requiredHead == "" {
		return fmt.Errorf("recovery requires an independently retained chain head")
	}
	checkpoint, _, err := loadAndVerifyRegistryCheckpoint(checkpointPath, publicKeyPath, requiredHead)
	if err != nil {
		return err
	}
	if err := writeRegistryExclusiveFile(outputPath, checkpoint.Payload, 0o600); err != nil {
		return fmt.Errorf("write recovered manifest: %w", err)
	}
	return nil
}

func readCheckpointOwnerOnlyFile(path string, limit int64) ([]byte, error) {
	return readCheckpointTrustedFile(path, limit, 0o077)
}

func readCheckpointPublicKeyFile(path string, limit int64) ([]byte, error) {
	return readCheckpointTrustedFile(path, limit, 0o022)
}

func readCheckpointTrustedFile(path string, limit int64, forbiddenMode os.FileMode) ([]byte, error) {
	if path == "" || limit < 0 {
		return nil, fmt.Errorf("checkpoint key/source path or limit is invalid")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("checkpoint key/source path must be canonical and absolute")
	}
	absPath := path
	dir := filepath.Dir(absPath)
	dirInfo, err := os.Lstat(dir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 ||
		dirInfo.Mode().Perm()&0o022 != 0 || !checkpointTrustedOwner(dirInfo) {
		return nil, fmt.Errorf("checkpoint key/source directory ownership or permissions are unsafe")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	openedDir, err := root.Stat(".")
	if err != nil || !os.SameFile(dirInfo, openedDir) {
		return nil, fmt.Errorf("checkpoint key/source directory changed while opening")
	}
	name := filepath.Base(absPath)
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Mode().Perm()&forbiddenMode != 0 || !checkpointTrustedOwner(before) ||
		before.Size() < 0 || before.Size() > limit {
		return nil, fmt.Errorf("checkpoint key/source file ownership or permissions are unsafe")
	}
	// #nosec G304,G703 -- name is a basename opened relative to an identity-checked root; O_NOFOLLOW and opened-file identity checks prevent substitution.
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("checkpoint key/source file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("checkpoint key/source file exceeds its read limit")
	}
	afterRead, err := f.Stat()
	if err != nil || !os.SameFile(opened, afterRead) || afterRead.Size() != int64(len(data)) {
		return nil, fmt.Errorf("checkpoint key/source file changed while reading")
	}
	afterPath, err := root.Lstat(name)
	if err != nil || !os.SameFile(before, afterPath) || afterPath.Mode().Perm()&forbiddenMode != 0 || !checkpointTrustedOwner(afterPath) {
		return nil, fmt.Errorf("checkpoint key/source file changed while validating trust")
	}
	currentDir, err := os.Lstat(dir)
	if err != nil || !os.SameFile(dirInfo, currentDir) {
		return nil, fmt.Errorf("checkpoint key/source directory changed while validating trust")
	}
	return data, nil
}

func checkpointTrustedOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	euid := int64(os.Geteuid())
	return stat.Uid == 0 || (euid >= 0 && int64(stat.Uid) == euid)
}

type registryCheckpointWriter func(*os.File, []byte) error

func writeRegistryExclusiveFile(path string, data []byte, mode os.FileMode) error {
	return writeRegistryExclusiveFileWithWriter(path, data, mode, func(file *os.File, content []byte) error {
		written, err := file.Write(content)
		if err == nil && written != len(content) {
			err = io.ErrShortWrite
		}
		return err
	})
}

func writeRegistryExclusiveFileWithWriter(path string, data []byte, mode os.FileMode, writeData registryCheckpointWriter) (returnErr error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("output path must be canonical and absolute")
	}
	if writeData == nil {
		return fmt.Errorf("output writer is unavailable")
	}
	absPath := path
	dir := filepath.Dir(absPath)
	dirInfo, err := os.Lstat(dir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 ||
		dirInfo.Mode().Perm()&0o022 != 0 || !checkpointTrustedOwner(dirInfo) {
		return fmt.Errorf("output directory must be trusted and not group/world-writable")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	openedDir, err := root.Stat(".")
	if err != nil || !os.SameFile(dirInfo, openedDir) {
		return fmt.Errorf("output directory changed while opening")
	}
	name := filepath.Base(absPath)
	tempName, f, err := createRegistryCheckpointTemp(root, mode)
	if err != nil {
		return err
	}
	tempPresent := true
	finalLinked := false
	published := false
	defer func() {
		if published {
			return
		}
		var cleanupErr error
		if finalLinked {
			if err := root.Remove(name); err != nil && !os.IsNotExist(err) {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove failed final output: %w", err))
			}
		}
		if tempPresent {
			if err := root.Remove(tempName); err != nil && !os.IsNotExist(err) {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove temporary output: %w", err))
			}
		}
		if err := syncRegistryCheckpointDirectory(root, dirInfo); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("sync output cleanup: %w", err))
		}
		returnErr = errors.Join(returnErr, cleanupErr)
	}()
	closed := false
	defer func() {
		if !closed {
			if closeErr := f.Close(); closeErr != nil {
				returnErr = errors.Join(returnErr, closeErr)
			}
		}
	}()
	if err := writeData(f, data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	closed = true
	if err := root.Link(tempName, name); err != nil {
		return fmt.Errorf("publish output without replacement: %w", err)
	}
	finalLinked = true
	if err := root.Remove(tempName); err != nil {
		return fmt.Errorf("remove published temporary link: %w", err)
	}
	tempPresent = false
	if err := syncRegistryCheckpointDirectory(root, dirInfo); err != nil {
		return err
	}
	currentDir, err := os.Lstat(dir)
	if err != nil || !os.SameFile(dirInfo, currentDir) {
		return fmt.Errorf("output directory moved during publication")
	}
	published = true
	return nil
}

func createRegistryCheckpointTemp(root *os.Root, mode os.FileMode) (string, *os.File, error) {
	for attempt := 0; attempt < 8; attempt++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", nil, err
		}
		name := ".secai-checkpoint-" + hex.EncodeToString(random[:]) + ".tmp"
		// #nosec G304,G703 -- the random basename is created beneath an identity-checked Root and O_EXCL prevents collision replacement.
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if os.IsExist(err) {
			continue
		}
		return name, file, err
	}
	return "", nil, fmt.Errorf("could not allocate unique checkpoint temporary file")
}

func syncRegistryCheckpointDirectory(root *os.Root, expected os.FileInfo) error {
	dirHandle, err := root.Open(".")
	if err != nil {
		return err
	}
	opened, statErr := dirHandle.Stat()
	if statErr != nil || !os.SameFile(expected, opened) {
		_ = dirHandle.Close()
		return fmt.Errorf("output directory changed during publication")
	}
	syncErr := dirHandle.Sync()
	closeErr := dirHandle.Close()
	return errors.Join(syncErr, closeErr)
}

func generateRegistryCheckpointKeypair(privatePath, publicPath string) error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := writeRegistryExclusiveFile(privatePath, []byte(base64.StdEncoding.EncodeToString(privateKey)), 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := writeRegistryExclusiveFile(publicPath, []byte(base64.StdEncoding.EncodeToString(publicKey)), 0o644); err != nil {
		return fmt.Errorf("write public key: %w (private key was created and must be secured)", err)
	}
	return nil
}

func registryManifestCLIPath() string {
	if dir := os.Getenv("REGISTRY_DIR"); dir != "" {
		return filepath.Join(dir, registryCheckpointPayload)
	}
	return filepath.Join("/registry", registryCheckpointPayload)
}

func runRegistryCheckpointCommand(args []string) (int, bool) {
	if len(args) == 0 {
		return 0, false
	}
	switch args[0] {
	case "audit-keygen":
		fs := flag.NewFlagSet("audit-keygen", flag.ContinueOnError)
		privatePath := fs.String("priv", "", "canonical absolute private key output path")
		publicPath := fs.String("pub", "", "canonical absolute public key output path")
		if err := fs.Parse(args[1:]); err != nil {
			return 2, true
		}
		if *privatePath == "" || *publicPath == "" {
			fmt.Fprintln(os.Stderr, "audit-keygen requires -priv and -pub")
			return 2, true
		}
		if err := generateRegistryCheckpointKeypair(*privatePath, *publicPath); err != nil {
			fmt.Fprintf(os.Stderr, "checkpoint key generation failed: %v\n", err)
			return 1, true
		}
		fmt.Printf("checkpoint keypair generated: private=%s public=%s\n", *privatePath, *publicPath)
		return 0, true
	case "audit-checkpoint":
		fs := flag.NewFlagSet("audit-checkpoint", flag.ContinueOnError)
		source := fs.String("manifest", registryManifestCLIPath(), "canonical absolute offline registry manifest path")
		key := fs.String("key", "", "canonical absolute owner-only Ed25519 private key path")
		output := fs.String("output", "", "canonical absolute new checkpoint output path")
		if err := fs.Parse(args[1:]); err != nil {
			return 2, true
		}
		if *key == "" || *output == "" {
			fmt.Fprintln(os.Stderr, "audit-checkpoint requires -key and -output")
			return 2, true
		}
		checkpoint, err := exportRegistryCheckpoint(*source, *key, *output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "checkpoint export failed: %v\n", err)
			return 1, true
		}
		fmt.Printf("registry checkpoint written: entries=%d head=%s\n", checkpoint.EntryCount, checkpoint.ChainHead)
		return 0, true
	case "audit-verify":
		fs := flag.NewFlagSet("audit-verify", flag.ContinueOnError)
		checkpointPath := fs.String("checkpoint", "", "checkpoint file path")
		publicPath := fs.String("pubkey", "", "canonical absolute trusted Ed25519 public key path")
		requiredHead := fs.String("require-head", "", "independently retained chain head required in the checkpoint")
		if err := fs.Parse(args[1:]); err != nil {
			return 2, true
		}
		if *checkpointPath == "" || *publicPath == "" {
			fmt.Fprintln(os.Stderr, "audit-verify requires -checkpoint and -pubkey")
			return 2, true
		}
		checkpoint, _, err := loadAndVerifyRegistryCheckpoint(*checkpointPath, *publicPath, *requiredHead)
		if err != nil {
			fmt.Fprintf(os.Stderr, "checkpoint verification failed: %v\n", err)
			return 1, true
		}
		fmt.Printf("registry checkpoint verified: entries=%d head=%s\n", checkpoint.EntryCount, checkpoint.ChainHead)
		return 0, true
	case "audit-recover":
		fs := flag.NewFlagSet("audit-recover", flag.ContinueOnError)
		checkpointPath := fs.String("checkpoint", "", "checkpoint file path")
		publicPath := fs.String("pubkey", "", "canonical absolute trusted Ed25519 public key path")
		output := fs.String("output", "", "canonical absolute new manifest output path (must not exist)")
		requiredHead := fs.String("require-head", "", "independently retained chain head required in the checkpoint")
		if err := fs.Parse(args[1:]); err != nil {
			return 2, true
		}
		if *checkpointPath == "" || *publicPath == "" || *output == "" || *requiredHead == "" {
			fmt.Fprintln(os.Stderr, "audit-recover requires -checkpoint, -pubkey, -output, and -require-head")
			return 2, true
		}
		if err := recoverRegistryCheckpoint(*checkpointPath, *publicPath, *output, *requiredHead); err != nil {
			fmt.Fprintf(os.Stderr, "checkpoint recovery failed: %v\n", err)
			return 1, true
		}
		fmt.Printf("verified registry manifest recovered to new path %s\n", *output)
		return 0, true
	case "-h", "--help", "help":
		printRegistryCheckpointUsage(os.Stderr)
		return 0, true
	default:
		fmt.Fprintf(os.Stderr, "unknown registry command: %s\n\n", args[0])
		printRegistryCheckpointUsage(os.Stderr)
		return 2, true
	}
}

func printRegistryCheckpointUsage(output io.Writer) {
	fmt.Fprint(output, `ai-model-registry — authenticated model registry

Usage:
  registry                         Start the registry server
  registry audit-keygen [options]  Generate a dedicated checkpoint keypair
  registry audit-checkpoint        Export a signed offline manifest checkpoint
  registry audit-verify            Verify a signed checkpoint and optional anchor
  registry audit-recover           Recover verified bytes to a new path
`)
}
