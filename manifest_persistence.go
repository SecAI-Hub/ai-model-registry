package main

import "os"

// Narrow fault-injection seams; production uses the local filesystem primitives.
// The latch is set only after publication when a directory-sync failure makes
// the persistence outcome ambiguous. The caller retains the restrictive candidate
// and stops runtime use instead of reverting memory to a possibly stale trusted state.
var manifestPersistence = struct {
	write         func(*os.File, []byte) (int, error)
	syncFile      func(*os.File) error
	rename        func(string, string) error
	syncDirectory func(string) error
}{
	write:    func(f *os.File, data []byte) (int, error) { return f.Write(data) },
	syncFile: func(f *os.File) error { return f.Sync() },
	rename:   os.Rename,
	syncDirectory: func(path string) error {
		dir, err := os.Open(path)
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Sync()
	},
}
