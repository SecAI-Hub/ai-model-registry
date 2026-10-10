package main

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// Empty scopes preserve the existing all-service deployment contract. Selecting
// any scoped path requires every independent credential; it never falls back.
var registryScopeTokens = map[string]string{}

func loadRegistryScopeTokens() (bool, error) {
	paths := map[string]string{}
	for _, role := range []string{"read", "verify", "promote", "admin"} {
		if path := strings.TrimSpace(os.Getenv("REGISTRY_" + strings.ToUpper(role) + "_TOKEN_PATH")); path != "" {
			paths[role] = path
		}
	}
	registryScopeTokens = map[string]string{}
	if len(paths) == 0 {
		return false, nil
	}
	if len(paths) != 4 {
		return true, fmt.Errorf("all registry scope token paths must be configured")
	}
	candidate, seen := map[string]string{}, map[string]bool{}
	for _, role := range []string{"read", "verify", "promote", "admin"} {
		info, err := os.Lstat(paths[role])
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || fileLinkCount(info) != 1 {
			return true, fmt.Errorf("registry %s credential must be a private single-link regular file", role)
		}
		data, err := readRegularBounded(paths[role], maxTokenBytes)
		if err != nil {
			return true, fmt.Errorf("registry %s credential unavailable: %w", role, err)
		}
		after, err := os.Lstat(paths[role])
		if err != nil || !os.SameFile(info, after) || info.Mode() != after.Mode() ||
			!info.ModTime().Equal(after.ModTime()) || info.Size() != after.Size() || fileLinkCount(after) != 1 {
			return true, fmt.Errorf("registry %s credential changed while loading", role)
		}
		token := strings.TrimSpace(string(data))
		if len(token) < 32 || strings.ContainsAny(token, " \t\r\n") || seen[token] {
			return true, fmt.Errorf("registry scope credentials must be distinct, at least 32 bytes and without whitespace")
		}
		seen[token], candidate[role] = true, token
	}
	registryScopeTokens = candidate
	return true, nil
}

func requireRegistryScope(role string, next http.HandlerFunc) http.HandlerFunc {
	return requireRegistryScopes(next, role)
}

func requireRegistryScopes(next http.HandlerFunc, roles ...string) http.HandlerFunc {
	allowedRoles := append(append([]string{}, roles...), "admin")
	return func(w http.ResponseWriter, r *http.Request) {
		if len(registryScopeTokens) == 0 {
			requireServiceToken(next)(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			token := strings.TrimPrefix(auth, "Bearer ")
			for _, allowed := range allowedRoles {
				if expected := registryScopeTokens[allowed]; expected != "" && subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1 {
					next(w, r)
					return
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden: invalid registry scope credential"}`))
	}
}

func modelPathSelector(raw string) (name, filename string, err error) {
	query, err := url.ParseQuery(raw)
	if err != nil || len(query["name"]) > 1 || len(query["filename"]) > 1 ||
		(len(query["name"]) == 1) == (len(query["filename"]) == 1) {
		return "", "", fmt.Errorf("exactly one model selector required")
	}
	name, filename = query.Get("name"), query.Get("filename")
	if len(query["name"]) == 1 {
		if !validArtifactName(name) {
			return "", "", fmt.Errorf("invalid model name")
		}
	} else if filename == "" || len(filename) > 512 || filename == "." || filename == ".." || strings.ContainsAny(filename, "/\\") {
		return "", "", fmt.Errorf("invalid model filename")
	} else {
		for _, character := range filename {
			if character < 32 || character == 127 {
				return "", "", fmt.Errorf("invalid model filename")
			}
		}
	}
	return name, filename, nil
}

func registryArtifactBySelector(name, filename string) (Artifact, bool) {
	manifestMu.RLock()
	defer manifestMu.RUnlock()
	if manifestPersistenceFailed {
		return Artifact{}, false
	}
	var selected Artifact
	matches := 0
	for _, artifact := range manifest.Models {
		if (name != "" && artifact.Name == name) || (filename != "" && artifact.Filename == filename) {
			selected = artifact
			matches++
		}
	}
	return selected, matches == 1
}
