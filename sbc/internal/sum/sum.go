package sum

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io/fs"
	"path/filepath"
	"sort"
)

func Verify(src embed.FS, dir, name string) error {
	h, err := hashDir(src, dir, name)
	if err != nil {
		return err
	}

	hd := dir + "\x20" + h

	path := filepath.Join(dir, name)
	hash, err := fs.ReadFile(src, path)
	if err != nil {
		return err
	}

	if hd == string(hash) {
		return nil
	}

	return errors.New("sum: detect checksum mismatch")
}

func hashDir(src embed.FS, dir, excl string) (string, error) {
	r, err := fs.ReadDir(src, dir)
	if err != nil {
		return "", err
	}

	var files []string

	for _, f := range r {
		name := f.Name()
		if name == excl {
			continue
		}
		files = append(files, name)
	}

	sort.Strings(files)

	h := sha256.New()

	for _, file := range files {
		cert, err := fs.ReadFile(src, filepath.Join(dir, file))
		if err != nil {
			return "", err
		}
		hf := sha256.New()
		hf.Write(cert)
		sum := hf.Sum(nil)
		h.Write([]byte(hex.EncodeToString(sum) + "\x20\x20" + file + "\n"))
	}

	return "h1:" + base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}
