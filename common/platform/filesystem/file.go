package filesystem

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/platform"
)

type FileReaderFunc func(path string) (io.ReadCloser, error)

var NewFileReader FileReaderFunc = func(path string) (io.ReadCloser, error) {
	return os.Open(path)
}

func ReadFile(path string) ([]byte, error) {
	reader, err := NewFileReader(path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return buf.ReadAllToBytes(reader)
}

func ReadAsset(file string) ([]byte, error) {
	path, _, err := getAssetFileLocation(file)
	if err != nil {
		return nil, err
	}
	return ReadFile(path)
}

func OpenAsset(file string) (io.ReadCloser, error) {
	path, _, err := getAssetFileLocation(file)
	if err != nil {
		return nil, err
	}
	return NewFileReader(path)
}

func StatAsset(file string) (os.FileInfo, error) {
	_, info, err := getAssetFileLocation(file)
	return info, err
}

func ResolveAsset(file string) (string, error) {
	path, err := resolveAssetPath(file)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return path, nil
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("asset is not a regular file")
	}
	return path, nil
}

func getAssetFileLocation(file string) (string, os.FileInfo, error) {
	path, err := ResolveAsset(file)
	if err != nil {
		return "", nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", nil, err
	}
	return path, info, nil
}

func resolveAssetPath(file string) (string, error) {
	if !filepath.IsLocal(file) || file == "." {
		return "", errors.New("asset path must stay in asset directory")
	}
	local, err := filepath.Localize(file)
	if err != nil {
		return "", err
	}
	return platform.GetAssetLocation(local), nil
}

func ReadCert(file string) ([]byte, error) {
	if filepath.IsAbs(file) {
		return ReadFile(file)
	}
	return ReadFile(platform.GetCertLocation(file))
}

func CopyFile(dst string, src string) error {
	bytes, err := ReadFile(src)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(bytes)
	return err
}
