package filesystem_test

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/xtls/xray-core/common/platform/filesystem"
)

func TestStatAssetRejectsInvalidPath(t *testing.T) {
	for _, file := range []string{
		"",
		".",
		"..",
		"../geoip.dat",
		"nested/..",
		"nested/../geoip.dat",
		"nested//geoip.dat",
		"/geoip.dat",
		"/tmp/geoip.dat",
		`C:\geoip.dat`,
		`C:geoip.dat`,
		`\\server\share\geoip.dat`,
		`nested\geoip.dat`,
		`nested\..\geoip.dat`,
		filepath.Join(t.TempDir(), "geoip.dat"),
	} {
		if _, err := StatAsset(file); err == nil {
			t.Fatalf("expected error for %q", file)
		}
	}
}

func TestResolveAsset(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("xray.location.asset", dir)

	path, err := ResolveAsset("geoip.dat")
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, "geoip.dat") {
		t.Fatalf("ResolveAsset() = %q, want %q", path, filepath.Join(dir, "geoip.dat"))
	}

	if err := os.Mkdir(filepath.Join(dir, "geodata"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveAsset("geodata"); err == nil {
		t.Fatal("expected error")
	}
}
