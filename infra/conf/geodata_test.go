package conf_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/app/geodata"
	. "github.com/xtls/xray-core/infra/conf"
)

func TestGeodataConfig(t *testing.T) {
	t.Setenv("xray.location.asset", t.TempDir())

	creator := func() Buildable {
		return new(GeodataConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"cron": "0 4 * * *",
				"outbound": "proxy",
				"assets": [
					{"url": "https://example.com/geoip.dat", "file": "geoip.dat"},
					{"url": "https://example.com/geosite.dat", "file": "geosite.dat"}
				]
			}`,
			Parser: loadJSON(creator),
			Output: &geodata.Config{
				Cron:     "0 4 * * *",
				Outbound: "proxy",
				Assets: []*geodata.Asset{
					{Url: "https://example.com/geoip.dat", File: "geoip.dat"},
					{Url: "https://example.com/geosite.dat", File: "geosite.dat"},
				},
			},
		},
	})
}

func TestGeodataAssetConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("xray.location.asset", dir)
	if err := os.WriteFile(filepath.Join(dir, "geoip.dat"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := (&GeodataAssetConfig{
		URL:  "https://example.com/geoip.dat",
		File: "geoip.dat",
	}).Build(); err != nil {
		t.Fatal(err)
	}

	if _, err := (&GeodataAssetConfig{
		URL:  "https://example.com/geoip.dat",
		File: "missing.dat",
	}).Build(); err != nil {
		t.Fatal(err)
	}
}

func TestGeodataAssetConfigInvalidURL(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("xray.location.asset", dir)
	if err := os.WriteFile(filepath.Join(dir, "geoip.dat"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, rawURL := range []string{
		"",
		"http://example.com/geoip.dat",
		"ftp://example.com/geoip.dat",
		"https:///geoip.dat",
	} {
		if _, err := (&GeodataAssetConfig{
			URL:  rawURL,
			File: "geoip.dat",
		}).Build(); err == nil {
			t.Fatalf("expected error for %q", rawURL)
		}
	}
}
