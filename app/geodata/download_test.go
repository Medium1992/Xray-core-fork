package geodata

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDownloadMissingAsset(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("xray.location.asset", dir)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("geodata"))
	}))
	defer server.Close()

	if err := DownloadMissingAssets(context.Background(), []*Asset{{Url: server.URL, File: "geoip.dat"}}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "geoip.dat"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "geodata" {
		t.Fatalf("asset contents = %q, want %q", data, "geodata")
	}
}
