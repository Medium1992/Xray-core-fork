package conf

import (
	"testing"

	"github.com/xtls/xray-core/transport/internet/reality"
)

func TestREALITYClientBrowser(t *testing.T) {
	base := func(browser string) *REALITYConfig {
		return &REALITYConfig{
			Fingerprint: "chrome",
			ServerName:  "example.com",
			Password:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			Browser:     browser,
		}
	}
	for browser, want := range map[string]string{"": "", "off": "", "auto": "auto", "AUTO": "auto"} {
		message, err := base(browser).Build()
		if err != nil {
			t.Fatalf("browser %q: %v", browser, err)
		}
		if got := message.(*reality.Config).Browser; got != want {
			t.Fatalf("browser %q builds %q, want %q", browser, got, want)
		}
	}
	if _, err := base("chrome").Build(); err == nil {
		t.Fatal(`"browser" takes "auto" or "off"`)
	}
}
