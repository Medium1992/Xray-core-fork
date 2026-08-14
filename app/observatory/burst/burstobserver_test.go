package burst

import "testing"

type handlerSelector []string

func (s handlerSelector) Select([]string) []string {
	return s
}

func TestObserverSelectOutboundsUsesAssignedTags(t *testing.T) {
	observer := &Observer{config: &Config{
		SubjectSelector: []string{""},
		OutboundTag:     []string{"second"},
		UseOutboundTag:  true,
	}}

	got := observer.selectOutbounds(handlerSelector{"first", "second", "third"})
	if len(got) != 1 || got[0] != "second" {
		t.Fatalf("got %v, want [second]", got)
	}
}
