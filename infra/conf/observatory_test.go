package conf

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestObservatoryConfigsUnmarshalJSON(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "object",
			input: `{"subjectSelector":["first"]}`,
			want:  []string{"first"},
		},
		{
			name:  "array",
			input: `[{"subjectSelector":["first"]},{"subjectSelector":["second"]}]`,
			want:  []string{"first", "second"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var configs ObservatoryConfigs
			if err := json.Unmarshal([]byte(test.input), &configs); err != nil {
				t.Fatal(err)
			}
			got := make([]string, 0, len(configs))
			for _, config := range configs {
				got = append(got, config.SubjectSelector[0])
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("got %v, want %v", got, test.want)
			}
		})
	}
}

func TestBurstObservatoryConfigsUnmarshalJSON(t *testing.T) {
	var configs BurstObservatoryConfigs
	if err := json.Unmarshal([]byte(`[{"subjectSelector":["first"],"pingConfig":{}},{"subjectSelector":["second"],"pingConfig":{}}]`), &configs); err != nil {
		t.Fatal(err)
	}
	if len(configs) != 2 {
		t.Fatalf("got %d configurations, want 2", len(configs))
	}
	if configs[0].SubjectSelector[0] != "first" || configs[1].SubjectSelector[0] != "second" {
		t.Fatalf("unexpected selectors: %v, %v", configs[0].SubjectSelector, configs[1].SubjectSelector)
	}
}

func TestMultipleObservatoryConfigPrefersBurst(t *testing.T) {
	config := &Config{
		OutboundConfigs: []OutboundDetourConfig{
			{Tag: "alpha"},
			{Tag: "beta"},
			{Tag: "gamma"},
		},
		Observatory: ObservatoryConfigs{
			{SubjectSelector: []string{""}},
			{SubjectSelector: []string{"beta"}},
		},
		BurstObservatory: BurstObservatoryConfigs{
			{SubjectSelector: []string{"beta"}, HealthCheck: &healthCheckSettings{}},
		},
	}

	result, err := config.buildMultipleObservatoryConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := result.Observatory[0].Config.OutboundTag, []string{"alpha", "gamma"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("first observatory tags: got %v, want %v", got, want)
	}
	if got := result.Observatory[1].Config.OutboundTag; len(got) != 0 {
		t.Fatalf("second observatory tags: got %v, want none", got)
	}
	if got, want := result.BurstObservatory[0].OutboundTag, []string{"beta"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("burst observatory tags: got %v, want %v", got, want)
	}
}
