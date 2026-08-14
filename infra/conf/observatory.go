package conf

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/app/observatory/burst"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/infra/conf/cfgcommon/duration"
)

type ObservatoryConfigs []*ObservatoryConfig

func (c *ObservatoryConfigs) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if bytes.Equal(data, []byte("null")) {
		*c = nil
		return nil
	}
	if len(data) > 0 && data[0] == '[' {
		return json.Unmarshal(data, (*[]*ObservatoryConfig)(c))
	}
	config := new(ObservatoryConfig)
	if err := json.Unmarshal(data, config); err != nil {
		return err
	}
	*c = []*ObservatoryConfig{config}
	return nil
}

type ObservatoryConfig struct {
	SubjectSelector   []string          `json:"subjectSelector"`
	ProbeURL          string            `json:"probeURL"`
	ProbeInterval     duration.Duration `json:"probeInterval"`
	EnableConcurrency bool              `json:"enableConcurrency"`
}

func (o *ObservatoryConfig) Build() (proto.Message, error) {
	return &observatory.Config{SubjectSelector: o.SubjectSelector, ProbeUrl: o.ProbeURL, ProbeInterval: int64(o.ProbeInterval), EnableConcurrency: o.EnableConcurrency}, nil
}

func (o *ObservatoryConfig) matches(tag string) bool {
	for _, selector := range o.SubjectSelector {
		if strings.HasPrefix(tag, selector) {
			return true
		}
	}
	return false
}

type BurstObservatoryConfig struct {
	SubjectSelector []string `json:"subjectSelector"`
	// health check settings
	HealthCheck *healthCheckSettings `json:"pingConfig,omitempty"`
}

type BurstObservatoryConfigs []*BurstObservatoryConfig

func (c *BurstObservatoryConfigs) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if bytes.Equal(data, []byte("null")) {
		*c = nil
		return nil
	}
	if len(data) > 0 && data[0] == '[' {
		return json.Unmarshal(data, (*[]*BurstObservatoryConfig)(c))
	}
	config := new(BurstObservatoryConfig)
	if err := json.Unmarshal(data, config); err != nil {
		return err
	}
	*c = []*BurstObservatoryConfig{config}
	return nil
}

func (b BurstObservatoryConfig) Build() (proto.Message, error) {
	if b.HealthCheck == nil {
		return nil, errors.New("BurstObservatory requires a valid pingConfig")
	}
	if result, err := b.HealthCheck.Build(); err == nil {
		return &burst.Config{SubjectSelector: b.SubjectSelector, PingConfig: result.(*burst.HealthPingConfig)}, nil
	} else {
		return nil, err
	}
}

func (b *BurstObservatoryConfig) matches(tag string) bool {
	for _, selector := range b.SubjectSelector {
		if strings.HasPrefix(tag, selector) {
			return true
		}
	}
	return false
}

func (c *Config) buildMultipleObservatoryConfig() (*burst.MultipleConfig, error) {
	config := &burst.MultipleConfig{}
	owners := make(map[string]*[]string)
	assign := func(tag string, tags *[]string) {
		if previous, found := owners[tag]; found {
			for i, assignedTag := range *previous {
				if assignedTag == tag {
					*previous = append((*previous)[:i], (*previous)[i+1:]...)
					break
				}
			}
			errors.LogWarning(context.Background(), "outbound ", tag, " is assigned to multiple observatories; using the last configuration")
		}
		*tags = append(*tags, tag)
		owners[tag] = tags
	}

	for _, rawConfig := range c.Observatory {
		message, err := rawConfig.Build()
		if err != nil {
			return nil, err
		}
		observatoryConfig := message.(*observatory.Config)
		observatoryConfig.UseOutboundTag = true
		config.Observatory = append(config.Observatory, &burst.ObservatoryConfig{Config: observatoryConfig})
		for _, outbound := range c.OutboundConfigs {
			if rawConfig.matches(outbound.Tag) {
				assign(outbound.Tag, &observatoryConfig.OutboundTag)
			}
		}
	}

	for _, rawConfig := range c.BurstObservatory {
		message, err := rawConfig.Build()
		if err != nil {
			return nil, err
		}
		burstConfig := message.(*burst.Config)
		burstConfig.UseOutboundTag = true
		config.BurstObservatory = append(config.BurstObservatory, burstConfig)
		for _, outbound := range c.OutboundConfigs {
			if rawConfig.matches(outbound.Tag) {
				assign(outbound.Tag, &burstConfig.OutboundTag)
			}
		}
	}

	return config, nil
}
