package burst

import (
	"context"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/features/extension"
	"google.golang.org/protobuf/proto"
)

type MultipleObserver struct {
	observatory      []*observatory.Observer
	burstObservatory []*Observer
}

func (o *MultipleObserver) Type() interface{} {
	return extension.ObservatoryType()
}

func (o *MultipleObserver) Start() error {
	for _, observer := range o.observatory {
		if err := observer.Start(); err != nil {
			return err
		}
	}
	for _, observer := range o.burstObservatory {
		if err := observer.Start(); err != nil {
			return err
		}
	}
	return nil
}

func (o *MultipleObserver) Close() error {
	for _, observer := range o.observatory {
		if err := observer.Close(); err != nil {
			return err
		}
	}
	for _, observer := range o.burstObservatory {
		if err := observer.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (o *MultipleObserver) GetObservation(ctx context.Context) (proto.Message, error) {
	result := &observatory.ObservationResult{}
	for _, observer := range o.observatory {
		observation, err := observer.GetObservation(ctx)
		if err != nil {
			return nil, err
		}
		result.Status = append(result.Status, observation.(*observatory.ObservationResult).Status...)
	}
	for _, observer := range o.burstObservatory {
		observation, err := observer.GetObservation(ctx)
		if err != nil {
			return nil, err
		}
		result.Status = append(result.Status, observation.(*observatory.ObservationResult).Status...)
	}
	return result, nil
}

func (o *MultipleObserver) Check(tags []string) {
	for _, observer := range o.burstObservatory {
		selected := make([]string, 0, len(tags))
		for _, tag := range tags {
			for _, configuredTag := range observer.config.OutboundTag {
				if tag == configuredTag {
					selected = append(selected, tag)
					break
				}
			}
		}
		observer.Check(selected)
	}
}

func NewMultiple(ctx context.Context, config *MultipleConfig) (*MultipleObserver, error) {
	observer := &MultipleObserver{}
	for _, item := range config.Observatory {
		child, err := observatory.New(ctx, item.Config)
		if err != nil {
			return nil, err
		}
		observer.observatory = append(observer.observatory, child)
	}
	for _, item := range config.BurstObservatory {
		child, err := New(ctx, item)
		if err != nil {
			return nil, err
		}
		observer.burstObservatory = append(observer.burstObservatory, child)
	}
	return observer, nil
}

func init() {
	common.Must(common.RegisterConfig((*MultipleConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewMultiple(ctx, config.(*MultipleConfig))
	}))
}
