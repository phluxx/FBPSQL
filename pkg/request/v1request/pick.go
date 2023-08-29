package v1request

import (
	"errors"

	"github.com/phluxx/FBPSQL/pkg/model/v1model"
)

type Picks struct {
	Picks map[string]string `json:"picks"`
}

func (p Picks) ToModel() (v1model.Picks, error) {
	picks := v1model.Picks{}
	for k, v := range p.Picks {
		if len(k) == 0 || len(v) == 0 {
			return nil, errors.New("received an empty UUID for a game")
		}
		picks[k] = v
	}
	return picks, nil
}
