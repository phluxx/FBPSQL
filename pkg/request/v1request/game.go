package v1request

import (
	"errors"

	"github.com/phluxx/FBPSQL/pkg/model/v1model"
)

type GameList struct {
	GameDate string `json:"gameDate"`
	Games    []Game `json:"games"`
}

type Game struct {
	ID     string  `json:"id"`
	FavID  string  `json:"favorite"`
	DogID  string  `json:"underdog"`
	Spread float64 `json:"spread"`
}

func (g Game) Validate() error {
	if len(g.ID) == 0 {
		return errors.New("received an empty UUID for a game")
	}
	return nil
}

func (g GameList) ToModel() ([]v1model.Game, error) {
	var games []v1model.Game
	for _, game := range g.Games {
		if err := game.Validate(); err != nil {
			return []v1model.Game{}, err
		}
		games = append(games, v1model.Game{
			Date:   g.GameDate,
			ID:     game.ID,
			FavID:  game.FavID,
			DogID:  game.DogID,
			Spread: game.Spread,
		})
	}

	return games, nil
}
