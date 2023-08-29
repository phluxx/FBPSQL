package v1view

type Game struct {
	ID     string  `json:"id"`
	FavID  string  `json:"favorite"`
	DogID  string  `json:"underdog"`
	Spread float64 `json:"spread"`
}
