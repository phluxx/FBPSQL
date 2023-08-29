package v1model

type Game struct {
	Date   string  `db:"date"`
	ID     string  `db:"id"`
	FavID  string  `db:"fav_id"`
	DogID  string  `db:"dog_id"`
	Spread float64 `db:"spread"`
}
