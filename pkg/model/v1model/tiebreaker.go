package v1model

type Tiebreaker struct {
	ID                 string `db:"id"`
	GameDate           string `db:"date"`
	TiebreakerQuestion string `db:"question"`
}

type UserTiebreaker struct {
	Username         string `db:"username"`
	TiebreakerAnswer int    `db:"response"`
	QID              string `db:"qid"`
}
