package v1request

import "github.com/phluxx/FBPSQL/pkg/model/v1model"

type UserTiebreaker struct {
	TiebreakerAnswer int    `json:"tiebreaker,string"`
	QID              string `json:"qid"`
}

func (u UserTiebreaker) ToModel(username string) v1model.UserTiebreaker {
	return v1model.UserTiebreaker{
		Username:         username,
		TiebreakerAnswer: u.TiebreakerAnswer,
		QID:              u.QID,
	}
}

type TieBreaker struct {
	ID                 string `json:"id"`
	GameDate           string `json:"gameDate"`
	TiebreakerQuestion string `json:"tiebreakerQuestion"`
}

func (t TieBreaker) ToModel() v1model.Tiebreaker {
	return v1model.Tiebreaker{
		ID:                 t.ID,
		GameDate:           t.GameDate,
		TiebreakerQuestion: t.TiebreakerQuestion,
	}
}
func (u UserTiebreaker) Valid() bool {
	return !(u.QID == "" || u.TiebreakerAnswer == 0)
}
