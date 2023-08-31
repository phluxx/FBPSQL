package store

import (
	"context"

	"github.com/phluxx/FBPSQL/internal/config"
	"github.com/phluxx/FBPSQL/pkg/model/v1model"

	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

type Mysql struct {
	db *sqlx.DB
}

func (m *Mysql) Close() error {
	return m.db.Close()
}

func (m *Mysql) GetTeams(ctx context.Context) ([]v1model.Team, error) {
	rows, err := m.db.QueryxContext(ctx, "SELECT id, team FROM teams ORDER BY team ASC")
	if err != nil {
		return []v1model.Team{}, err
	}

	defer rows.Close()

	var teams []v1model.Team
	for rows.Next() {
		var team v1model.Team
		if err := rows.StructScan(&team); err != nil {
			return []v1model.Team{}, err
		}
		teams = append(teams, team)
	}
	return teams, nil
}

func (m *Mysql) GetGames(ctx context.Context, date string) ([]v1model.Game, error) {
	rows, err := m.db.QueryxContext(ctx, "SELECT id, fav_id, dog_id, spread FROM games WHERE date = ?", date)
	if err != nil {
		return []v1model.Game{}, err
	}

	defer rows.Close()

	var games []v1model.Game
	for rows.Next() {
		var game v1model.Game
		if err := rows.StructScan(&game); err != nil {
			return []v1model.Game{}, err
		}
		games = append(games, game)
	}
	return games, nil
}

func (m *Mysql) SaveGames(ctx context.Context, games []v1model.Game) error {
	stmt, err := m.db.PreparexContext(ctx, `INSERT INTO games (id, fav_id, dog_id, date, spread) VALUES (:id, :fav_id, :dog_id, :date, :spread)`)
	if err != nil {
		return err
	}

	defer stmt.Close()

	for _, game := range games {
		_, err = stmt.ExecContext(ctx, game)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Mysql) UpdateGames(ctx context.Context, games []v1model.Game) error {
	stmt, err := m.db.PreparexContext(ctx, `UPDATE games SET fav_id = :fav_id, dog_id = :dog_id, date = :date, spread = :spread WHERE id = :id`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, game := range games {
		if _, err = stmt.Exec(game); err != nil {
			return err
		}
	}

	return nil
}

func (m *Mysql) SaveTiebreaker(ctx context.Context, tb v1model.Tiebreaker) error {
	_, err := m.db.NamedExecContext(ctx, `INSERT INTO tiebreaker (id, question, date) VALUES (UUID(), :question, :date)`, tb)
	return err
}

func (m *Mysql) SaveUserpicks(ctx context.Context, picks v1model.Picks, username string) error {
	stmt, err := m.db.PrepareContext(ctx, `INSERT INTO userpicks (id, username, gameid, pickwinner) VALUES (UUID(), ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for gameID, teamID := range picks {
		_, err = stmt.Exec(username, gameID, teamID)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Mysql) SaveUserTiebreaker(ctx context.Context, tb v1model.UserTiebreaker) error {
	_, err := m.db.NamedExecContext(ctx, `INSERT INTO usertiebreakers (id, qid, username, response) VALUES (UUID(), :qid, :username, :response)`, tb)
	return err
}

func (m *Mysql) GetTiebreaker(ctx context.Context, date string) (v1model.Tiebreaker, error) {
	var tb v1model.Tiebreaker
	err := m.db.GetContext(ctx, &tb, `SELECT id, question, date FROM tiebreaker WHERE date = ?`, date)
	return tb, err
}

func NewMySQL(cfg *config.Config) (*Mysql, error) {
	// MySQL Database setup
	myconf := mysql.Config{
		User:                 cfg.Mysql.User,
		Passwd:               cfg.Mysql.Passwd,
		Net:                  "tcp",
		Addr:                 cfg.Mysql.Host,
		DBName:               cfg.Mysql.DBName,
		AllowNativePasswords: true,
	}

	db, err := sqlx.Open("mysql", myconf.FormatDSN())
	if err != nil {
		return nil, err
	}

	return &Mysql{db: db}, nil
}
