package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

type Team struct {
	ID   string `json:"id"`
	Name string `json:"team"`
}

type payloadData struct {
	GameDate string `json:"gameDate"`
	Games    []struct {
		ID     string  `json:"id"`
		FavID  string  `json:"favorite"`
		DogID  string  `json:"underdog"`
		Spread float64 `json:"spread"`
	} `json:"games"`
}

type gameData struct {
	ID     string  `json:"id"`
	FavID  string  `json:"favorite"`
	DogID  string  `json:"underdog"`
	Spread float64 `json:"spread"`
}

type matchData struct {
	ID     string  `json:"id"`
	FavID  string  `json:"favorite"`
	DogID  string  `json:"underdog"`
	Spread float64 `json:"spread"`
}

type tiebreakerData struct {
	GameDate           string `json:"gameDate"`
	TiebreakerQuestion string `json:"tiebreakerQuestion"`
}

type userTiebreakerData struct {
	GameDate         string `json:"gameDate"`
	TiebreakerAnswer int    `json:"tiebreakerAnswer"`
}

var db *sql.DB

func main() {
	// MySQL Database setup
	config := mysql.Config{
		User:                 os.Getenv("MYSQL_USER"),
		Passwd:               os.Getenv("MYSQL_PASSWORD"),
		Net:                  "tcp",
		Addr:                 os.Getenv("MYSQL_HOST"),
		DBName:               os.Getenv("MYSQL_DATABASE"),
		AllowNativePasswords: true,
	}
	var err error
	db, err = sql.Open("mysql", config.FormatDSN())
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	r := mux.NewRouter()
	r.HandleFunc("/api/populateteams", populateTeamsHandler).Methods("GET")
	r.HandleFunc("/api/savegames", saveGamesHandler).Methods("POST")
	r.HandleFunc("/api/checkdate/{date}", checkDateHandler)
	r.HandleFunc("/api/populategames/{date}", populateGamesHandler).Methods("GET")
	r.HandleFunc("/api/updategames", updateGamesHandler).Methods("PUT")
	r.HandleFunc("/api/matchmaker/{date}", matchMakerHandler).Methods("GET")
	r.HandleFunc("/api/savetiebreaker", saveTiebreakerHandler).Methods("POST")
	r.HandleFunc("/api/saveusertiebreaker", saveUserTiebreakerHandler).Methods("POST")
	r.HandleFunc("/api/gettiebreaker/{date}", getTiebreakerHandler).Methods("GET")

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"https://pool.ewnix.net"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization"},
		AllowCredentials: true,
	})

	handler := c.Handler(r)
	log.Fatal(http.ListenAndServe(":8080", handler))
}

func populateTeamsHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, team FROM teams ORDER BY team ASC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var teams []Team
	for rows.Next() {
		var team Team
		if err := rows.Scan(&team.ID, &team.Name); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		teams = append(teams, team)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(teams)
}

func saveGamesHandler(w http.ResponseWriter, r *http.Request) {

	var payload payloadData
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	stmt, err := db.Prepare(`INSERT INTO games (id, fav_id, dog_id, date, spread) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	for _, game := range payload.Games {
		if len(game.ID) == 0 {
			http.Error(w, "Received an empty UUID for a game.", http.StatusBadRequest)
			return
		}
		log.Printf("Parsing ID: %s", game.ID)
		_, err = stmt.Exec(game.ID, game.FavID, game.DogID, payload.GameDate, game.Spread)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "Games saved successfully!",
	})
}

func populateGamesHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	date := vars["date"]

	rows, err := db.Query("SELECT id, fav_id, dog_id, spread FROM games WHERE date = ?", date)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var games []gameData
	for rows.Next() {
		var game gameData
		err = rows.Scan(&game.ID, &game.FavID, &game.DogID, &game.Spread)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		games = append(games, game)
	}
	json.NewEncoder(w).Encode(games)
}

func checkDateHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	gameDate := vars["date"]
	// Let's make sure the dates are valid before we even begin.
	_, err := time.Parse("2006-01-02", gameDate)
	if err != nil {
		http.Error(w, "Invalid date format.", http.StatusBadRequest)
		return
	}
	// Query the DB
	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM games WHERE date=?)", gameDate).Scan(&exists)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	response := map[string]bool{
		"gamesExist": exists,
	}
	// Send the response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func updateGamesHandler(w http.ResponseWriter, r *http.Request) {

	var payload payloadData
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// The SQL statement is modified to UPDATE the games based on the game's UUID.
	stmt, err := db.Prepare(`UPDATE games SET fav_id = ?, dog_id = ?, date = ?, spread = ? WHERE id = ?`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	for _, game := range payload.Games {
		if len(game.ID) == 0 {
			http.Error(w, "Received an empty UUID for a game.", http.StatusBadRequest)
			return
		}
		log.Printf("Updating ID: %s", game.ID)
		// The order of values in Exec() corresponds to the order of placeholders in the SQL statement.
		_, err = stmt.Exec(game.FavID, game.DogID, payload.GameDate, game.Spread, game.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "Games updated successfully!",
	})
}

func matchMakerHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	date := vars["date"]

	rows, err := db.Query("SELECT id, fav_id, dog_id, spread FROM games WHERE date = ?", date)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var games []matchData
	for rows.Next() {
		var match matchData
		err = rows.Scan(&match.ID, &match.FavID, &match.DogID, &match.Spread)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		games = append(games, match)
	}
	json.NewEncoder(w).Encode(games)
}

func saveTiebreakerHandler(w http.ResponseWriter, r *http.Request) {
	var payload tiebreakerData
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	stmt, err := db.Prepare(`INSERT INTO tiebreaker (id, question, date) VALUES (UUID(), ?, ?)`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(payload.TiebreakerQuestion, payload.GameDate)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "Tiebreaker saved successfully!",
	})
}

func saveUserTiebreakerHandler(w http.ResponseWriter, r *http.Request) {
	var payload userTiebreakerData
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var tiebreakerID string
	err = db.QueryRow("SELECT id FROM tiebreaker WHERE date=?", payload.GameDate).Scan(&tiebreakerID)
	if err != nil {
		http.Error(w, "Error fetching tiebreaker ID: "+err.Error(), http.StatusInternalServerError)
		return
	}

	stmt, err := db.Prepare(`INSERT INTO usertiebreakers (id, qid, response) VALUES (UUID(), ?, ?)`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(tiebreakerID, payload.TiebreakerAnswer)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "User tiebreaker saved successfully!",
	})
}

func getTiebreakerHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	date := vars["date"]

	var tiebreakerQuestion string
	err := db.QueryRow("SELECT question FROM tiebreaker WHERE date=?", date).Scan(&tiebreakerQuestion)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "No tiebreaker found for the given date", http.StatusNotFound)
			return
		}
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	response := tiebreakerData{
		GameDate:           date,
		TiebreakerQuestion: tiebreakerQuestion,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
