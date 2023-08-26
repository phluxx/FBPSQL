package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"database/sql/driver"
	"errors"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/google/uuid"
)

type Team struct {
	ID   string `json:"id"`
	Name string `json:"team"`
}

var db *sql.DB

func main() {
	// MySQL Database setup
	config := mysql.Config{
		User:   os.Getenv("MYSQL_USER"),
		Passwd: os.Getenv("MYSQL_PASSWORD"),
		Net:    "tcp",
		Addr:   os.Getenv("MYSQL_HOST"),
		DBName: os.Getenv("MYSQL_DATABASE"),
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
	r.HandleFunc("/api/checkdate", checkDateHandler)

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"https://pool.ewnix.net"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization"},
		AllowCredentials: true,
	})

	handler := c.Handler(r)
	log.Fatal(http.ListenAndServe(":8080",handler))
}

func populateTeamsHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT HEX(id) as id, team FROM teams ORDER BY team ASC")
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

func uuidFromStrToBin(u string) (driver.Value, error) {
	uuidVal, err := uuid.Parse(u)
	if uuidVal == uuid.Nil {
	    return nil, errors.New("Parsed UUID is nil")
	}
	if err != nil {
	    return nil, err
	}
	return uuidVal[:], nil
}

func saveGamesHandler(w http.ResponseWriter, r *http.Request) {
        type payloadData struct {
            GameDate string `json:"gameDate"`
	    Games []struct {
		ID     string `json:"id"`
		FavID  string `json:"favorite"`
		DogID  string `json:"underdog"`
		Spread float64 `json:"spread"`
	} `json:"games"`
      }

        var payload payloadData
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	stmt, err := db.Prepare(`INSERT INTO games (id, fav_id, dog_id, date, spread) VALUES (?, UNHEX(?), UNHEX(?), ?, ?)`)
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
		binID, err := uuidFromStrToBin(game.ID)
		if err != nil {
		    http.Error(w, err.Error(), http.StatusInternalServerError)
		    return
		}
		_, err = stmt.Exec(binID, game.FavID, game.DogID, payload.GameDate, game.Spread)
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

func checkDateHandler(w http.ResponseWriter, r *http.Request) {
    gameDate := strings.TrimPrefix(r.URL.Path, "/api/checkdate/")
    // Let's make sure the dates are valid before we even begin.
    _, err := time.Parse("2023-01-02", gameDate)
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
