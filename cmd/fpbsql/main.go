package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
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
	ID                 string `json:"id"`
	GameDate           string `json:"gameDate"`
	TiebreakerQuestion string `json:"tiebreakerQuestion"`
}

type userTiebreakerPayload struct {
	TiebreakerAnswer int    `json:"tiebreaker,string"`
	Username         string `json:"username"`
	QID              string `json:"qid"`
}

type userPickPayload struct {
	Username string            `json:"username"`
	Picks    map[string]string `json:"picks"`
}

var db *sql.DB

var jwtSecret = []byte(os.Getenv("TOKEN_SIGNATURE"))

type TokenResponse struct {
	Token string `json:"token"`
}

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
	r.HandleFunc("/api/saveuserpicks", verifyTokenMiddleware(saveUserPicksHandler)).Methods("POST")
	r.HandleFunc("/api/savetiebreaker", saveTiebreakerHandler).Methods("POST")
	r.HandleFunc("/api/saveusertiebreaker", verifyTokenMiddleware(saveUserTiebreakerHandler)).Methods("POST")
	r.HandleFunc("/api/gettiebreaker/{date}", getTiebreakerHandler).Methods("GET")
	r.HandleFunc("/api/isbettingopen", isBettingOpenHandler).Methods("GET")
	r.HandleFunc("/api/openbetting", openBettingHandler).Methods("POST")
	r.HandleFunc("/api/closebetting", closeBettingHandler).Methods("POST")
	r.HandleFunc("/api/login", loginHandler).Methods("POST")
	r.HandleFunc("/api/register", registerHandler).Methods("POST")
	r.HandleFunc("/api/getusertiebreaker/{decodedUsername}/{nextSaturday}", getUserTiebreakerHandler).Methods("GET")
	r.HandleFunc("/api/getuserpicks/{decodedUsername}/{nextSaturday}", getUserPicksHandler).Methods("GET")

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
	var payload userTiebreakerPayload
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if the necessary fields are present
	if payload.Username == "" || payload.QID == "" || payload.TiebreakerAnswer == 0 {
		http.Error(w, "Missing required fields in payload", http.StatusBadRequest)
		return
	}

	stmt, err := db.Prepare(`INSERT INTO usertiebreakers (id, qid, username, response) VALUES (UUID(), ?, ?, ?)`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(payload.QID, payload.Username, payload.TiebreakerAnswer)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "Tiebreaker saved successfully!",
	})
}

func getTiebreakerHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	date := vars["date"]

	var id, tiebreakerQuestion string
	err := db.QueryRow("SELECT id, question FROM tiebreaker WHERE date=?", date).Scan(&id, &tiebreakerQuestion)
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
		ID:                 id,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func isBettingOpenHandler(w http.ResponseWriter, r *http.Request) {
	var isOpenInt int
	err := db.QueryRow("SELECT value FROM config WHERE name='isBettingOpen'").Scan(&isOpenInt)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Betting configuration not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	isOpen := false
	if isOpenInt == 1 {
		isOpen = true
	}

	response := map[string]bool{
		"isBettingOpen": isOpen,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func openBettingHandler(w http.ResponseWriter, r *http.Request) {
	_, err := db.Exec("UPDATE config SET value=1 WHERE name='isBettingOpen'")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "Betting opened successfully!",
	})
}

func closeBettingHandler(w http.ResponseWriter, r *http.Request) {
	_, err := db.Exec("UPDATE config SET value=0 WHERE name='isBettingOpen'")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "Betting closed successfully!",
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Unable to parse request", http.StatusBadRequest)
		return
	}

	// Connect to LDAP
	l, err := ldap.DialURL("ldap://sso.ewnix.net")
	if err != nil {
		http.Error(w, "Failed to connect to the LDAP server", http.StatusInternalServerError)
		return
	}
	defer l.Close()

	// Search the LDAP DB for the user

	searchRequest := ldap.NewSearchRequest(
		"ou=people,dc=ewnix,dc=net",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(cn=%s)", creds.Username),
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil || len(sr.Entries) != 1 {
		http.Error(w, "Failed to find user", http.StatusUnauthorized)
		return
	}

	userDN := sr.Entries[0].DN

	// Bind as the user to verify their password

	err = l.Bind(userDN, creds.Password)
	if err != nil {
		http.Error(w, "Failed to authenticate user", http.StatusUnauthorized)
		return
	}

	// Create the token

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": creds.Username,
		"nbf":      time.Now().Unix(),
	})

	// Sign the token

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Failed to generate the token", http.StatusInternalServerError)
		return
	}

	// Create response

	response := TokenResponse{
		Token: tokenString,
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Failed to encode token to JSON", http.StatusInternalServerError)
		return
	}

	// Return the token
	w.Header().Set("Content-Type", "application/json")

	w.Write(jsonData)
}

func saveUserPicksHandler(w http.ResponseWriter, r *http.Request) {
	var payload userPickPayload
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	stmt, err := db.Prepare(`INSERT INTO userpicks (id, username, gameid, pickwinner) VALUES (UUID(), ?, ?, ?)`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	for gameID, teamID := range payload.Picks {
		if len(gameID) == 0 || len(teamID) == 0 {
			http.Error(w, "Received an empty UUID for a game.", http.StatusBadRequest)
			return
		}
		log.Printf(" Parsing Game ID: %s with Team ID: %s", gameID, teamID)
		_, err = stmt.Exec(payload.Username, gameID, teamID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "User picks saved successfully!",
	})
}

func GenerateCrypt(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return "{CRYPT}" + string(hashed), nil
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Unable to parse request", http.StatusBadRequest)
		return
	}

	l, err := ldap.DialURL("ldap://sso.ewnix.net")
	if err != nil {
		http.Error(w, "Failed to connect to the LDAP server", http.StatusInternalServerError)
		return
	}
	defer l.Close()

	// Bind as the admin to add the new user
	adminPassword := os.Getenv("LDAP_ADMIN_PASSWORD")
	err = l.Bind("cn=admin,dc=ewnix,dc=net", adminPassword)
	if err != nil {
		http.Error(w, "Failed to bind as admin", http.StatusInternalServerError)
		return
	}

	// Generate a CRYPT hash
	hashedPassword, err := GenerateCrypt(creds.Password)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to hash password: %v", err), http.StatusInternalServerError)
		return
	}

	addUserRequest := ldap.NewAddRequest(fmt.Sprintf("cn=%s,ou=people,dc=ewnix,dc=net", creds.Username), nil)
	addUserRequest.Attribute("objectClass", []string{"inetOrgPerson"}) // Assuming you're using inetOrgPerson
	addUserRequest.Attribute("cn", []string{creds.Username})
	addUserRequest.Attribute("sn", []string{creds.Username})
	addUserRequest.Attribute("mail", []string{creds.Email})
	addUserRequest.Attribute("userPassword", []string{hashedPassword})

	err = l.Add(addUserRequest)
	if err != nil {
		http.Error(w, "Failed to add user", http.StatusInternalServerError)
		return
	}

	modifyGroupRequest := ldap.NewModifyRequest("cn=football,ou=groups,dc=ewnix,dc=net", nil)
	userDN := fmt.Sprintf("cn=%s,ou=people,dc=ewnix,dc=net", creds.Username)
	modifyGroupRequest.Add("member", []string{userDN})

	err = l.Modify(modifyGroupRequest)
	if err != nil {
		http.Error(w, "Failed to add user to group", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Registration successful"))
}

func verifyTokenMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header is missing", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]

		// Parse the token string
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Ensure token method is what we expect
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Continue to the next handler if the token is valid
		next.ServeHTTP(w, r)
	}
}

func getUserTiebreakerHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["decodedUsername"]
	date := vars["nextSaturday"]

	var response userTiebreakerPayload
	err := db.QueryRow("SELECT qid, username, response FROM usertiebreakers WHERE username=? AND date=?", username, date).Scan(&response.QID, &response.Username, &response.TiebreakerAnswer)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "No tiebreaker found for the given username and date", http.StatusNotFound)
			return
		}
		http.Error(w, "Server error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func getUserPicksHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["decodedUsername"]
	date := vars["nextSaturday"]

	// SQL query that joins the userpicks table with the games table based on game ID and filters by date
	query := `
        SELECT 
            userpicks.id, userpicks.username, userpicks.gameid, userpicks.pickwinner 
        FROM 
            userpicks 
        JOIN 
            games ON userpicks.gameid = games.id 
        WHERE 
            userpicks.username = ? AND games.date = ?
    `

	rows, err := db.Query(query, username, date)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var picks []userPickPayload
	for rows.Next() {
		var pick struct {
			ID         string `json:"id"`
			Username   string `json:"username"`
			GameID     string `json:"gameId"`
			PickWinner string `json:"pickWinner"`
		}

		if err := rows.Scan(&pick.ID, &pick.Username, &pick.GameID, &pick.PickWinner); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Map the results to the expected payload
		payload := userPickPayload{
			Username: pick.Username,
			Picks: map[string]string{
				pick.GameID: pick.PickWinner,
			},
		}

		picks = append(picks, payload)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(picks)
}
