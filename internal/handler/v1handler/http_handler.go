package v1handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/phluxx/FBPSQL/internal/config"
	"github.com/phluxx/FBPSQL/internal/store"
	"github.com/phluxx/FBPSQL/pkg/request/v1request"
	"github.com/phluxx/FBPSQL/pkg/view/v1view"

	"github.com/go-ldap/ldap/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

func New(cfg *config.Config, mysql *store.Mysql) *HttpHandler {
	h := &HttpHandler{
		config: cfg,
		mysql:  mysql,
		auth:   NewAuthMiddleware(cfg),
	}
	h.init()
	return h
}

type HttpHandler struct {
	config *config.Config
	r      *mux.Router
	mysql  *store.Mysql
	auth   *AuthMiddleware
}

func (h *HttpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.r.ServeHTTP(w, r)
}

func (h *HttpHandler) init() {
	h.r = mux.NewRouter()
	authed := h.r.NewRoute().Subrouter()

	h.r.HandleFunc("/api/teams", h.populateTeamsHandler).Methods("GET")
	h.r.HandleFunc("/api/tiebreaker/inquiry/{date}", h.getTiebreakerHandler).Methods("GET")
	h.r.HandleFunc("/api/tiebreaker/inquiry", h.saveTiebreakerHandler).Methods("POST")
	authed.HandleFunc("/api/tiebreaker/response", h.saveUserTiebreakerHandler).Methods("PUT")
	authed.HandleFunc("/api/picks", h.saveUserPicksHandler).Methods("PUT")
	h.r.HandleFunc("/api/games/{date}", h.populateGamesHandler).Methods("GET")
	h.r.HandleFunc("/api/games", h.updateGamesHandler).Methods("PUT")
	h.r.HandleFunc("/api/games", h.saveGamesHandler).Methods("POST")
	h.r.HandleFunc("/api/v1/auth/login", h.loginHandler).Methods("POST")
	h.r.HandleFunc("/api/v1/auth/register", h.registerHandler).Methods("POST")

	authed.Use(h.auth.Auth)
}

func (h *HttpHandler) populateTeamsHandler(w http.ResponseWriter, r *http.Request) {
	teams, err := h.mysql.GetTeams(r.Context())
	if err != nil {
		http.Error(w, "Failed to get teams", http.StatusInternalServerError)
		return
	}
	vTeams := make([]v1view.Team, 0, len(teams))
	for _, team := range teams {
		vTeams = append(vTeams, v1view.Team{
			ID:   team.ID,
			Name: team.Name,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vTeams)
}

func (h *HttpHandler) saveGamesHandler(w http.ResponseWriter, r *http.Request) {

	var payload v1request.GameList
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	games, err := payload.ToModel()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.mysql.SaveGames(r.Context(), games)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "Games saved successfully!",
	})
}

func (h *HttpHandler) populateGamesHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	date := vars["date"]

	games, err := h.mysql.GetGames(r.Context(), date)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	vGames := make([]v1view.Game, 0, len(games))

	for _, game := range games {
		vGames = append(vGames, v1view.Game{
			ID:     game.ID,
			FavID:  game.FavID,
			DogID:  game.DogID,
			Spread: game.Spread,
		})
	}

	json.NewEncoder(w).Encode(vGames)
}

func (h *HttpHandler) updateGamesHandler(w http.ResponseWriter, r *http.Request) {
	var payload v1request.GameList
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	games, err := payload.ToModel()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.mysql.UpdateGames(r.Context(), games); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "Games updated successfully!",
	})
}

func (h *HttpHandler) saveTiebreakerHandler(w http.ResponseWriter, r *http.Request) {
	var payload v1request.TieBreaker
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tiebreaker := payload.ToModel()

	if err := h.mysql.SaveTiebreaker(r.Context(), tiebreaker); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "Tiebreaker saved successfully!",
	})
}

func (h *HttpHandler) saveUserTiebreakerHandler(w http.ResponseWriter, r *http.Request) {
	var username = r.Header.Get("username")
	var payload v1request.UserTiebreaker
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if the necessary fields are present
	if !payload.Valid() {
		http.Error(w, "Missing required fields in payload", http.StatusBadRequest)
		return
	}

	tb := payload.ToModel(username)

	if err := h.mysql.SaveUserTiebreaker(r.Context(), tb); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "Tiebreaker saved successfully!",
	})
}

func (h *HttpHandler) getTiebreakerHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	date := vars["date"]

	tb, err := h.mysql.GetTiebreaker(r.Context(), date)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := v1view.TieBreaker{
		GameDate:           tb.GameDate,
		TiebreakerQuestion: tb.TiebreakerQuestion,
		ID:                 tb.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *HttpHandler) saveUserPicksHandler(w http.ResponseWriter, r *http.Request) {
	var username = r.Header.Get("username")
	var payload v1request.Picks
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	picks, err := payload.ToModel()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.mysql.SaveUserpicks(r.Context(), picks, username); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "User picks saved successfully!",
	})
}

func (h *HttpHandler) loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds v1request.Login

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Unable to parse request", http.StatusBadRequest)
		return
	}

	// Connect to LDAP
	l, err := ldap.DialURL(h.config.Ldap.Host)
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

	tokenString, err := token.SignedString([]byte(h.config.Jwt.Secret))
	if err != nil {
		http.Error(w, "Failed to generate the token", http.StatusInternalServerError)
		return
	}

	// Create response

	response := v1view.Token{
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

func (h *HttpHandler) registerHandler(w http.ResponseWriter, r *http.Request) {
	var creds v1request.Register

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Unable to parse request", http.StatusBadRequest)
		return
	}

	l, err := ldap.DialURL(h.config.Ldap.Host)
	if err != nil {
		http.Error(w, "Failed to connect to the LDAP server", http.StatusInternalServerError)
		return
	}
	defer l.Close()

	// Bind as the admin to add the new user
	adminPassword := h.config.Ldap.Password
	err = l.Bind("cn=admin,dc=ewnix,dc=net", adminPassword)
	if err != nil {
		http.Error(w, "Failed to bind as admin", http.StatusInternalServerError)
		return
	}

	addUserRequest := ldap.NewAddRequest(fmt.Sprintf("cn=%s,ou=people,dc=ewnix,dc=net", creds.Username), nil)
	addUserRequest.Attribute("objectClass", []string{"inetOrgPerson"}) // Assuming you're using inetOrgPerson
	addUserRequest.Attribute("cn", []string{creds.Username})
	addUserRequest.Attribute("sn", []string{creds.Username})
	addUserRequest.Attribute("mail", []string{creds.Email})
	addUserRequest.Attribute("userPassword", []string{creds.Password})

	err = l.Add(addUserRequest)
	if err != nil {
		http.Error(w, "Failed to add user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Registration successful"))
}
