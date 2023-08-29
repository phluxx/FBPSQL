package v1handler

import (
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/phluxx/FBPSQL/internal/config"
)

type AuthMiddleware struct {
	cfg *config.Config
}

func NewAuthMiddleware(cfg *config.Config) *AuthMiddleware {
	return &AuthMiddleware{
		cfg: cfg,
	}
}

func (a *AuthMiddleware) Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		tokenString := r.Header.Get("Authorization")
		if len(tokenString) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Missing Authorization Header"))
			return
		}
		tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
		claims, err := a.verifyToken(tokenString)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Error verifying JWT token: " + err.Error()))
			return
		}
		username := claims.(jwt.MapClaims)["username"].(string)

		r.Header.Set("username", username)

		next.ServeHTTP(w, r)
	})
}

func (a *AuthMiddleware) verifyToken(tokenString string) (jwt.Claims, error) {
	signingKey := []byte(a.cfg.Jwt.Secret)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return signingKey, nil
	})
	if err != nil {
		return nil, err
	}
	return token.Claims, err
}
