package v1request

type Login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
