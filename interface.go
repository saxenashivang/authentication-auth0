package authentication

import "net/http"

type AuthenticationInterface interface {
	HomeHandler(w http.ResponseWriter, r *http.Request)
	LoginHandler(w http.ResponseWriter, r *http.Request)
	LogoutHandler(w http.ResponseWriter, r *http.Request)
	CallbackHandler(w http.ResponseWriter, r *http.Request)
	IsAuthenticated(w http.ResponseWriter, r *http.Request, next http.HandlerFunc)
	UserHandler(w http.ResponseWriter, r *http.Request)
}