package authentication

import (
	"os"
	"context"
	"go.uber.org/fx"
	"log"
	"net/http"
	"github.com/gorilla/mux"
	"github.com/codegangsta/negroni"
	"golang.org/x/oauth2"

	oidc "github.com/coreos/go-oidc"
)

var Module = fx.Options(

)

type Authenticator struct {
	Provider *oidc.Provider
	Config   oauth2.Config
	Ctx      context.Context
}

func NewAuthenticator() (*Authenticator, error) {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, "https://" + os.Getenv("AUTH0_DOMAIN") + "/")
	if err != nil {
		log.Printf("failed to get provider: %v", err)
		return nil, err
	}

	conf := oauth2.Config{
		ClientID:     os.Getenv("AUTH0_CLIENT_ID"),
		ClientSecret: os.Getenv("AUTH0_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("AUTH0_CALLBACK_URL"),
		Endpoint: 	  provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
	}

	return &Authenticator{
		Provider: provider,
		Config:   conf,
		Ctx:      ctx,
	}, nil
}

func StartServer(a AuthenticationInterface){
	r := mux.NewRouter()

	r.HandleFunc("/", a.HomeHandler)
	r.HandleFunc("/login", a.LoginHandler)
	r.HandleFunc("/logout", a.LogoutHandler)
	r.HandleFunc("/callback", a.CallbackHandler)
	r.Handle("/user", negroni.New(
		negroni.HandlerFunc(a.IsAuthenticated),
		negroni.Wrap(http.HandlerFunc(a.UserHandler)),
	))
	r.PathPrefix("/public/").Handler(http.StripPrefix("/public/", http.FileServer(http.Dir("public/"))))
	http.Handle("/", r)
	log.Print("Server listening on http://localhost:3000/")
	log.Fatal(http.ListenAndServe("0.0.0.0:3000", nil))
}