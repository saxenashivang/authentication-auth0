package main

import (
	"alfred/authentication"
)
func main() {
	authentication.Init()
	authentication.StartServer(authentication.NewAuthentication())
}
