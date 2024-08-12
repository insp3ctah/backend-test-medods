package main

import (
	"log"
	"medods-test/controllers"
	"medods-test/initializers"
	"net/http"
	"os"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDB()
}

func main() {
	port := os.Getenv("HTTP_PORT")

	http.HandleFunc("/auth", controllers.AuthHandler)
	http.HandleFunc("/refresh", controllers.RefreshHandler)

	log.Fatal(http.ListenAndServe(port, nil))
}
