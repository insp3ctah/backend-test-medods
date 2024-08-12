package main

import (
	"medods-test/initializers"
	"medods-test/models"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDB()
}

func main() {
	initializers.DB.AutoMigrate(&models.RefreshUserToken{})
	//initializers.DB.Exec("ALTER SEQUENCE users_id_seq RESTART WITH 1;")
}
