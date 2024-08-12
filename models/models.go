package models

import (
	"github.com/dgrijalva/jwt-go"
	"gorm.io/gorm"
)

type RefreshUserToken struct {
	gorm.Model
	GUID      uint64
	TokenHash string
	ClientIP  string
}

type CustomJWTClaims struct {
	jwt.StandardClaims
	GUID       uint64 `json:"sub"`
	ClientIP   string `json:"client_ip"`
	SyncString string `json:"sync_string"`
}
