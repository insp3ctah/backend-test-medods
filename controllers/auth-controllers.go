package controllers

import (
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"log"
	"math/rand"
	"medods-test/initializers"
	"medods-test/models"
	"net/http"
	"net/smtp"
	"strconv"
	"sync"
	"time"
)

var JwtRefreshSignKey = []byte("secret_key_close_ur_eyes_pls")
var JwtAccessSignKey = []byte("hope_i_ll_get_the_job")
var refresh_duration time.Duration = time.Hour * 720
var access_duration time.Duration = time.Hour * 24

func SendMail(s string) error {
	auth := smtp.PlainAuth("",
		"i-get-job@gmail.com",
		"passwith16charsforgmail",
		"smtp.gmail.com",
	)

	msg := "hello ur ip changed to " + s

	err := smtp.SendMail(
		"smtp.gmail.com:587",
		auth,
		"i-get-job@gmail.com",
		[]string{"receiver@gmail.com"},
		[]byte(msg),
	)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func GetSyncString(n int) string {
	alphabet := []byte("o23oi12u3oi21hkj41nejwqheklqh3l12hkj15j5lj2gvk34g31l234k6hj34y209444")
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(b)
}

func ReverseString(str string) (res string) {
	for _, v := range str {
		res = string(v) + res
	}
	return
}

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	ip_addr_cookie, err := r.Cookie("id_addr")
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	ip_addr := ip_addr_cookie.Value

	cred_str, ok := r.URL.Query()["guid"]
	if !ok || len(cred_str[0]) <= 0 {
		log.Println("no guid parsed")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	guid := cred_str[0]

	var wg sync.WaitGroup
	wg.Add(2)
	errChan := make(chan error, 2)

	var accessToken, refreshToken string

	guid_uint, err := strconv.ParseUint(guid, 10, 64)
	if err != nil {
		log.Println("cant parse guid into num", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	syncString := GetSyncString(32)

	go func() {
		defer wg.Done()

		claims := models.CustomJWTClaims{
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(refresh_duration).Unix(),
			},
			GUID:       guid_uint,
			ClientIP:   ip_addr,
			SyncString: syncString,
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

		s, err := token.SignedString(JwtRefreshSignKey)
		if err != nil {
			log.Println("cant sign token", err)
			errChan <- err
			return
		} else {
			refreshToken = s
		}

		refreshHash, err := bcrypt.GenerateFromPassword([]byte(ReverseString(refreshToken)), bcrypt.DefaultCost)
		if err != nil {
			log.Println("cant crypt token", err)
			errChan <- err
			return
		}

		userToken := models.RefreshUserToken{
			GUID:      guid_uint,
			TokenHash: string(refreshHash),
			ClientIP:  ip_addr,
		}

		initializers.DB.Create(&userToken)
	}()

	go func() {
		defer wg.Done()

		claims := models.CustomJWTClaims{
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(access_duration).Unix(),
			},
			GUID:       guid_uint,
			ClientIP:   ip_addr,
			SyncString: syncString,
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

		s, err := token.SignedString(JwtAccessSignKey)
		if err != nil {
			log.Println("cant sign token", err)
			errChan <- err
		} else {
			accessToken = s
		}
	}()

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Expires:  time.Now().Add(access_duration),
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Expires:  time.Now().Add(refresh_duration),
		HttpOnly: true,
	})

	w.WriteHeader(http.StatusOK)
}

func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	ip_addr_cookie, err := r.Cookie("id_addr")
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	ip_addr := ip_addr_cookie.Value
	accessTokenCookie, err := r.Cookie("access_token")
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	refreshTokenCookie, err := r.Cookie("refresh_token")
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	accessToken := accessTokenCookie.Value
	refreshToken := refreshTokenCookie.Value

	access_claims := &models.CustomJWTClaims{}
	token, err := jwt.ParseWithClaims(accessToken, access_claims, func(token *jwt.Token) (interface{}, error) {
		return JwtAccessSignKey, nil
	})
	if err != nil || !token.Valid {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	refresh_claims := &models.CustomJWTClaims{}
	token, err = jwt.ParseWithClaims(accessToken, refresh_claims, func(token *jwt.Token) (interface{}, error) {
		return JwtRefreshSignKey, nil
	})
	if err != nil || !token.Valid {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if access_claims.SyncString != refresh_claims.SyncString {
		log.Println("tokens from different pairs")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var storedToken models.RefreshUserToken
	if err := initializers.DB.Where("guid = ?", access_claims.GUID).First(&storedToken).Error; err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedToken.TokenHash), []byte(refreshToken))
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if storedToken.ClientIP != ip_addr {
		err := SendMail(ip_addr)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	guid := storedToken.GUID

	var wg sync.WaitGroup
	wg.Add(3)
	errChan := make(chan error, 2)

	syncString := GetSyncString(32)

	go func() {
		defer wg.Done()

		claims := models.CustomJWTClaims{
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(refresh_duration).Unix(),
			},
			GUID:       guid,
			ClientIP:   ip_addr,
			SyncString: syncString,
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

		s, err := token.SignedString(JwtRefreshSignKey)
		if err != nil {
			log.Println("cant sign token", err)
			errChan <- err
			return
		} else {
			refreshToken = s
		}

		refreshHash, err := bcrypt.GenerateFromPassword([]byte(ReverseString(refreshToken)), bcrypt.DefaultCost)
		if err != nil {
			log.Println("cant crypt token", err)
			errChan <- err
			return
		}

		userToken := models.RefreshUserToken{
			GUID:      guid,
			TokenHash: string(refreshHash),
			ClientIP:  ip_addr,
		}

		initializers.DB.Create(&userToken)
	}()

	go func() {
		defer wg.Done()

		claims := models.CustomJWTClaims{
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(access_duration).Unix(),
			},
			GUID:       guid,
			ClientIP:   ip_addr,
			SyncString: syncString,
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

		s, err := token.SignedString(JwtAccessSignKey)
		if err != nil {
			log.Println("cant sign token", err)
			errChan <- err
		} else {
			accessToken = s
		}
	}()

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Expires:  time.Now().Add(access_duration),
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Expires:  time.Now().Add(refresh_duration),
		HttpOnly: true,
	})

	w.WriteHeader(http.StatusOK)
}
