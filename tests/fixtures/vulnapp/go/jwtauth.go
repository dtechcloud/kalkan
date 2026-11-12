//go:build jwtauth

// The account endpoints need the golang-jwt module. Build them with -tags jwtauth.

package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte(os.Getenv("VULNAPP_JWT_KEY"))

func init() {
	mux.HandleFunc("/account", accountClaims)
	mux.HandleFunc("/account/v2", accountClaimsV2)
}

func accountClaims(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	token, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		http.Error(w, "bad token", http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(token.Claims)
}

func accountClaimsV2(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	token, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		return jwtKey, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !token.Valid {
		http.Error(w, "bad token", http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(token.Claims)
}
