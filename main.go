package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type user struct {
	Login  string
	Salt   string // Base64-ed
	PubKey string // Base64-ed
}

// A map from login to user
var users map[string]*user = make(map[string]*user)

func main() {
	http.Handle("/", staticHandler)
	http.HandleFunc("/register", handleRegister)
	http.HandleFunc("/login", handleLogin)

	log.Println("Listening on :8080...")
	http.ListenAndServe(":8080", nil)
}

var staticHandler = http.FileServer(http.Dir("www"))
var registerStaticHandler = http.StripPrefix("/register", staticHandler)
var loginStaticHandler = http.StripPrefix("/login", staticHandler)

type challenge struct {
	Token string `json:"token"`
	Salt  string `json:"salt"`
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		loginStaticHandler.ServeHTTP(w, r)
	case "POST":
		err := r.ParseForm()
		if err != nil || r.Form.Get("login") == "" {
			log.Println(err)
			http.Error(w, "Error with your request", http.StatusBadRequest)
			return
		}

		var tokenRaw [32]byte
		rand.Read(tokenRaw[:])
		token := base64.StdEncoding.EncodeToString(tokenRaw[:])

		var defaultSaltRaw [32]byte
		rand.Read(defaultSaltRaw[:])
		defaultSalt := base64.StdEncoding.EncodeToString(defaultSaltRaw[:])

		login := r.Form.Get("login")
		response := r.Form.Get("response")
		if response == "" {
			u, ok := users[login]
			salt := defaultSalt
			if ok {
				salt = u.Salt
			}
			err := json.NewEncoder(w).Encode(challenge{token, salt})
			if err != nil {
				log.Println(err)
				http.Error(w, "Error with your request", http.StatusBadRequest)
				return
			}
		} else {
		}
	default:
		http.Error(w, "Verb not understood", http.StatusBadRequest)
	}
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		registerStaticHandler.ServeHTTP(w, r)
	case "POST":
		err := r.ParseForm()
		if err != nil {
			log.Println(err)
			http.Error(w, "Error with your request", http.StatusBadRequest)
			return
		}

		if r.Form.Get("login") == "" ||
			r.Form.Get("salt") == "" ||
			r.Form.Get("pubKey") == "" {
			http.Error(w, "Error with your request", http.StatusBadRequest)
			return
		}
		u := user{
			Login:  r.Form.Get("login"),
			Salt:   r.Form.Get("salt"),
			PubKey: r.Form.Get("pubKey"),
		}

		if _, ok := users[u.Login]; ok {
			http.Error(w, fmt.Sprintf("%s already exists", u.Login),
				http.StatusBadRequest)
			return
		}

		users[u.Login] = &u
		log.Printf("%s just registered\n", u.Login)
	default:
		http.Error(w, "Verb not understood", http.StatusBadRequest)
	}
}
