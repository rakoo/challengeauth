package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/agl/ed25519"
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

// The static handlers
var (
	staticHandler         = http.FileServer(http.Dir("www"))
	registerStaticHandler = http.StripPrefix("/register", staticHandler)
	loginStaticHandler    = http.StripPrefix("/login", staticHandler)
)

// Signing stuff
var signingPubKey, signingKey = getSigningKey()

func getSigningKey() (*[ed25519.PublicKeySize]byte, *[ed25519.PrivateKeySize]byte) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return pub, priv
}

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

		login := r.Form.Get("login")
		token := r.Form.Get("token")
		sig := r.Form.Get("sig")
		if token == "" && sig == "" {
			replyWithChallenge(w, login)
		} else {
			checkAuth(w, login, token, sig)
		}
		return
	default:
		http.Error(w, "Verb not understood", http.StatusBadRequest)
	}
}

func replyWithChallenge(w http.ResponseWriter, login string) {

	var defaultSaltRaw [32]byte
	rand.Read(defaultSaltRaw[:])
	salt := base64.StdEncoding.EncodeToString(defaultSaltRaw[:])

	u, ok := users[login]
	if ok {
		salt = u.Salt
	}

	var token [32]byte
	rand.Read(token[:])
	sig := ed25519.Sign(signingKey, token[:])

	signedTokenRaw := make([]byte, len(token)+len(sig))
	copy(signedTokenRaw, token[:])
	copy(signedTokenRaw[len(token):], sig[:])
	signedToken := base64.StdEncoding.EncodeToString(signedTokenRaw)

	err := json.NewEncoder(w).Encode(challenge{signedToken, salt})
	if err != nil {
		log.Println(err)
		http.Error(w, "Error with your request", http.StatusBadRequest)
	}
}

func checkAuth(w http.ResponseWriter, login, token, sig string) {
	tokenRaw, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		log.Println(err)
		http.Error(w, "Error with your request", http.StatusBadRequest)
		return
	}

	sigRaw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		log.Println(err)
		http.Error(w, "Error with your request", http.StatusBadRequest)
		return
	}

	var sigForVerif [ed25519.SignatureSize]byte
	copy(sigForVerif[:], sigRaw[:])

	user, ok := users[login]
	if !ok {
		http.Error(w, "Bad auth", http.StatusUnauthorized)
		return
	}

	userPubKeyRaw, err := base64.StdEncoding.DecodeString(user.PubKey)
	if err != nil || len(userPubKeyRaw) != ed25519.PublicKeySize {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	var userPubKey [ed25519.PublicKeySize]byte
	copy(userPubKey[:], userPubKeyRaw)

	ok = ed25519.Verify(&userPubKey, tokenRaw, &sigForVerif)
	if ok {
		if len(tokenRaw) != 32+ed25519.SignatureSize {
			http.Error(w, "Bad token", http.StatusUnauthorized)
			return
		}
		ourToken := tokenRaw[:len(tokenRaw)-ed25519.SignatureSize]
		ourSig := tokenRaw[len(tokenRaw)-ed25519.SignatureSize:]
		var ourSigForVerif [ed25519.SignatureSize]byte
		copy(ourSigForVerif[:], ourSig)

		ok = ed25519.Verify(signingPubKey, ourToken, &ourSigForVerif)
		if !ok {
			http.Error(w, "Bad token", http.StatusUnauthorized)
			return
		}
		log.Printf("%s just logged in\n", login)
	} else {
		log.Printf("%s didn't log in", login)
		http.Error(w, "Bad auth", http.StatusUnauthorized)
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
