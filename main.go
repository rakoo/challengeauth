package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/agl/ed25519"
)

type user struct {
	pub  string
	salt string
}

var users map[string]user

func handleSession(w http.ResponseWriter, r *http.Request) {
	_, err := r.Cookie("auth")
	if err != nil {
		if err != http.ErrNoCookie {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	} else {
		w.WriteHeader(http.StatusOK)
		return
	}

	// No cookie, check the challenge
	auth := r.Header.Get("Authorization")
	if auth != "" {
		ok := checkAuth(auth)
		if ok {
			http.SetCookie(w, &http.Cookie{
				Name:  "auth",
				Value: "ok",
			})
			log.Printf("Successfully authentified %s\n", auth)
			return
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	// No challenge, send it
	pub := r.Header.Get("pub")
	if pub == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_, ok := users[pub]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.Header().Add("WWW-Authenticate", "Challenge "+challenge(pub))
	w.WriteHeader(http.StatusUnauthorized)
}

func challenge(pub string) string {
	u, _ := users[pub]
	var challenge [20]byte
	_, err := rand.Read(challenge[:])
	if err != nil {
		log.Fatalf("Couldn't generate challege: ", err)
	}
	return fmt.Sprintf("salt=%s, challenge=%s", u.salt, hex.EncodeToString(challenge[:]))
}

func checkAuth(auth string) bool {
	authType := strings.TrimSpace(strings.Fields(auth)[0])

	if authType != "Challenge" {
		return false
	}

	rest := strings.Split(strings.TrimPrefix(auth, authType), ",")
	args := map[string]string{}

	for _, field := range rest {
		kv := strings.Split(field, "=")
		if len(kv) != 2 {
			return false
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		args[key] = val
	}

	for _, expected := range []string{"response", "challenge", "pub"} {
		if args[expected] == "" {
			return false
		}
	}

	// Transform to special format
	pubKeySlice, err := hex.DecodeString(args["pub"])
	if err != nil {
		return false
	}
	if len(pubKeySlice) != ed25519.PublicKeySize {
		return false
	}
	var pubKeyArray [ed25519.PublicKeySize]byte
	copy(pubKeyArray[:], pubKeySlice)

	sigSlice, err := hex.DecodeString(args["response"])
	if err != nil {
		return false
	}
	if len(sigSlice) != ed25519.SignatureSize {
		return false
	}
	var sigArray [ed25519.SignatureSize]byte
	copy(sigArray[:], sigSlice)

	return ed25519.Verify(&pubKeyArray, []byte(args["challenge"]), &sigArray)
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	pub := r.URL.Query().Get("pub")
	if pub == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	salt := r.URL.Query().Get("salt")
	if salt == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	users[pub] = user{
		pub:  pub,
		salt: salt,
	}
	log.Printf("Registered %s with salt %s\n", pub, salt)
}

func main() {
	users = make(map[string]user)

	http.HandleFunc("/register", register)
	http.HandleFunc("/session", handleSession)
	err := http.ListenAndServe(":8888", nil)
	if err != nil {
		log.Fatal(err)
	}
}
