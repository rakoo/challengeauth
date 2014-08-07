package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/agl/ed25519"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Need a password!")
	}

	password := os.Args[1]

	// 1. Generate priv/pub keypair
	var salt [20]byte
	_, err := rand.Read(salt[:])
	if err != nil {
		log.Fatal(err)
	}
	hmacker := hmac.New(sha256.New, []byte(password))
	seed := hmacker.Sum(salt[:])

	pub, priv, err := ed25519.GenerateKey(bytes.NewReader(seed))
	if err != nil {
		log.Fatal(err)
	}
	hexPub := hex.EncodeToString(pub[:])
	hexSalt := hex.EncodeToString(salt[:])

	// 2. register
	baseRegisterUrl, err := url.Parse("http://localhost:8888/register")
	if err != nil {
		log.Fatal(err)
	}
	q := baseRegisterUrl.Query()
	q.Set("pub", hexPub)
	q.Set("salt", hexSalt)
	baseRegisterUrl.RawQuery = q.Encode()

	resp, err := http.Post(baseRegisterUrl.String(), "", nil)
	if err != nil {
		log.Fatal(err)
	}

	if resp.StatusCode == http.StatusOK {
		log.Printf("Successfully registered %s\n", hexPub)
	}

	// 3. Get auth params
	req, err := http.NewRequest("GET", "http://localhost:8888/session", nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("pub", hexPub)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		log.Fatalf("Strange: expected 401, got %d", resp.StatusCode)
	}

	// TODO: Is this legal ?
	auth := parseAuth(resp.Header.Get("Www-Authenticate"))
	challengeAuth, ok := auth["Challenge"]
	if !ok {
		log.Fatal("No \"Challenge\" auth in WWW-Authenticate from server")
	}

	challenge, ok := challengeAuth["challenge"]
	if !ok || challenge == "" {
		log.Fatal("No challenge!")
	}

	sig := ed25519.Sign(priv, []byte(challenge))
	hexSig := hex.EncodeToString(sig[:])

	// 4. sign-in
	req, err = http.NewRequest("GET", "http://localhost:8888/session", nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Signing for [%s] with challenge [%s], sig is [%s]\n", hexPub, challenge, hexSig)
	req.Header.Set("Authorization", fmt.Sprintf("Challenge challenge=%s, response=%s, pub=%s", challenge, hexSig, hexPub))

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Failed signing-in: %d\n", resp.StatusCode)
	}

	log.Printf("Successfully authenticated, cookies are: %v\n", resp.Cookies())
}

func parseAuth(raw string) map[string]map[string]string {
	auths := make(map[string]map[string]string)
	fields := strings.Fields(raw)
	var auth map[string]string
	for _, field := range fields {
		kv := strings.Split(field, "=")
		if len(kv) == 1 {
			auth = make(map[string]string)
			auths[kv[0]] = auth
		} else if len(kv) == 2 && auth != nil {
			key := strings.Trim(kv[0], ", ")
			val := strings.Trim(kv[1], ", ")
			auth[key] = val
		} else {
			log.Fatalf("Couldn't parse %s in auth (all auth: [%s])\n", field,
				raw)
		}
	}
	return auths
}
