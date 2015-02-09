package main

import (
	"log"
	"net/http"
	"strings"
)

func main() {
	http.Handle("/", staticHandler)
	http.HandleFunc("/register", handleRegister)

	log.Println("Listening on :8080...")
	http.ListenAndServe(":8080", nil)
}

var staticHandler = http.FileServer(http.Dir("www"))
var registerStaticHandler = http.StripPrefix("/register", staticHandler)

func handleRegister(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if !strings.HasSuffix(r.URL.Path, "register.html") {
			r.URL.Path = r.URL.Path + "/register.html"
		}
		registerStaticHandler.ServeHTTP(w, r)
	case "POST":
		err := r.ParseForm()
		if err != nil {
			log.Println(err)
			http.Error(w, "Error with your request", http.StatusBadRequest)
		}
		log.Println(r.PostForm)
	default:
		http.Error(w, "Verb not understood", http.StatusBadRequest)
	}

}
