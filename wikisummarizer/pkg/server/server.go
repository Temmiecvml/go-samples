package server

import (
	"log"
	"net/http"
)

func StartServer(addr string, handler http.Handler) {
	log.Printf("Listening on port %s", addr)
	log.Fatal(http.ListenAndServe(addr, handler))
}
