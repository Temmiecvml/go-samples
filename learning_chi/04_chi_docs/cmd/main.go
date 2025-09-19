package main

import (
	"github.com/temmie/learning_chi/04_chi_docs/internal/routes"
	"github.com/temmie/learning_chi/04_chi_docs/pkg/server"
)

func main() {
	r := routes.NewRouter()
	server.StartServer(":3000", r)
}
