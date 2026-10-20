package main

import (
	"log"

	"MyContainer/internal/payloadsync"
	poseidonfunctions "MyContainer/poseidon/agentfunctions"
)

func main() {
	// load up the agent functions directory so all the init() functions execute
	poseidonfunctions.Initialize()
	// sync over definitions and listen
	if err := payloadsync.StartAndRunForever("poseidon", poseidonfunctions.SupportedCryptoSchemes()); err != nil {
		log.Fatal(err)
	}
}
