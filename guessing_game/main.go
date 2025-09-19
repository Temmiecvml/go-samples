package main

import (
	"fmt"
	"math/rand"
	"time"
)

var guess uint32

func generateSecretNumber() uint32 {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	num := uint32(r.Intn(10))
	return num
}

func generateGuess() {
	fmt.Println("Guess a number")
	fmt.Scan(&guess)

}

func main() {
	secretNumber := generateSecretNumber()

	for {
		generateGuess()
		if secretNumber > guess {
			fmt.Println("Too small")
		} else if secretNumber < guess {
			fmt.Println("Too big")
		} else {
			fmt.Println("You win")
			break
		}

	}

}
