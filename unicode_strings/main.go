package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Person demonstrates JSON marshalling
type Person struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

func main() {
	fmt.Println("=== UTF-8 basics ===")
	utf8Basics()

	fmt.Println("\n=== Normalization (NFC vs NFD) ===")
	normalizationDemo()

	fmt.Println("\n=== JSON marshal/unmarshal (and HTTP example) ===")
	jsonDemo()

	// start a tiny HTTP server that demonstrates writing JSON bytes
	go startHTTPServer()

	fmt.Println("\nServer running at http://localhost:8080/person (press Ctrl+C to stop)")
	select {} // block forever (so the server keeps running)
}

func utf8Basics() {
	ascii := "A"            // U+0041
	threeByte := "€"        // U+20AC (3 bytes in UTF-8)
	emoji := "🤖"            // robot face (4 bytes in UTF-8)
	mixed := "A€🤖"          // mixed string
	decomposed := "e\u0301" // 'e' + combining acute (NFD)
	precomposed := "\u00e9" // 'é' single code point (NFC)

	examples := []string{ascii, threeByte, emoji, mixed, decomposed, precomposed}
	for _, s := range examples {
		fmt.Printf("String: %q\n", s)
		fmt.Printf("  len(s) bytes: %d\n", len(s))                                 // bytes
		fmt.Printf("  utf8.RuneCountInString(s): %d\n", utf8.RuneCountInString(s)) // code points (runes)
		fmt.Printf("  []byte(s) (hex): %x\n", []byte(s))                           // raw bytes hex
		fmt.Println()
	}

	// decode first rune and its byte size
	r, size := utf8.DecodeRuneInString(mixed)
	fmt.Printf("First rune in %q -> rune: %U (%q), size in bytes: %d\n", mixed, r, r, size)

	// rune length required to encode a rune
	fmt.Printf("utf8.RuneLen('%c') = %d bytes\n", '€', utf8.RuneLen('€'))
}

func normalizationDemo() {
	// two strings that look identical when printed, but different code point sequences:
	sNFC := "\u00e9"  // U+00E9 : 'é' (precomposed)
	sNFD := "e\u0301" // 'e' + COMBINING ACUTE ACCENT

	fmt.Printf("sNFC bytes (hex): %x; runes: %d\n", []byte(sNFC), utf8.RuneCountInString(sNFC))
	fmt.Printf("sNFD bytes (hex): %x; runes: %d\n", []byte(sNFD), utf8.RuneCountInString(sNFD))

	fmt.Printf("sNFC == sNFD ? %v\n", sNFC == sNFD)

	// Normalize both to NFC and compare
	sNFCnorm := norm.NFC.String(sNFC)
	sNFDnorm := norm.NFC.String(sNFD)
	fmt.Printf("After NFC normalization: equal? %v\n", sNFCnorm == sNFDnorm)
	fmt.Printf("NFC bytes hex: %x\n", []byte(sNFCnorm))

	// Normalize to NFD
	fmt.Printf("NFD bytes hex (from sNFC normalized to NFD): %x\n", []byte(norm.NFD.String(sNFC)))
}

func jsonDemo() {
	p := Person{Name: "Ada", Age: 30}

	// json.Marshal returns []byte (actual bytes of JSON)
	b, err := json.Marshal(p)
	if err != nil {
		log.Fatalf("json.Marshal: %v", err)
	}
	fmt.Printf("json.Marshal -> []byte length: %d; as string: %s\n", len(b), string(b))

	// Unmarshal back to struct
	var p2 Person
	if err := json.Unmarshal(b, &p2); err != nil {
		log.Fatalf("json.Unmarshal: %v", err)
	}
	fmt.Printf("Unmarshalled struct: %+v\n", p2)

	// Alternatively, you can write JSON directly to an io.Writer (e.g., http.ResponseWriter)
	// using json.NewEncoder(w).Encode(p) — that streams bytes and avoids creating an intermediate []byte.
}

func startHTTPServer() {
	p := Person{Name: "Ada", Age: 30}
	http.HandleFunc("/person", func(w http.ResponseWriter, r *http.Request) {
		// set content-type and write JSON bytes
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		// Option A: json.NewEncoder streams the JSON bytes to the client
		if err := json.NewEncoder(w).Encode(p); err != nil {
			http.Error(w, "encoding error", http.StatusInternalServerError)
		}

		// Option B (commented): you could also do:
		// b, _ := json.Marshal(p)
		// w.Write(b)
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}
