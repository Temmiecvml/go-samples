package wiki

import (
	"os"
	"strings"
)

type Page struct {
	Title string
	Body  []byte
}

func (p *Page) Save() error {
	filename := p.Title + ".txt"
	return os.WriteFile(filename, p.Body, 0600)
}

func LoadPage(title string) (*Page, error) {
	title = strings.Trim(title, "/")
	filename := title + ".txt"
	body, err := os.ReadFile("data/" + filename)
	if err != nil {
		return nil, err
	}
	return &Page{Title: title, Body: body}, nil
}
