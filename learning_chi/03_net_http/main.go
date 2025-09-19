package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"nethttpintro/wiki"
	"regexp"
)

var templates = template.Must(template.ParseFiles("tmpl/edit.html", "tmpl/view.html"))
var validPath = regexp.MustCompile("^/(edit|save|view)/([a-zA-Z0-9]+)$")

func RenderTemplate(w http.ResponseWriter, tmpl string, p *wiki.Page) {
	err := templates.ExecuteTemplate(w, fmt.Sprintf("%s.html", tmpl), p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
}

func saveHandler(w http.ResponseWriter, r *http.Request, title string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body := r.FormValue("body")
	p := &wiki.Page{Title: title, Body: []byte(body)}
	err := p.Save()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/view/"+title, http.StatusFound)
}

func editHandler(w http.ResponseWriter, r *http.Request, title string) {
	p, err := wiki.LoadPage(title)
	if err != nil {
		p = &wiki.Page{Title: title}
	}
	RenderTemplate(w, "edit", p)
}

func viewHandler(w http.ResponseWriter, r *http.Request, title string) {
	p, err := wiki.LoadPage(title)

	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	RenderTemplate(w, "view", p)
}

func makeHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m := validPath.FindStringSubmatch(r.URL.Path)
		if m == nil {
			http.NotFound(w, r)
			return
		}
		// m[2] The title is the second subexpression.
		fn(w, r, m[2])
	}
}

func main() {
	http.HandleFunc("/", handler)
	http.HandleFunc("/view/", makeHandler(viewHandler))
	http.HandleFunc("/edit/", makeHandler(editHandler))
	http.HandleFunc("/save/", makeHandler(saveHandler))
	log.Fatal(http.ListenAndServe(":8080", nil))
}
