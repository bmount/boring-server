package auth

import (
	"code.google.com/p/go.crypto/bcrypt"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
)

var templates = template.Must(template.ParseGlob("templates/**.tmpl"))

func LoginByName(name, givenPw string) (error, *User) {
	u := &User{UniqueName: name}
	err := u.Load()
	if err != nil {
		return errors.New("unauthorized"), nil
	}
	authed := bcrypt.CompareHashAndPassword([]byte(u.EncryptedPassword), []byte(givenPw))
	if authed == nil {
		return authed, u
	}
	return authed, nil
}

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		err := templates.ExecuteTemplate(w, "login_form.tmpl", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}

	if r.Method == "POST" {
		chosenName := r.FormValue("chosen_name")
		pw := r.FormValue("password")
		authFail, u := LoginByName(chosenName, pw)
		if authFail != nil {
			http.Redirect(w, r, "failed-password", 307)
			return
		} else {
			err := u.setSession(w)
			if err != nil {
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			} else {
				http.Redirect(w, r, "/", 302)
				return
			}
		}
	}

	if r.Method == "DELETE" {
		u := &User{}
		u.overwriteSession(w)
		http.Redirect(w, r, "/", 302)
	}
}

func Signup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		_ = templates.ExecuteTemplate(w, "sign_up.tmpl", nil)
	case "POST":
		chosenName := r.FormValue("chosen_name")
		invitation := r.FormValue("invite")
		if chosenName == "" || invitation == "" {
			http.Redirect(w, r, "/", 302)
		}
		invite := decode(invitation)
		if invite == nil {
			http.Redirect(w, r, "/", 302)
			return
		}
		var u *User
		err := json.Unmarshal(invite, &u)
		if err != nil {
			http.Error(w, "expired or invalid invitation", http.StatusUnauthorized)
			return
		}
		password := r.FormValue("password")
		if password == "" {
			http.Redirect(w, r, "/", 302)
			return
		}
		err = u.Save()
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		_ = u.setSession(w)
		http.Redirect(w, r, "/", 302)
		return
	}
}
