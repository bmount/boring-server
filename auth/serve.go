package auth

import (
	"fmt"
	"net/http"
)

type Rule struct {
	Admin        bool
	TrustExactly int
	Trust        int
}

var loginHandler *http.ServeMux

func loginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		templates.ExecuteTemplate(w, "login_form.tmpl", nil)
		return
	}
	if r.Method == "POST" {
		//invite := r.FormValue("invite")

	}
	//http.Error(w, "not allowed", http.StatusMethodNotAllowed)
}

func Wrap(h http.Handler, rule *Rule) http.Handler {
	if loginHandler == nil {
		loginHandler = http.NewServeMux()
		loginHandler.Handle("/", http.HandlerFunc(Login))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := getSession(r)
		if rule.Admin && !u.Admin {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if u.Admin {
			h.ServeHTTP(w, r)
			return
		}
		if rule.TrustExactly == u.Trust && rule.TrustExactly != 0 {
			h.ServeHTTP(w, r)
			return
		}
		if u.Trust >= 1 && rule.Trust >= 1 && u.Trust >= rule.Trust {
			fmt.Println("trust condition met")
			h.ServeHTTP(w, r)
			return
		}
		loginHandler.ServeHTTP(w, r)
	})
}
