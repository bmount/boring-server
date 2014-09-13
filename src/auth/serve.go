package auth

import (
	"net/http"
)

type Rule struct {
	Trust int
	Admin bool
}

func Wrap(h http.Handler, rule Rule) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := getSession(r)
		if u.Admin {
			h.ServeHTTP(w, r)
			return
		}
		if u.Trust >= 1 && rule.Trust >= 1 && u.Trust >= rule.Trust {
			h.ServeHTTP(w, r)
			return
		}
	})
}
