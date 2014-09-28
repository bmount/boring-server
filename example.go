package main

import (
	"./auth"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
)

var (
	firstRun = flag.Bool("first_run", false, "print an initial admin invitation")
	listenOn = flag.String("listen_on", "127.0.0.1:9090", "host:port")
)

// Wrappable admin rule:
var adminRule = &auth.Rule{Admin: true}

// Wrappable "logged in" rule
var sharedByInvitation = &auth.Rule{Trust: 5}

func main() {
	flag.Parse()

	// initialize with a local db at ~/.config/boring-server/...
	// use auth.NewWithOpts for non-defaults
	err := auth.New()
	if err != nil {
		panic(err)
	}

	if *firstRun {
		// can only be run once, initial user name will be 'admin',
		// password set on invitation acceptance
		fmt.Println(auth.FirstRunInvitation())
	}

	// Usually, we're just a static server
	http.Handle("/", http.HandlerFunc(generallyPublic))

	// Viewers of /admin/... have to be admins
	http.Handle("/admin/", auth.Wrap(http.HandlerFunc(showToAdmins), adminRule))

	// These files are shared:
	http.Handle("/file-share/", http.FileServer(http.Dir("./file-share")))

	// These files are private to admins:
	http.Handle("/private-files/", auth.Wrap(http.FileServer(
		http.Dir("./private-files/")), adminRule))

	// Viewing /amigos/... requires an invite with trust >= 5
	http.Handle("/amigos/", auth.Wrap(http.HandlerFunc(amigos),
		&auth.Rule{Trust: 5}))

	// A nice HTTP API we put behind our auth layer
	var couchDB *httputil.ReverseProxy
	couchUrl, _ := url.Parse("http://localhost:5984")
	couchDB = httputil.NewSingleHostReverseProxy(couchUrl)
	http.Handle("/couchdb/", auth.Wrap(http.StripPrefix("/couchdb/", couchDB),
		adminRule))

	http.ListenAndServe(*listenOn, nil)
}

func generallyPublic(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "hello")
	return
}

func showToAdmins(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "hello admin")
	return
}

func amigos(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "el club de los inútiles")
	return
}

func printInvite(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	admin := r.FormValue("admin") == "true"
	trust, _ := strconv.Atoi(r.FormValue("trust"))
	_, invitation, err := auth.NewUserInvitation(email, admin, trust)
	if err != nil {
		http.Error(w, "unable to generate invitation", http.StatusInternalServerError)
		return
	}
	invite := make(map[string]string)
	invite["invitation"] = invitation
	bits, err := json.Marshal(&invitation)
	if err != nil {
		http.Error(w, "unable to generate invitation", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, string(bits))
	return
}

func dropAllKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method == "DELETE" {
		err := auth.ResetKeys()
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "OK! All sessions and pending invitations cancelled.\n")
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}
