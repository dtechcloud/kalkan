// Command inventory is the inventory service of the vulnapp fixture.
package main

import (
	"crypto/md5"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
	"time"
)

const noteTemplate = "Note for {{.}}"

var (
	db          *sql.DB
	mux         = http.NewServeMux()
	reportDir   = filepath.Join(os.Getenv("VULNAPP_DATA"), "reports")
	returnPages = map[string]string{"cart": "/cart", "orders": "/orders"}
	statusFeeds = map[string]string{
		"payments": "https://status.payments.vulnapp.internal/feed.json",
		"shipping": "https://status.shipping.vulnapp.internal/feed.json",
	}
)

func writeRows(w http.ResponseWriter, rows *sql.Rows) {
	defer rows.Close()
	for rows.Next() {
		var id int
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return
		}
		fmt.Fprintf(w, "%d\t%s\n", id, html.EscapeString(name))
	}
}

func searchItems(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, err := db.Query(fmt.Sprintf("SELECT id, name FROM items WHERE name = '%s'", name))
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	writeRows(w, rows)
}

func filterItems(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, err := db.Query("SELECT id, name FROM items WHERE name = ?", name)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	writeRows(w, rows)
}

func pingHost(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if err := exec.Command("sh", "-c", "ping -c 1 "+host).Run(); err != nil {
		http.Error(w, "host unreachable", http.StatusBadGateway)
		return
	}
	fmt.Fprintln(w, "reachable")
}

func pingHostV2(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if err := exec.Command("ping", "-c", "1", "--", host).Run(); err != nil {
		http.Error(w, "host unreachable", http.StatusBadGateway)
		return
	}
	fmt.Fprintln(w, "reachable")
}

func fetchURL(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func fetchFeed(w http.ResponseWriter, r *http.Request) {
	feedURL, ok := statusFeeds[r.URL.Query().Get("feed")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	resp, err := http.Get(feedURL)
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func searchPage(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<h2>Results for %s</h2>", query)
}

func searchPageCompact(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<h2>Results for %s</h2>", html.EscapeString(query))
}

func continueLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
}

func continueLogout(w http.ResponseWriter, r *http.Request) {
	target, ok := returnPages[r.URL.Query().Get("page")]
	if !ok {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func downloadReport(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join(reportDir, r.URL.Query().Get("name")))
}

func downloadSummary(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join(reportDir, filepath.Base(r.URL.Query().Get("name"))))
}

func renderNote(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.New("note").Parse(r.FormValue("template"))
	if err != nil {
		http.Error(w, "bad template", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	tmpl.Execute(w, r.FormValue("name"))
}

func renderNoteV2(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.New("note").Parse(noteTemplate)
	if err != nil {
		http.Error(w, "bad template", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	tmpl.Execute(w, r.FormValue("name"))
}

func hashPassword(password string) string {
	sum := md5.Sum([]byte(password))
	return hex.EncodeToString(sum[:])
}

func hashPasswordV2(password string, salt []byte) (string, error) {
	key, err := pbkdf2.Key(sha256.New, password, salt, 600000, 32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

func register(w http.ResponseWriter, r *http.Request) {
	digest := hashPassword(r.FormValue("password"))
	if _, err := db.Exec("INSERT INTO users (name, pw) VALUES (?, ?)", r.FormValue("name"), digest); err != nil {
		http.Error(w, "register failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func changePassword(w http.ResponseWriter, r *http.Request) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		http.Error(w, "entropy failure", http.StatusInternalServerError)
		return
	}
	digest, err := hashPasswordV2(r.FormValue("password"), salt)
	if err != nil {
		http.Error(w, "hash failure", http.StatusInternalServerError)
		return
	}
	if _, err := db.Exec("UPDATE users SET pw = ?, salt = ? WHERE id = ?", digest, hex.EncodeToString(salt), 1); err != nil {
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func withPartnerCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		next.ServeHTTP(w, r)
	})
}

func withStoreCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://shop.vulnapp.internal")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		next.ServeHTTP(w, r)
	})
}

func main() {
	var err error
	db, err = sql.Open("mysql", os.Getenv("VULNAPP_DSN"))
	if err != nil {
		log.Fatal(err)
	}
	mux.HandleFunc("/items/search", searchItems)
	mux.HandleFunc("/items/filter", filterItems)
	mux.HandleFunc("/tools/ping", pingHost)
	mux.HandleFunc("/tools/ping/v2", pingHostV2)
	mux.HandleFunc("/tools/fetch", fetchURL)
	mux.HandleFunc("/tools/feed", fetchFeed)
	mux.HandleFunc("/search", searchPage)
	mux.HandleFunc("/search/compact", searchPageCompact)
	mux.HandleFunc("/login/continue", continueLogin)
	mux.HandleFunc("/logout/continue", continueLogout)
	mux.HandleFunc("/reports", downloadReport)
	mux.HandleFunc("/reports/summary", downloadSummary)
	mux.HandleFunc("/notes", renderNote)
	mux.HandleFunc("/notes/v2", renderNoteV2)
	mux.HandleFunc("/register", register)
	mux.HandleFunc("/password", changePassword)
	mux.Handle("/partner/items", withPartnerCORS(http.HandlerFunc(filterItems)))
	mux.Handle("/store/items", withStoreCORS(http.HandlerFunc(filterItems)))
	server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}
