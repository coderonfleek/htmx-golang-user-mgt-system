package main

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"

	"github.com/coderonfleek/user-mgt-system/pkg/handlers"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var tmpl *template.Template
var db *sql.DB

var Store = sessions.NewCookieStore([]byte("usermanagementsecret"))

func init() {
	tmpl, _ = template.ParseGlob("templates/*.html")

	//Set up Sessions
	Store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600 * 3,
		HttpOnly: true,
	}

}

func initDB() {
	var err error
	// Initialize the db variable
	db, err = sql.Open("mysql", "root:root@(127.0.0.1:3333)/usermanagement?parseTime=true")
	if err != nil {
		log.Fatal(err)
	}

	// Check the database connection
	if err = db.Ping(); err != nil {
		log.Fatal(err)
	}
}

func main() {

	gRouter := mux.NewRouter()

	//Setup MySQL
	initDB()
	defer db.Close()

	gRouter.HandleFunc("/", handlers.Homepage(db, tmpl, Store))

	gRouter.HandleFunc("/register", handlers.RegisterPage(db, tmpl)).Methods("GET")

	gRouter.HandleFunc("/register", handlers.RegisterHandler(db, tmpl)).Methods("POST")

	gRouter.HandleFunc("/login", handlers.LoginPage(db, tmpl)).Methods("GET")

	gRouter.HandleFunc("/login", handlers.LoginHandler(db, tmpl, Store)).Methods("POST")

	http.ListenAndServe(":4000", gRouter)

}
