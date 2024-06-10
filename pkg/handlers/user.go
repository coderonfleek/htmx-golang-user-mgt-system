package handlers

import (
	"database/sql"
	"html/template"
	"net/http"
	"strconv"

	"github.com/coderonfleek/user-mgt-system/pkg/models"
	"github.com/coderonfleek/user-mgt-system/pkg/repository"
	"golang.org/x/crypto/bcrypt"
)

func Homepage(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		tmpl.ExecuteTemplate(w, "home.html", nil)

	}
}

func LoginPage(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		tmpl.ExecuteTemplate(w, "login", nil)

	}
}

func RegisterPage(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		tmpl.ExecuteTemplate(w, "register", nil)

	}
}

func RegisterHandler(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user models.User
		var errorMessages []string

		// Parse the form data
		r.ParseForm()

		user.Name = r.FormValue("name")
		user.Email = r.FormValue("email")
		user.Password = r.FormValue("password")
		user.Category, _ = strconv.Atoi(r.FormValue("category"))

		// Basic validation
		if user.Name == "" {
			errorMessages = append(errorMessages, "Name is required.")
		}
		if user.Email == "" {
			errorMessages = append(errorMessages, "Email is required.")
		}
		if user.Password == "" {
			errorMessages = append(errorMessages, "Password is required.")
		}

		if len(errorMessages) > 0 {
			tmpl.ExecuteTemplate(w, "autherrors", errorMessages)
			return
		}

		// Hash the password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			errorMessages = append(errorMessages, "Failed to hash password.")
			tmpl.ExecuteTemplate(w, "autherrors", errorMessages)
			return
		}
		user.Password = string(hashedPassword)

		// Create user in the database
		err = repository.CreateUser(db, user)
		if err != nil {
			errorMessages = append(errorMessages, "Failed to create user: "+err.Error())
			tmpl.ExecuteTemplate(w, "autherrors", errorMessages)
			return
		}

		/* // Successfully created user
		// Redirect to login on successful registration
		http.Redirect(w, r, "/login", http.StatusSeeOther) */
		// Instead of redirecting, set HTTP status code to 204 (not content) and set 'HX-Location' header
		w.Header().Set("HX-Location", "/login")
		w.WriteHeader(http.StatusNoContent)
	}
}
