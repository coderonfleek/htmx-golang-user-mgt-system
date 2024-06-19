package handlers

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/coderonfleek/user-mgt-system/pkg/models"
	"github.com/coderonfleek/user-mgt-system/pkg/repository"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

func Homepage(db *sql.DB, templates *template.Template, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		user, _ := CheckLoggedIn(w, r, store, db)

		/* session, err := store.Get(r, "logged-in-user")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Check if the user_id is present in the session
		userID, ok := session.Values["user_id"]
		if !ok {
			//w.Header().Set("HX-Location", "/login")
			fmt.Println("Redirecting to /login")
			http.Redirect(w, r, "/login", http.StatusSeeOther) // 303 required for the redirect to happen

			return
		}

		// Fetch user details from the database
		user, err := repository.GetUserById(db, userID.(string)) // Ensure that user ID handling is appropriate for your ID data type
		if err != nil {
			if err == sql.ErrNoRows {
				// No user found, possibly handle by clearing the session or redirecting to login
				session.Options.MaxAge = -1 // Clear the session
				session.Save(r, w)
				//w.Header().Set("HX-Location", "/login")
				fmt.Println("Redirecting to /login")
				http.Redirect(w, r, "/login", http.StatusSeeOther)

				return
			}
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		} */

		// User is logged in and found, render the homepage with user data
		if err := templates.ExecuteTemplate(w, "home.html", user); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}
}

func Editpage(db *sql.DB, templates *template.Template, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		user, _ := CheckLoggedIn(w, r, store, db)

		if err := templates.ExecuteTemplate(w, "editProfile", user); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}
}

func UpdateProfileHandler(db *sql.DB, tmpl *template.Template, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Retrieve the session
		currentUserProfile, userID := CheckLoggedIn(w, r, store, db)

		// Parse the form
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		var errorMessages []string

		// Collect and validate form data
		name := r.FormValue("name")
		bio := r.FormValue("bio")
		dobStr := r.FormValue("dob")

		if name == "" {
			errorMessages = append(errorMessages, "Name is required.")
		}

		if dobStr == "" {
			errorMessages = append(errorMessages, "Date of birth is required.")
		}

		dob, err := time.Parse("2006-01-02", dobStr)
		if err != nil {
			errorMessages = append(errorMessages, "Invalid date format.")
		}

		// Handle validation errors
		if len(errorMessages) > 0 {
			tmpl.ExecuteTemplate(w, "autherrors", errorMessages)
			return
		}

		// Create user struct
		user := models.User{
			Id:       userID,
			Name:     name,
			DOB:      dob,
			Bio:      bio,
			Category: currentUserProfile.Category,
			Avatar:   currentUserProfile.Avatar,
		}

		// Call the repository function to update the user
		if err := repository.UpdateUser(db, userID, user); err != nil {
			errorMessages = append(errorMessages, "Failed to update user")
			tmpl.ExecuteTemplate(w, "autherrors", errorMessages)
			log.Fatal(err)

			return
		}

		// Redirect or return success
		// Set HX-Location header and return 204 No Content status
		w.Header().Set("HX-Location", "/")
		w.WriteHeader(http.StatusNoContent)
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

func LoginHandler(db *sql.DB, templates *template.Template, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		email := r.FormValue("email")
		password := r.FormValue("password")

		var errorMessages []string

		// Basic validation
		if email == "" {
			errorMessages = append(errorMessages, "Email is required.")
		}
		if password == "" {
			errorMessages = append(errorMessages, "Password is required.")
		}

		if len(errorMessages) > 0 {
			templates.ExecuteTemplate(w, "autherrors", errorMessages)
			return
		}

		// Retrieve user by email
		user, err := repository.GetUserByEmail(db, email)
		if err != nil {
			if err == sql.ErrNoRows {
				errorMessages = append(errorMessages, "Invalid email or password")
				templates.ExecuteTemplate(w, "autherrors", errorMessages)
				return
			}

			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Compare the hashed password from the DB with the provided password
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			errorMessages = append(errorMessages, "Invalid email or password")
			templates.ExecuteTemplate(w, "autherrors", errorMessages)

			return
		}

		// Create session and authenticate the user
		session, err := store.Get(r, "logged-in-user")
		if err != nil {
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		session.Values["user_id"] = user.Id
		if err := session.Save(r, w); err != nil {
			http.Error(w, "Error saving session", http.StatusInternalServerError)
			return
		}

		// Set HX-Location header and return 204 No Content status
		w.Header().Set("HX-Location", "/")
		w.WriteHeader(http.StatusNoContent)
	}
}

func CheckLoggedIn(w http.ResponseWriter, r *http.Request, store *sessions.CookieStore, db *sql.DB) (models.User, string) {

	session, err := store.Get(r, "logged-in-user")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return models.User{}, ""
	}

	// Check if the user_id is present in the session
	userID, ok := session.Values["user_id"]
	if !ok {
		//w.Header().Set("HX-Location", "/login")
		fmt.Println("Redirecting to /login")
		http.Redirect(w, r, "/login", http.StatusSeeOther) // 303 required for the redirect to happen
		/* w.Header().Set("HX-Location", "/login")
		w.WriteHeader(http.StatusNoContent) */
		return models.User{}, ""
	}

	// Fetch user details from the database
	user, err := repository.GetUserById(db, userID.(string)) // Ensure that user ID handling is appropriate for your ID data type
	if err != nil {
		if err == sql.ErrNoRows {
			// No user found, possibly handle by clearing the session or redirecting to login
			session.Options.MaxAge = -1 // Clear the session
			session.Save(r, w)
			//w.Header().Set("HX-Location", "/login")
			fmt.Println("Redirecting to /login")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			/* w.Header().Set("HX-Location", "/login")
			w.WriteHeader(http.StatusNoContent) */
			return models.User{}, ""
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return models.User{}, ""
	}

	return user, userID.(string)
}
