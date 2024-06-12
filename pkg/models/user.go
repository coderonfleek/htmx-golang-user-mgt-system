package models

import (
	"database/sql"
)

type User struct {
	Id       string
	Email    string
	Password string
	Name     string
	Category int
	DOB      sql.NullTime   //To accept null date columns
	Bio      sql.NullString //Handles null strings
	Avatar   sql.NullString
}

//The null properties won't be filled upon registration
