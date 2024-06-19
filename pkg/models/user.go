package models

import (
	"database/sql"
	"time"
)

type User struct {
	Id           string
	Email        string
	Password     string
	Name         string
	Category     int
	DOB          time.Time //To accept null date columns
	DOBFormatted string
	Bio          string //Handles null strings
	Avatar       sql.NullString
}
