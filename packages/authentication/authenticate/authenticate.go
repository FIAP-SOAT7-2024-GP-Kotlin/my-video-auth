package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type UserRole string

const (
	UserRoleAdmin UserRole = "ADMIN"
	UserRoleUser  UserRole = "USER"
)

type Request struct {
	Email    *string     `json:"email"`
	Password *string     `json:"password"`
	Type     RequestType `json:"type"`
	Token    *string     `json:"token"`
	Role     *UserRole   `json:"role"`
	Id       *uuid.UUID  `json:"id"`
}

type RequestType string

const (
	UserCreation       RequestType = "USER_CREATION"
	UserAuthentication RequestType = "USER_AUTHENTICATION"
	JwtValidation      RequestType = "JWT_VALIDATION"
	GetUser            RequestType = "GET_USER"
	GetUserById        RequestType = "GET_USER_BY_ID"
)

type Response struct {
	StatusCode int               `json:"statusCode,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Token      string            `json:"access_token,omitempty"`
	Message    string            `json:"message,omitempty"`
	Body       interface{}       `json:"body,omitempty"`
}

type Claims struct {
	Email string `json:"email"`
	Role  string `json:"role"`
	jwt.StandardClaims
}

type User struct {
	ID       uuid.UUID
	Email    string
	Password string
	Role     string
}

var (
	config          Config
	ErrNoRequest    = errors.New("no request type provided")
	ErrUserNotFound = errors.New("user not found")
)

type Config struct {
	DatabaseUrl      string
	DatabaseUsername string
	DatabasePassword string
	DatabaseName     string
	DatabaseSchema   string
	JwtKey           string
	Port             string
}

func init() {
	config = Config{
		DatabaseUrl:      getEnv("DATABASE_URL"),
		DatabaseUsername: getEnv("DATABASE_USERNAME"),
		DatabasePassword: getEnv("DATABASE_PASSWORD"),
		DatabaseName:     getEnv("DATABASE_NAME"),
		DatabaseSchema:   getEnv("DATABASE_SCHEMA"),
		JwtKey:           getEnv("JWT_KEY"),
		Port:             getEnv("DATABASE_PORT"),
	}
}

func getEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("%s environment variable is required", key)
	}
	return value
}

func Main(input Request) (*Response, error) {
	switch input.Type {
	case UserCreation:
		err := handleUserCreation(input)
		if err != nil {
			log.Println("Error creating user:", err)
			return &Response{StatusCode: http.StatusInternalServerError, Message: "Error creating user"}, err
		}
		return &Response{StatusCode: http.StatusCreated, Message: "User successfully created"}, nil
	case UserAuthentication:
		response, err := handleAuthentication(input)
		if err != nil {
			log.Println("Error handling authentication:", err)
			return &Response{StatusCode: http.StatusUnauthorized, Message: err.Error()}, err
		}
		return &Response{StatusCode: http.StatusOK, Token: response, Body: map[string]string{"token": response}}, nil
	case JwtValidation:
		claims, err := validateJWT(input.Token)
		if err != nil {
			log.Println("Error validating JWT:", err)
			return &Response{StatusCode: http.StatusUnauthorized, Message: err.Error()}, err
		}
		return &Response{StatusCode: http.StatusOK, Message: fmt.Sprintf("Valid token for email: %s", claims.Email)}, nil
	case GetUser:
		response, err := handleGetUserByEmail(input)
		if err != nil {
			log.Println("Error getting user:", err)
			return &Response{StatusCode: http.StatusNotFound, Message: err.Error()}, err
		}
		return &Response{StatusCode: http.StatusOK, Message: fmt.Sprintf("User found by email: %s, role: %s", response.Email, response.Role), Body: map[string]string{"email": response.Email, "role": response.Role}}, nil
	case GetUserById:
		response, err := handleGetUserById(input)
		if err != nil {
			log.Printf("Error while retrieving user by id", err)
			return &Response{StatusCode: http.StatusNotFound, Message: err.Error()}, err
		}
		return &Response{StatusCode: http.StatusOK, Message: fmt.Sprintf("User found : %s, role: %s", response.Email, response.Role), Body: map[string]string{"email": response.Email, "role": response.Role}}, nil
	default:
		return &Response{StatusCode: http.StatusBadRequest, Message: "Invalid request type"}, ErrNoRequest
	}
}

func handleAuthentication(request Request) (string, error) {
	if request.Email == nil || request.Password == nil {
		return "", fmt.Errorf("email and password are required")
	}
	db, err := setupDbConnection()
	if err != nil {
		log.Println("Error connecting to database:", err)
		return "", err
	}
	defer db.Close()

	user, err := findUserByEmail(db, *request.Email)
	if err != nil {
		log.Println("Error finding user by Email:", err)
		return "", err
	}

	if user == nil {
		log.Println("User not found for cpf:", request.Email)
		return "", ErrUserNotFound

	}

	if err := verifyPassword(user.Password, *request.Password); err != nil {
		return "", fmt.Errorf("invalid password: %v", http.StatusUnauthorized)
	}

	token, err := generateJWT(db, *request.Email)
	if err != nil {
		log.Println("Error generating JWT token:", err)
		return "", err
	}
	return token, nil
}

func handleUserCreation(request Request) error {
	if request.Email == nil || request.Password == nil || request.Role == nil {
		return fmt.Errorf("email, password and role are required")
	}

	if *request.Role != UserRoleAdmin && *request.Role != UserRoleUser {
		return fmt.Errorf("invalid role: %s", *request.Role)
	}

	db, err := setupDbConnection()
	if err != nil {
		log.Println("Error connecting to database:", err)
		return err
	}
	defer db.Close()

	user, err := findUserByEmail(db, *request.Email)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.Println("Error finding user by Email:", err)
		return err
	}

	if user != nil {
		return fmt.Errorf("user already exists")
	}

	if err := createUser(db, request); err != nil {
		log.Println("Error creating user:", err)
		return err
	}

	return nil
}

func setupDbConnection() (*sql.DB, error) {
	connectionString := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s search_path=%s sslmode=require",
		config.DatabaseUrl, config.Port, config.DatabaseUsername, config.DatabasePassword, config.DatabaseName, config.DatabaseSchema)
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		log.Println("Error opening database connection:", err)
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return db, nil
}

func handleGetUserByEmail(request Request) (*User, error) {
	if request.Email == nil {
		return nil, fmt.Errorf("email is required")
	}
	db, err := setupDbConnection()
	if err != nil {
		log.Println("Error connecting to database:", err)
		return nil, err
	}
	defer db.Close()

	user, err := findUserByEmail(db, *request.Email)
	if err != nil {
		log.Println("Error finding user by CPF:", err)
		return nil, err
	}

	if user == nil {
		return nil, ErrUserNotFound
	}

	return user, nil
}

func handleGetUserById(request Request) (*User, error) {
	if request.Id == nil {
		return nil, fmt.Errorf("email is required")
	}
	db, err := setupDbConnection()
	if err != nil {
		log.Println("Error connecting to database:", err)
		return nil, err
	}
	defer db.Close()

	user, err := findUserById(db, *request.Id)
	if err != nil {
		log.Println("Error finding user by CPF:", err)
		return nil, err
	}

	if user == nil {
		return nil, ErrUserNotFound
	}

	return user, nil
}

func findUserByEmail(db *sql.DB, email string) (*User, error) {
	var user User
	const findUserByEmailQuery = "SELECT id, email, password, role FROM \"user\" WHERE email = $1"
	err := db.QueryRow(findUserByEmailQuery, email).Scan(&user.ID, &user.Email, &user.Password, &user.Role)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to query user by email: %w", err)
	}
	return &user, nil
}

func findUserById(db *sql.DB, id uuid.UUID) (*User, error) {
	var user User
	const findUserByEmailQuery = "SELECT id, email, password, role FROM \"user\" WHERE id = $1"
	err := db.QueryRow(findUserByEmailQuery, id.String()).Scan(&user.ID, &user.Email, &user.Password, &user.Role)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to query user by email: %w", err)
	}
	return &user, nil
}

func createUser(db *sql.DB, request Request) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*request.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	const query = "INSERT INTO \"user\" (id, email, password, role) VALUES ($1, $2, $3, $4)"
	_, err = db.Exec(query, uuid.New(), request.Email, hashedPassword, request.Role)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	fmt.Printf("User successfully created with email: %s\n", *request.Email)
	return nil
}

func verifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func generateJWT(db *sql.DB, email string) (string, error) {
	user, err := findUserByEmail(db, email)
	if err != nil {
		return "", fmt.Errorf("failed to find user by email: %w", err)
	}
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Email: email,
		Role:  user.Role,
		StandardClaims: jwt.StandardClaims{
			Subject:   email,
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: expirationTime.Unix(),
			Issuer:    "my_key",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.JwtKey))
}

func validateJWT(tokenString *string) (*Claims, error) {
	if tokenString == nil {
		return nil, fmt.Errorf("token is required")
	}
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(*tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(config.JwtKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
