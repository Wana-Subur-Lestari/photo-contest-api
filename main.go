package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var jwtSecret = []byte("your-secret-key-change-this") // Change in production!

// Models
type User struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}

type Photo struct {
	ID          int       `json:"id"`
	URL         string    `json:"url"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	UploadedBy  int       `json:"uploaded_by"`
	TotalPoints int       `json:"total_points"`
	TimesRanked int       `json:"times_ranked"`
	UploadDate  time.Time `json:"upload_date"`
}

type Ranking struct {
	ID           int       `json:"id"`
	UserID       int       `json:"user_id"`
	PhotoID      int       `json:"photo_id"`
	RankPosition int       `json:"rank_position"`
	Points       int       `json:"points"`
	RankedAt     time.Time `json:"ranked_at"`
}

type Claims struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// Request/Response types
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

type RankingSubmission struct {
	Rankings []struct {
		PhotoID      int `json:"photo_id"`
		RankPosition int `json:"rank_position"`
		Points       int `json:"points"`
	} `json:"rankings"`
}

type PhotoUpload struct {
	URL         string `json:"url"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// Database initialization
func initDB() {
	var err error
	// Update with your MySQL credentials
	user := os.Getenv("MYSQLUSER")
	pass := os.Getenv("MYSQLPASSWORD")
	host := os.Getenv("MYSQLHOST")
	port := os.Getenv("MYSQLPORT")
	dbName := os.Getenv("MYSQLDATABASE")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		user, pass, host, port, dbName,
	)

	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	log.Println("Database connected successfully")
}

// Middleware
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing authorization header", http.StatusUnauthorized)
			return
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Add claims to request context
		r.Header.Set("X-User-ID", strconv.Itoa(claims.UserID))
		r.Header.Set("X-User-Role", claims.Role)
		next.ServeHTTP(w, r)
	})
}

func AdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := r.Header.Get("X-User-Role")
		if role != "admin" {
			http.Error(w, "Admin access required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Auth Handlers
func Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Insert user
	result, err := db.Exec(
		"INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
		req.Username, req.Email, string(hashedPassword),
	)
	if err != nil {
		http.Error(w, "Username or email already exists", http.StatusConflict)
		return
	}

	userID, _ := result.LastInsertId()

	// Create token
	token, err := createToken(int(userID), req.Username, "user")
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	user := User{
		ID:       int(userID),
		Username: req.Username,
		Email:    req.Email,
		Role:     "user",
	}

	json.NewEncoder(w).Encode(AuthResponse{Token: token, User: user})
}

func GetEnv(w http.ResponseWriter, r *http.Request) {
	env := os.Getenv("MYSQLPORT")
	json.NewEncoder(w).Encode(env)
}
func Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var user User
	err := db.QueryRow(
		"SELECT id, username, email, password_hash, role FROM users WHERE username = ?",
		req.Username,
	).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Role)

	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Create token
	token, err := createToken(user.ID, user.Username, user.Role)
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	user.PasswordHash = "" // Don't send hash to client
	json.NewEncoder(w).Encode(AuthResponse{Token: token, User: user})
}

func createToken(userID int, username, role string) (string, error) {
	claims := &Claims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// Photo Handlers
func GetPhotos(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT id, url, title, description, uploaded_by, total_points, times_ranked, upload_date 
		FROM photos 
		ORDER BY upload_date DESC
	`)
	if err != nil {
		http.Error(w, "Failed to fetch photos", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var photos []Photo
	for rows.Next() {
		var p Photo
		if err := rows.Scan(&p.ID, &p.URL, &p.Title, &p.Description, &p.UploadedBy, &p.TotalPoints, &p.TimesRanked, &p.UploadDate); err != nil {
			continue
		}
		photos = append(photos, p)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(photos)
}

func GetPhoto(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var p Photo
	err := db.QueryRow(`
		SELECT id, url, title, description, uploaded_by, total_points, times_ranked, upload_date 
		FROM photos WHERE id = ?
	`, id).Scan(&p.ID, &p.URL, &p.Title, &p.Description, &p.UploadedBy, &p.TotalPoints, &p.TimesRanked, &p.UploadDate)

	if err != nil {
		http.Error(w, "Photo not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}

func UploadPhoto(w http.ResponseWriter, r *http.Request) {
	var req PhotoUpload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	userID, _ := strconv.Atoi(r.Header.Get("X-User-ID"))

	result, err := db.Exec(
		"INSERT INTO photos (url, title, description, uploaded_by) VALUES (?, ?, ?, ?)",
		req.URL, req.Title, req.Description, userID,
	)
	if err != nil {
		http.Error(w, "Failed to upload photo", http.StatusInternalServerError)
		return
	}

	photoID, _ := result.LastInsertId()

	photo := Photo{
		ID:          int(photoID),
		URL:         req.URL,
		Title:       req.Title,
		Description: req.Description,
		UploadedBy:  userID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(photo)
}

func DeletePhoto(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	_, err := db.Exec("DELETE FROM photos WHERE id = ?", id)
	if err != nil {
		http.Error(w, "Failed to delete photo", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// get contest status
func GetStatus(w http.ResponseWriter, r *http.Request) {
	// Example deadline (replace with DB value)
	deadlineStr := "2025-12-14T10:00:00Z"

	deadline, err := time.Parse(time.RFC3339, deadlineStr)
	if err != nil {
		http.Error(w, "invalid deadline format", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()

	if now.After(deadline) {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{
			"is_active": "false",
		})
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"is_active": "true"})
}

// Ranking Handlers
func SubmitRankings(w http.ResponseWriter, r *http.Request) {
	var req RankingSubmission
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	userID, _ := strconv.Atoi(r.Header.Get("X-User-ID"))

	// Validate: 1-5 rankings, unique positions, correct points
	if len(req.Rankings) < 1 || len(req.Rankings) > 5 {
		http.Error(w, "Must rank between 1 and 5 photos", http.StatusBadRequest)
		return
	}

	positions := make(map[int]bool)
	for _, r := range req.Rankings {
		if r.RankPosition < 1 || r.RankPosition > 5 {
			http.Error(w, "Invalid rank position", http.StatusBadRequest)
			return
		}
		if r.Points != (6 - r.RankPosition) {
			http.Error(w, "Points don't match rank position", http.StatusBadRequest)
			return
		}
		if positions[r.RankPosition] {
			http.Error(w, "Duplicate rank positions", http.StatusBadRequest)
			return
		}
		positions[r.RankPosition] = true
	}
	fmt.Println(req.Rankings)
	// Delete existing rankings for this user
	_, err := db.Exec("DELETE FROM rankings WHERE user_id = ?", userID)
	if err != nil {
		http.Error(w, "Failed to clear old rankings", http.StatusInternalServerError)
		return
	}
	// Insert new rankings
	for _, ranking := range req.Rankings {
		_, err := db.Exec(
			"INSERT INTO rankings (user_id, photo_id, rank_position, points) VALUES (?, ?, ?, ?)",
			userID, ranking.PhotoID, ranking.RankPosition, ranking.Points,
		)
		if err != nil {
			fmt.Println(err.Error())
			http.Error(w, "Failed to save ranking", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Rankings submitted successfully"})
}

func GetMyRankings(w http.ResponseWriter, r *http.Request) {
	userID, _ := strconv.Atoi(r.Header.Get("X-User-ID"))

	rows, err := db.Query(`
		SELECT r.id, r.user_id, r.photo_id, r.rank_position, r.points, r.ranked_at,
		       p.title, p.url
		FROM rankings r
		JOIN photos p ON r.photo_id = p.id
		WHERE r.user_id = ?
		ORDER BY r.rank_position ASC
	`, userID)
	if err != nil {
		http.Error(w, "Failed to fetch rankings", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type RankingWithPhoto struct {
		Ranking
		PhotoTitle string `json:"photo_title"`
		PhotoURL   string `json:"photo_url"`
	}

	var rankings []RankingWithPhoto
	for rows.Next() {
		var r RankingWithPhoto
		if err := rows.Scan(&r.ID, &r.UserID, &r.PhotoID, &r.RankPosition, &r.Points, &r.RankedAt, &r.PhotoTitle, &r.PhotoURL); err != nil {
			continue
		}
		rankings = append(rankings, r)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rankings)
}

func GetRankingStatus(w http.ResponseWriter, r *http.Request) {
	userID, _ := strconv.Atoi(r.Header.Get("X-User-ID"))

	var photosRanked int
	err := db.QueryRow("SELECT COUNT(*) FROM rankings WHERE user_id = ?", userID).Scan(&photosRanked)
	if err != nil {
		http.Error(w, "Failed to fetch status", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"photos_ranked": photosRanked,
		"has_ranked":    photosRanked > 0,
	})
}

func GetLeaderboard(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT * FROM photo_leaderboard")
	if err != nil {
		http.Error(w, "Failed to fetch leaderboard", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type LeaderboardEntry struct {
		ID                  int       `json:"id"`
		Title               string    `json:"title"`
		URL                 string    `json:"url"`
		Description         string    `json:"description"`
		TotalPoints         int       `json:"total_points"`
		TimesRanked         int       `json:"times_ranked"`
		AvgPointsPerRanking *float64  `json:"avg_points_per_ranking"`
		UploadedByUsername  string    `json:"uploaded_by_username"`
		UploadDate          time.Time `json:"upload_date"`
	}

	var leaderboard []LeaderboardEntry
	for rows.Next() {
		var entry LeaderboardEntry
		if err := rows.Scan(&entry.ID, &entry.Title, &entry.URL, &entry.Description, &entry.TotalPoints, &entry.TimesRanked, &entry.AvgPointsPerRanking, &entry.UploadedByUsername, &entry.UploadDate); err != nil {
			continue
		}
		leaderboard = append(leaderboard, entry)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(leaderboard)
}

func main() {
	// Load environment variables
	if APP_ENV := os.Getenv("APP_ENV"); APP_ENV != "production" {
		err := godotenv.Load()
		if err != nil {
			log.Fatal("Error loading .env file")
		}
	}
	if secret := os.Getenv("JWT_SECRET"); secret != "" {
		jwtSecret = []byte(secret)
	}

	initDB()
	defer db.Close()

	router := mux.NewRouter()

	// Public routes
	router.HandleFunc("/api/contest/status", GetStatus).Methods("GET")
	router.HandleFunc("/api/auth/register", Register).Methods("POST")
	router.HandleFunc("/api/auth/login", Login).Methods("POST")

	// Protected routes
	api := router.PathPrefix("/api").Subrouter()
	api.Use(AuthMiddleware)

	api.HandleFunc("/photos", GetPhotos).Methods("GET")
	api.HandleFunc("/photos/{id}", GetPhoto).Methods("GET")
	api.HandleFunc("/rankings", SubmitRankings).Methods("POST")
	api.HandleFunc("/rankings/my", GetMyRankings).Methods("GET")
	api.HandleFunc("/rankings/status", GetRankingStatus).Methods("GET")
	api.HandleFunc("/leaderboard", GetLeaderboard).Methods("GET")

	// Admin routes
	admin := api.PathPrefix("/admin").Subrouter()
	admin.Use(AdminMiddleware)
	admin.HandleFunc("/photos", UploadPhoto).Methods("POST")
	admin.HandleFunc("/photos/{id}", DeletePhoto).Methods("DELETE")

	// CORS
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"https://photo-contest-2025.netlify.app", "http://localhost:5173"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	})

	handler := c.Handler(router)

	port := "8080"
	if p := os.Getenv("PORT"); p != "" {
		port = p
	}

	fmt.Printf("Server starting on port %s...\n", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}
