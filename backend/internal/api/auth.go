package api

import (
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"vscan-mohesr/internal/config"
	"vscan-mohesr/internal/models"
)

var jwtSecret []byte

func init() {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "vscan-mohesr-secret-change-in-production"
	}
	jwtSecret = []byte(secret)
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string      `json:"token"`
	User  models.User `json:"user"`
}

func Login(c *fiber.Ctx) error {
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	var user models.User
	if err := config.DB.Where("username = ?", req.Username).First(&user).Error; err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Invalid username or password"})
	}

	if !user.IsActive {
		return c.Status(403).JSON(fiber.Map{"error": "Account is disabled"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Invalid username or password"})
	}

	// Generate JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"role":     user.Role,
		"exp":      time.Now().Add(72 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate token"})
	}

	return c.JSON(LoginResponse{
		Token: tokenString,
		User:  user,
	})
}

func GetProfile(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uint)
	var user models.User
	if err := config.DB.First(&user, userID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}
	return c.JSON(user)
}

func ChangePassword(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uint)

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	var user models.User
	if err := config.DB.First(&user, userID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.OldPassword)); err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Old password is incorrect"})
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to hash password"})
	}

	config.DB.Model(&user).Update("password", string(hashed))
	return c.JSON(fiber.Map{"message": "Password changed successfully"})
}

// --- Admin: User Management ---

func GetUsers(c *fiber.Ctx) error {
	var users []models.User
	config.DB.Order("created_at desc").Find(&users)
	return c.JSON(users)
}

func CreateUser(c *fiber.Ctx) error {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		FullName string `json:"full_name"`
		Email    string `json:"email"`
		Role     string `json:"role"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	if req.Username == "" || req.Password == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Username and password are required"})
	}

	if req.Role == "" {
		req.Role = "user"
	}

	// Check if username exists
	var existing models.User
	if config.DB.Where("username = ?", req.Username).First(&existing).Error == nil {
		return c.Status(409).JSON(fiber.Map{"error": "Username already exists"})
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to hash password"})
	}

	user := models.User{
		Username: req.Username,
		Password: string(hashed),
		FullName: req.FullName,
		Email:    req.Email,
		Role:     req.Role,
		IsActive: true,
	}
	config.DB.Create(&user)
	return c.Status(201).JSON(user)
}

func UpdateUser(c *fiber.Ctx) error {
	id := c.Params("id")
	var user models.User
	if err := config.DB.First(&user, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}

	var req struct {
		FullName string `json:"full_name"`
		Email    string `json:"email"`
		Role     string `json:"role"`
		IsActive *bool  `json:"is_active"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	if req.FullName != "" {
		user.FullName = req.FullName
	}
	if req.Email != "" {
		user.Email = req.Email
	}
	if req.Role != "" {
		user.Role = req.Role
	}
	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}
	if req.Password != "" {
		hashed, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		user.Password = string(hashed)
	}

	config.DB.Save(&user)
	return c.JSON(user)
}

func DeleteUser(c *fiber.Ctx) error {
	id := c.Params("id")
	var user models.User
	if err := config.DB.First(&user, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}
	config.DB.Delete(&user)
	return c.JSON(fiber.Map{"message": "User deleted"})
}

// --- JWT Middleware ---

func AuthRequired() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(401).JSON(fiber.Map{"error": "Authorization header required"})
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid or expired token"})
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid token claims"})
		}

		c.Locals("user_id", uint(claims["user_id"].(float64)))
		c.Locals("username", claims["username"].(string))
		c.Locals("role", claims["role"].(string))

		return c.Next()
	}
}

func AdminRequired() fiber.Handler {
	return func(c *fiber.Ctx) error {
		role, ok := c.Locals("role").(string)
		if !ok || role != "admin" {
			return c.Status(403).JSON(fiber.Map{"error": "Admin access required"})
		}
		return c.Next()
	}
}
