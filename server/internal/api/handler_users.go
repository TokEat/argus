package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/user/dddd-server/internal/db"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// ---------------- 鉴权引擎 --------------------
func authLogin(c *gin.Context) {
	var req struct {
		TenantID string `json:"tenant_id"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Username = strings.TrimSpace(req.Username)

	// Backward compatibility: if username is empty but tenant_id is provided, use tenant_id as username
	// This supports the legacy login flow where tenant_id was used as the username
	loginUsername := req.Username
	if loginUsername == "" {
		if req.TenantID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username or tenant_id is required"})
			return
		}
		loginUsername = req.TenantID
	}

	// 尝试从数据库校验用户
	var user db.User
	var tenantClaim string
	var roleClaim string
	var userIDClaim string
	var expAuthorizedClaim bool
	if err := db.DB.Where("username = ?", loginUsername).First(&user).Error; err == nil {
		// 数据库有此用户，校验密码
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Wrong password"})
			return
		}
		if user.Status != "active" {
			c.JSON(http.StatusForbidden, gin.H{"error": "User is disabled"})
			return
		}
		tenantClaim = user.TenantID
		roleClaim = user.Role
		if roleClaim == "" {
			roleClaim = "viewer"
		}
		userIDClaim = fmt.Sprintf("%d", user.ID)
		expAuthorizedClaim = user.ExpAuthorized
	} else if errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Wrong password"})
		return
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query user"})
		return
	}

	// 颁发 Token（包含角色信息）
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"tenant_id":      tenantClaim,
		"role":           roleClaim,
		"role_base":      baseRoleForToken(tenantClaim, roleClaim),
		"user_id":        userIDClaim,
		"exp_authorized": expAuthorizedClaim,
		"exp":            time.Now().Add(time.Hour * 72).Unix(),
	})
	tokenString, err := token.SignedString(currentJWTSecret())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sign"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func listUsers(c *gin.Context) {
	tenantID := currentTenantID(c)
	var users []db.User
	db.DB.Where("tenant_id = ?", tenantID).Order("created_at DESC").Find(&users)

	type UserResp struct {
		ID            uint   `json:"id"`
		TenantID      string `json:"tenant_id"`
		Username      string `json:"username"`
		Role          string `json:"role"`
		Status        string `json:"status"`
		ExpAuthorized bool   `json:"exp_authorized"`
		CreatedAt     string `json:"created_at"`
		UpdatedAt     string `json:"updated_at"`
	}

	resp := make([]UserResp, 0, len(users))
	for _, u := range users {
		resp = append(resp, UserResp{
			ID:            u.ID,
			TenantID:      u.TenantID,
			Username:      u.Username,
			Role:          u.Role,
			Status:        u.Status,
			ExpAuthorized: u.ExpAuthorized,
			CreatedAt:     u.CreatedAt.Format(time.RFC3339),
			UpdatedAt:     u.UpdatedAt.Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, resp)
}

func createUser(c *gin.Context) {
	var req struct {
		Username      string `json:"username" binding:"required"`
		Password      string `json:"password" binding:"required"`
		Role          string `json:"role"`
		TenantID      string `json:"tenant_id"`
		ExpAuthorized bool   `json:"exp_authorized"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenantID := currentTenantID(c)
	role, ok := normalizeUserRoleForTenant(tenantID, req.Role)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role must be a built-in role or an existing custom role"})
		return
	}
	if req.TenantID != "" && req.TenantID != tenantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot create user for another tenant"})
		return
	}
	req.TenantID = tenantID

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user := db.User{
		TenantID:      req.TenantID,
		Username:      req.Username,
		PasswordHash:  string(hash),
		Role:          role,
		Status:        "active",
		ExpAuthorized: req.ExpAuthorized,
	}
	if err := db.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "id": user.ID})
}

func updateUser(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)
	var req struct {
		Role          string `json:"role"`
		Status        string `json:"status"`
		Password      string `json:"password"`
		ExpAuthorized *bool  `json:"exp_authorized"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := map[string]interface{}{}
	if req.Role != "" {
		role, ok := normalizeUserRoleForTenant(tenantID, req.Role)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "role must be a built-in role or an existing custom role"})
			return
		}
		updates["role"] = role
	}
	if req.Status != "" {
		status, ok := normalizeUserStatus(req.Status)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "status must be one of: active, disabled"})
			return
		}
		updates["status"] = status
	}
	if req.Password != "" {
		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		updates["password_hash"] = string(hash)
	}
	if req.ExpAuthorized != nil {
		updates["exp_authorized"] = *req.ExpAuthorized
	}

	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No fields to update"})
		return
	}

	res := db.DB.Model(&db.User{}).Where("id = ? AND tenant_id = ?", id, tenantID).Updates(updates)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func deleteUser(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)
	res := db.DB.Delete(&db.User{}, "id = ? AND tenant_id = ?", id, tenantID)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
