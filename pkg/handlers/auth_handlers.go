package handlers

import (
	"net/http"

	"github.com/andrescris/firestore/lib/firebase"
	"github.com/andrescris/firestore/lib/firebase/auth" // Asegúrate que el path sea correcto
	"github.com/gin-gonic/gin"
)

// RequestOTP maneja la solicitud de un nuevo código OTP.
func RequestOTP(c *gin.Context) {
	var req firebase.RequestOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "El email es requerido."})
		return
	}
	res, err := auth.RequestOTP(c.Request.Context(), req)
	if err != nil || !res.Success {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": res.Message})
		return
	}
	c.JSON(http.StatusOK, res)
}

func LoginWithOTP(c *gin.Context) {
	var req firebase.LoginWithOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "El email y el OTP son requeridos."})
		return
	}

	loginResponse, err := auth.LoginWithOTP(c.Request.Context(), req)
	if err != nil || !loginResponse.Success {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": loginResponse.Message})
		return
	}
	
	// En lugar de devolver 'loginResponse' completo, creamos una respuesta segura.
	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"message":      loginResponse.Message,
		"session_id":   loginResponse.SessionID,
		"custom_token": loginResponse.CustomToken,
		"expires_at":   loginResponse.ExpiresAt,
		"uid":          loginResponse.User.UID, // Devolvemos solo el UID
		"claims":       loginResponse.Claims,
	})
}


// Logout maneja el cierre de sesión.
func Logout(c *gin.Context) {
	sessionID, _ := c.Get("session_id")
	err := auth.Logout(c.Request.Context(), sessionID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ocurrió un error durante el logout."})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Sesión cerrada correctamente."})
}