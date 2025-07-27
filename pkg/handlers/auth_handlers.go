package handlers

import (
	"net/http"

	"github.com/andrescris/firestore/lib/firebase/auth" // Asegúrate que el path sea correcto
	"github.com/gin-gonic/gin"
)

// Login maneja la solicitud de inicio de sesión.
func Login(c *gin.Context) {
	var req auth.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "El email y la contraseña son requeridos."})
		return
	}

	// Llama a la función Login de tu librería
	loginResponse, err := auth.Login(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ocurrió un error durante el login", "details": err.Error()})
		return
	}

	if !loginResponse.Success {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": loginResponse.Message})
		return
	}

	// ### CAMBIO IMPORTANTE AQUÍ ###
	// En lugar de devolver el objeto 'loginResponse' completo (que causa el error de fecha),
	// construimos una respuesta limpia solo con los datos que el cliente necesita.
	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"message":      loginResponse.Message,
		"session_id":   loginResponse.SessionID,
		"custom_token": loginResponse.CustomToken,
		"expires_at":   loginResponse.ExpiresAt,
		"uid":          loginResponse.User.UID, // Devolvemos solo el UID en lugar del objeto User completo
		"claims":       loginResponse.Claims,
	})
}

// Logout maneja el cierre de sesión.
func Logout(c *gin.Context) {
	// El middleware de sesión ya validó y guardó estos datos en el contexto
	sessionID, _ := c.Get("session_id")
	uid, _ := c.Get("uid")

	req := auth.LogoutRequest{
		UID:       uid.(string),
		SessionID: sessionID.(string),
	}

	// Llama a la función Logout de tu librería
	logoutResponse, err := auth.Logout(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ocurrió un error durante el logout", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, logoutResponse)
}