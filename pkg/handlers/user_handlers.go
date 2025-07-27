// pkg/handlers/user_handlers.go
package handlers

import (
	"context"
	"log"
	"net/http"
	"strconv"

	"github.com/andrescris/firestore/lib/firebase"
	"github.com/andrescris/firestore/lib/firebase/auth"
	"github.com/andrescris/firestore/lib/firebase/firestore"
	"github.com/gin-gonic/gin"
)

// CreateUser maneja la creación de nuevos usuarios
func CreateUser(c *gin.Context) {
    // Leer el cuerpo como JSON genérico
    var body map[string]interface{}
    if err := c.ShouldBindJSON(&body); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error":   "Invalid JSON format",
            "details": err.Error(),
        })
        return
    }

    // Validar y extraer project_id
    projectID, ok := body["project_id"].(string)
    if !ok || projectID == "" {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Missing or invalid 'project_id'",
        })
        return
    }

    // Extraer los campos necesarios para crear el usuario
    email, _ := body["email"].(string)
    password, _ := body["password"].(string)
    displayName, _ := body["display_name"].(string)

    if email == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Email is required"})
        return
    }
    if password == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Password is required"})
        return
    }

    // Construir request para Firebase Auth
    request := firebase.CreateUserRequest{
        Email:       email,
        Password:    password,
        DisplayName: displayName,
    }

    ctx := context.Background()
    // 1. Crear usuario en el servicio de Autenticación de Firebase
    user, err := auth.CreateUser(ctx, request)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{
            "error":   "Failed to create user in Auth service",
            "details": err.Error(),
        })
        return
    }

    // === PASO AÑADIDO Y CRUCIAL ===
    // 2. Guardar el hash de la contraseña en Firestore para que el login funcione
    err = auth.StoreUserCredentials(ctx, user.UID, password)
    if err != nil {
        // Si esto falla, el usuario existe pero no podrá loguearse.
        // Es importante devolver un error claro.
        c.JSON(http.StatusInternalServerError, gin.H{
            "error":   "User created in Auth, but failed to store credentials in Firestore.",
            "details": err.Error(),
        })
        return
    }

    // 3. Crear perfil en Firestore con project_id
    profileData := map[string]interface{}{
        "user_id":      user.UID,
        "email":        user.Email,
        "display_name": user.DisplayName,
        "status":       "active",
        "role":         "user",
        "project_id":   projectID,
    }

    profileID, err := firestore.CreateDocument(ctx, "profiles", profileData)
    if err != nil {
        // Esto es menos crítico, por eso solo lo logueamos como advertencia.
        log.Printf("Warning: Failed to create profile for user %s: %v", user.UID, err)
    }

    c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"message": "Usuario y credenciales creados exitosamente",
		"user": gin.H{
			"uid":          user.UID,
			"email":        user.Email,
			"display_name": user.DisplayName,
		},
		"profile": gin.H{
			"profile_id":  profileID,
			"project_id":  projectID,
			"role":        "user",
			"status":      "active",
		},
	})
}

// ListUsers maneja la lista de usuarios con paginación 
func ListUsers(c *gin.Context) {
	// Parámetros de query opcionales
	limitStr := c.DefaultQuery("limit", "10")
	pageToken := c.Query("page_token")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100 // Máximo para evitar sobrecarga
	}

	ctx := context.Background()
	users, nextToken, err := auth.ListUsers(ctx, limit, pageToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to list users",
			"details": err.Error(),
		})
		return
	}

	// Definimos una estructura segura para la respuesta JSON.
	type UserResponse struct {
		UID                 string `json:"uid"`
		Email               string `json:"email"`
		DisplayName         string `json:"display_name"`
		Disabled            bool   `json:"disabled"`
		CreationTimestamp   int64  `json:"creation_timestamp"`
		LastLogInTimestamp  int64  `json:"last_log_in_timestamp"`
	}

	// Creamos un slice para las respuestas limpias.
	responseUsers := make([]UserResponse, 0, len(users))

	// Mapeamos los datos del usuario al formato seguro.
	for _, user := range users {
		responseUsers = append(responseUsers, UserResponse{
			UID:         user.UID,
			Email:       user.Email,
			DisplayName: user.DisplayName,
			Disabled:    user.Disabled,
			// Convertimos el time.Time a un número (milisegundos Unix) que es seguro para JSON.
			// Esto funciona incluso con la fecha del año 57522.
			CreationTimestamp:   user.CreationTime.UnixMilli(),
			LastLogInTimestamp:  user.LastLogInTime.UnixMilli(),
		})
	}

	// Enviamos la respuesta final y segura.
	c.JSON(http.StatusOK, gin.H{
		"success":         true,
		"users":           responseUsers,
		"count":           len(responseUsers),
		"next_page_token": nextToken,
		"has_more":        nextToken != "",
	})
}

// GetUser obtiene un usuario por su UID
func GetUser(c *gin.Context) {
	uid := c.Param("uid")
	if uid == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "UID is required"})
		return
	}

	ctx := context.Background()
	user, err := auth.GetUser(ctx, uid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
			"uid": uid,
		})
		return
	}

	// ### LA CORRECCIÓN ESTÁ AQUÍ ###
	// En lugar de devolver el objeto 'user' directamente, creamos una respuesta segura.
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"user": gin.H{
			"uid":                   user.UID,
			"email":                 user.Email,
			"email_verified":        user.EmailVerified,
			"display_name":          user.DisplayName,
			"photo_url":             user.PhotoURL,
			"disabled":              user.Disabled,
			"creation_timestamp":    user.CreationTime.UnixMilli(), // Convertimos la fecha a un número
			"last_signin_timestamp": user.LastLogInTime.UnixMilli(), // Convertimos la fecha a un número
			"custom_claims":         user.CustomClaims,
		},
	})
}

// GetUserByEmail obtiene un usuario por su email
func GetUserByEmail(c *gin.Context) {
	email := c.Param("email")
	if email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email is required"})
		return
	}

	ctx := context.Background()
	user, err := auth.GetUserByEmail(ctx, email)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
			"email": email,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"user":    user,
	})
}

// UpdateUser actualiza la información de un usuario
func UpdateUser(c *gin.Context) {
	uid := c.Param("uid")
	var request firebase.UpdateUserRequest
	
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid JSON format",
			"details": err.Error(),
		})
		return
	}

	ctx := context.Background()
	user, err := auth.UpdateUser(ctx, uid, request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update user",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"user":    user,
		"message": "User updated successfully",
	})
}

// DeleteUser elimina un usuario
func DeleteUser(c *gin.Context) {
	uid := c.Param("uid")
	if uid == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "UID is required"})
		return
	}

	ctx := context.Background()
	err := auth.DeleteUser(ctx, uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete user",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "User deleted successfully",
		"uid":     uid,
	})
}

// SetUserClaims establece claims y los sincroniza con Firestore
func SetUserClaims(c *gin.Context) {
	uid := c.Param("uid")
	var claims map[string]interface{}
	
	if err := c.ShouldBindJSON(&claims); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
		return
	}

	ctx := context.Background()

	// 1. Establecer los claims en Firebase Authentication (como antes)
	err := auth.SetCustomClaims(ctx, uid, claims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set custom claims in Firebase Auth"})
		return
	}

	// 2. ACTUALIZAR (o crear si no existe) el documento en Firestore
	// Usamos UpdateDocument para asegurarnos de que se sobreescriba si ya existe.
	err = firestore.UpdateDocument(ctx, "user_claims", uid, map[string]interface{}{
		"claims": claims,
	})
	if err != nil {
		// Si Update falla porque el doc no existe, intentamos crearlo (esto lo hace más robusto)
		errCreate := firestore.CreateDocumentWithID(ctx, "user_claims", uid, map[string]interface{}{
			"claims": claims,
		})
		if errCreate != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sync claims to Firestore"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Custom claims set and synchronized successfully",
	})
}

// UpdateUserClaims (PATCH) actualiza claims existentes sin borrar los que no se envían.
func UpdateUserClaims(c *gin.Context) {
	uid := c.Param("uid")
	var newClaims map[string]interface{}
	
	if err := c.ShouldBindJSON(&newClaims); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
		return
	}

	ctx := context.Background()

	// 1. OBTENER los claims actuales del usuario desde Firebase Auth.
	user, err := auth.GetUser(ctx, uid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	
	// Si el usuario no tiene claims, empezamos con un mapa vacío.
	existingClaims := user.CustomClaims
	if existingClaims == nil {
		existingClaims = make(map[string]interface{})
	}

	// 2. FUSIONAR los claims existentes con los nuevos.
	// Los nuevos valores sobreescribirán los viejos si las claves son las mismas.
	for key, value := range newClaims {
		existingClaims[key] = value
	}

	// 3. ESTABLECER el mapa de claims completo y fusionado.
	// Llamamos a la misma función que antes, pero ahora con el set completo de claims.
	err = auth.SetCustomClaims(ctx, uid, existingClaims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set custom claims in Firebase Auth"})
		return
	}

	// 4. Sincronizar con Firestore (como en la otra función)
	err = firestore.UpdateDocument(ctx, "user_claims", uid, map[string]interface{}{
		"claims": existingClaims,
	})
	if err != nil {
		// ... (manejo de error si la sincronización falla)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Claims updated successfully",
		"uid":     uid,
		"claims":  existingClaims, // Devolvemos el resultado final
	})
}

