// pkg/handlers/utility_handlers.go
package handlers

import (
	"context"
	"log"
	"net/http"

	"github.com/andrescris/firestore/lib/firebase"
	"github.com/andrescris/firestore/lib/firebase/auth"
	"github.com/gin-gonic/gin"
)

// GetStats obtiene estadísticas generales del servidor
func GetStats(c *gin.Context) {
	ctx := context.Background()
	
	// Obtener estadísticas básicas
	userCount, err := auth.GetUserCount(ctx)
	if err != nil {
		log.Printf("Error getting user count: %v", err)
		userCount = -1
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"stats": gin.H{
			"project_id":  firebase.GetProjectID(),
			"user_count":  userCount,
			"server_time": "2025-06-08", // Usar time.Now() en producción
		},
	})
}

// ApiDocs muestra la documentación de la API
func ApiDocs(c *gin.Context) {
	docs := `
🔥 Firebase API Documentation

BASE URL: http://localhost:8080/api/v1

=== USUARIOS ===
POST   /users                    - Crear usuario
GET    /users                    - Listar usuarios (?limit=10&page_token=xxx)
GET    /users/:uid               - Obtener usuario por UID
GET    /users/email/:email       - Obtener usuario por email
PUT    /users/:uid               - Actualizar usuario
DELETE /users/:uid               - Eliminar usuario
POST   /users/:uid/claims        - Establecer claims personalizados

=== DOCUMENTOS ===
POST   /collections/:collection/documents     - Crear documento
GET    /collections/:collection/documents     - Listar documentos
GET    /collections/:collection/documents/:id - Obtener documento
PUT    /collections/:collection/documents/:id - Actualizar documento
DELETE /collections/:collection/documents/:id - Eliminar documento

=== CONSULTAS ===
POST   /collections/:collection/query         - Consultar con filtros

=== UTILIDADES ===
GET    /stats                                 - Estadísticas del servidor

Ejemplos en Postman Collection disponibles en: 
https://github.com/andrescris/firestore/tree/main/examples/postman
`

	c.String(http.StatusOK, docs)
}