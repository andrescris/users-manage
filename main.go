// main.go
package main

import (
	"log"
	"net/http"

	"github.com/andrescris/alimedia/pkg/handlers"
	"github.com/andrescris/alimedia/pkg/middleware"
	"github.com/andrescris/firestore/lib/firebase"
	"github.com/gin-gonic/gin"
)

func main() {
	// Inicializar Firebase
	if err := firebase.InitFirebaseFromEnv(); err != nil {
		log.Fatalf("Error initializing Firebase: %v", err)
	}
	defer firebase.Close()

	// Configurar Gin
	r := gin.Default()

	// Middleware para CORS (permitir Postman)
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-KEY, X-Session-ID, X-Client-Subdomain")
		
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		
		c.Next()
	})

	// Health check
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "🔥 Firebase API Server",
			"status":  "running",
			"project": firebase.GetProjectID(),
		})
	})

	// Configurar rutas
	setupRoutes(r)

	log.Println("🚀 API Server iniciado en http://localhost:8080")
	log.Println("📖 Documentación en http://localhost:8080/api/v1/docs")
	
	r.Run(":8080")
}

func setupRoutes(r *gin.Engine) {
	// Rutas de API
	api := r.Group("/api/v1")
	api.Use(middleware.APIKeyAuthMiddleware())
	{

   authGroup := api.Group("/auth")
        {
            // El login solo necesita la API Key general
            authGroup.POST("/login", handlers.Login)
            // El logout necesita la API Key Y una sesión válida
            authGroup.POST("/logout", middleware.SessionAuthMiddleware(), handlers.Logout)
        }

		// === USUARIOS ===
		users := api.Group("/users")
		{
			users.POST("/", handlers.CreateUser)           // Crear usuario
			users.GET("/", middleware.SessionAuthMiddleware(), middleware.AdminOnlyMiddleware(), handlers.ListUsers)
			users.GET("/:uid", handlers.GetUser)          // Obtener usuario por UID
			users.GET("/email/:email", handlers.GetUserByEmail) // Obtener usuario por email
			users.PUT("/:uid", handlers.UpdateUser)        // Actualizar usuario
			users.DELETE("/:uid", handlers.DeleteUser)     // Eliminar usuario
			users.POST("/:uid/claims", middleware.SessionAuthMiddleware(), middleware.AdminOnlyMiddleware(), handlers.SetUserClaims)
			//users.POST("/:uid/claims", middleware.SessionAuthMiddleware(), handlers.SetUserClaims)
			users.PATCH("/:uid/claims", middleware.SessionAuthMiddleware(), middleware.AdminOnlyMiddleware(), handlers.UpdateUserClaims)
		}

		// === DOCUMENTOS ===
		docs := api.Group("/collections/:collection/documents")
		docs.Use(middleware.SessionAuthMiddleware())        // Validar sesión
		docs.Use(middleware.SubdomainMatchMiddleware())     // Validar acceso al subdominio
		{
			docs.POST("/", handlers.CreateDocument)        
			docs.GET("/", handlers.ListDocuments)          
			docs.GET("/:id", handlers.GetDocument)         
			docs.PUT("/:id", handlers.UpdateDocument)      
			docs.DELETE("/:id", handlers.DeleteDocument)   
		}

		// === CONSULTAS ===
		 api.POST("/collections/:collection/query", 
            middleware.SessionAuthMiddleware(), 
            middleware.SubdomainMatchMiddleware(), // <-- Añadimos el nuevo middleware
            handlers.QueryDocuments,
        )
		
		// === UTILIDADES ===
		api.GET("/stats", handlers.GetStats) // Estadísticas generales

       
	}
	
	// Agregar ruta de documentación
	r.GET("/api/v1/docs", handlers.ApiDocs)
}