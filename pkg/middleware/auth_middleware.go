package middleware

import (
	"context"
	"crypto/subtle"
	"net/http"
	"os"

	"github.com/andrescris/firestore/lib/firebase/auth"
	"github.com/gin-gonic/gin"
)

// APIKeyAuthMiddleware se encarga de verificar el API Key estática en las solicitudes.
func APIKeyAuthMiddleware() gin.HandlerFunc {
	requiredAPIKey := os.Getenv("API_KEY")
	if requiredAPIKey == "" {
		// Esto es un log fatal porque el servidor no puede operar de forma segura sin esta clave.
		panic("Error: La variable de entorno API_KEY no está definida.")
	}

	return func(c *gin.Context) {
		clientKey := c.GetHeader("X-API-KEY")
		if subtle.ConstantTimeCompare([]byte(clientKey), []byte(requiredAPIKey)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "API Key inválida o no proporcionada."})
			return
		}
		c.Next()
	}
}


func SessionAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID := c.GetHeader("X-Session-ID")
		clientSubdomain := c.GetHeader("X-Client-Subdomain")

		if sessionID == "" || clientSubdomain == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Faltan las cabeceras X-Session-ID o X-Client-Subdomain."})
			return
		}

		// 1. Validar la sesión
		sessionInfo, err := auth.ValidateSession(context.Background(), sessionID)
		if err != nil || !sessionInfo.Active {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Sesión inválida o expirada."})
			return
		}

		// 2. Validar permiso para el subdominio
		claims := sessionInfo.Claims
		
		// Un admin tiene acceso a todo
		if role, ok := claims["role"].(string); ok && role == "admin" {
			// Si es admin, guardamos los datos y continuamos
			c.Set("uid", sessionInfo.UID)
			c.Set("claims", claims)
			c.Set("subdomain", clientSubdomain) // El admin opera en el subdominio que elija
			c.Next()
			return
		}

		// Para usuarios normales, verificamos que tengan el subdominio en su lista
		userSubdomains, ok := claims["subdomain"].([]interface{})
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Acceso denegado. No tienes subdominios asignados."})
			return
		}

		isAllowed := false
		for _, sub := range userSubdomains {
			if subStr, ok := sub.(string); ok && subStr == clientSubdomain {
				isAllowed = true
				break
			}
		}

		if !isAllowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Acceso denegado. No tienes permiso para este subdominio."})
			return
		}

		// 3. Si todo está bien, guardamos los datos en el contexto
		c.Set("uid", sessionInfo.UID)
		c.Set("claims", claims)
		c.Set("subdomain", clientSubdomain) // Guardamos el subdominio validado
		
		c.Next()
	}
}

func SubdomainMatchMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Obtenemos el subdominio del claim del usuario (inyectado por SessionAuthMiddleware)
		userSubdomain, userHasSubdomain := c.Get("subdomain")

		// Obtenemos el subdominio que el cliente dice estar visitando
		clientSubdomain := c.GetHeader("X-Client-Subdomain")

		// Si el usuario tiene un subdominio asignado, deben coincidir
		if userHasSubdomain {
			// Antes de comparar, verificamos si el usuario es admin.
			// Un admin puede no tener la restricción.
			claimsValue, _ := c.Get("claims")
			claims, _ := claimsValue.(map[string]interface{})
			role, _ := claims["role"].(string)

			// Si no es admin y los subdominios no coinciden, denegamos el acceso.
			if role != "admin" && userSubdomain.(string) != clientSubdomain {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "Acceso denegado. No tienes permiso para acceder a este subdominio.",
				})
				return
			}
		}
		
		c.Next()
	}
}

func AdminOnlyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. Obtenemos los claims que el 'SessionAuthMiddleware' ya guardó en el contexto.
		claimsValue, exists := c.Get("claims")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Acceso denegado. No se encontraron claims en la sesión."})
			return
		}

		// 2. Convertimos los claims a un mapa para poder leerlos.
		claims, ok := claimsValue.(map[string]interface{})
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "El formato de los claims es incorrecto."})
			return
		}

		// 3. Verificamos si el rol es 'admin'.
		role, _ := claims["role"].(string)
		if role != "admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Acceso denegado. Se requiere rol de administrador."})
			return
		}

		// 4. Si todo es correcto, permitimos que la petición continúe.
		c.Next()
	}
}

