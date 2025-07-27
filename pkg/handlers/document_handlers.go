//document_handlers

package handlers

import (
	"context"
	"net/http"

	"github.com/andrescris/firestore/lib/firebase"
	"github.com/andrescris/firestore/lib/firebase/firestore"
	"github.com/gin-gonic/gin"
)

// CreateDocument maneja la creación de nuevos documentos
func CreateDocument(c *gin.Context) {
	collection := c.Param("collection")
	var data map[string]interface{}

	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid JSON format",
			"details": err.Error(),
		})
		return
	}

	// Validar que venga el project_id
	projectID, ok := data["project_id"].(string)
	if !ok || projectID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing or invalid 'project_id'",
		})
		return
	}

	// SEGURIDAD: Forzar el subdomain del usuario autenticado
	userSubdomain, exists := c.Get("subdomain")
	if exists {
		data["subdomain"] = userSubdomain.(string)
	}

	ctx := context.Background()
	docID, err := firestore.CreateDocument(ctx, collection, data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create document",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"success":     true,
		"document_id": docID,
		"collection":  collection,
		"data":        data,
		"message":     "Document created successfully",
	})
}

// GetDocument obtiene un documento específico por ID
func GetDocument(c *gin.Context) {
	collection := c.Param("collection")
	docID := c.Param("id")

	ctx := context.Background()
	doc, err := firestore.GetDocument(ctx, collection, docID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":       "Document not found",
			"collection":  collection,
			"document_id": docID,
		})
		return
	}

	// SEGURIDAD: Verificar que el documento pertenezca al subdominio del usuario
	userSubdomain, exists := c.Get("subdomain")
	if exists {
		docSubdomain, hasSubdomain := doc.Data["subdomain"].(string)
		
		// Si el documento tiene subdomain y no coincide, denegar acceso
		if hasSubdomain && docSubdomain != userSubdomain.(string) {
			// Verificar si es admin (los admins pueden ver todo)
			claims, _ := c.Get("claims")
			claimsMap, _ := claims.(map[string]interface{})
			role, _ := claimsMap["role"].(string)
			
			if role != "admin" {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "No tienes permiso para ver este documento",
				})
				return
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"document": doc,
	})
}

// ListDocuments obtiene todos los documentos de una colección
func ListDocuments(c *gin.Context) {
	collection := c.Param("collection")

	// SEGURIDAD: En lugar de obtener TODOS los documentos, 
	// hacemos una consulta filtrada por subdomain
	userSubdomain, exists := c.Get("subdomain")
	if !exists {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "No se pudo determinar el subdominio del usuario",
		})
		return
	}

	// Verificar si es admin
	claims, _ := c.Get("claims")
	claimsMap, _ := claims.(map[string]interface{})
	role, _ := claimsMap["role"].(string)

	ctx := context.Background()
	var docs []*firebase.Document
	var err error

	if role == "admin" {
		// Los admins pueden ver todos los documentos
		docs, err = firestore.GetAllDocuments(ctx, collection)
	} else {
		// Usuarios normales solo ven sus documentos
		options := firebase.QueryOptions{
			Filters: []firebase.QueryFilter{
				{Field: "subdomain", Operator: "==", Value: userSubdomain.(string)},
			},
		}
		docs, err = firestore.QueryDocuments(ctx, collection, options)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to list documents",
			"details": err.Error(),
		})
		return
	}

	// Convertir los documentos a formato map para la respuesta JSON
	docMaps := make([]map[string]interface{}, len(docs))
	for i, doc := range docs {
		docMaps[i] = doc.Data
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"documents":  docMaps,
		"count":      len(docMaps),
		"collection": collection,
	})
}

// UpdateDocument actualiza un documento existente
func UpdateDocument(c *gin.Context) {
	collection := c.Param("collection")
	docID := c.Param("id")
	var data map[string]interface{}

	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid JSON format",
			"details": err.Error(),
		})
		return
	}

	ctx := context.Background()

	// SEGURIDAD: Verificar que el documento existe y pertenece al usuario
	currentDoc, err := firestore.GetDocument(ctx, collection, docID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":       "Document not found",
			"collection":  collection,
			"document_id": docID,
		})
		return
	}

	// Verificar ownership por subdomain
	userSubdomain, exists := c.Get("subdomain")
	if exists {
		docSubdomain, hasSubdomain := currentDoc.Data["subdomain"].(string)
		
		if hasSubdomain && docSubdomain != userSubdomain.(string) {
			// Verificar si es admin
			claims, _ := c.Get("claims")
			claimsMap, _ := claims.(map[string]interface{})
			role, _ := claimsMap["role"].(string)
			
			if role != "admin" {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "No puedes modificar documentos de otro subdominio",
				})
				return
			}
		}
	}

	// SEGURIDAD: Prevenir que cambien el subdomain via update
	// (solo admins podrían hacerlo, y solo si es necesario)
	if exists {
		claims, _ := c.Get("claims")
		claimsMap, _ := claims.(map[string]interface{})
		role, _ := claimsMap["role"].(string)
		
		if role != "admin" {
			// Usuarios normales no pueden cambiar el subdomain
			delete(data, "subdomain")
		}
	}

	err = firestore.UpdateDocument(ctx, collection, docID, data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to update document",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":     true,
		"message":     "Document updated successfully",
		"collection":  collection,
		"document_id": docID,
	})
}

// DeleteDocument elimina un documento
func DeleteDocument(c *gin.Context) {
	collection := c.Param("collection")
	docID := c.Param("id")

	ctx := context.Background()

	// SEGURIDAD: Verificar que el documento existe y pertenece al usuario
	currentDoc, err := firestore.GetDocument(ctx, collection, docID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":       "Document not found",
			"collection":  collection,
			"document_id": docID,
		})
		return
	}

	// Verificar ownership por subdomain
	userSubdomain, exists := c.Get("subdomain")
	if exists {
		docSubdomain, hasSubdomain := currentDoc.Data["subdomain"].(string)
		
		if hasSubdomain && docSubdomain != userSubdomain.(string) {
			// Verificar si es admin
			claims, _ := c.Get("claims")
			claimsMap, _ := claims.(map[string]interface{})
			role, _ := claimsMap["role"].(string)
			
			if role != "admin" {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "No puedes eliminar documentos de otro subdominio",
				})
				return
			}
		}
	}

	err = firestore.DeleteDocument(ctx, collection, docID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to delete document",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":     true,
		"message":     "Document deleted successfully",
		"collection":  collection,
		"document_id": docID,
	})
}

// QueryDocuments realiza consultas con filtros en una colección
func QueryDocuments(c *gin.Context) {
	collection := c.Param("collection")
	var options firebase.QueryOptions

	if err := c.ShouldBindJSON(&options); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid JSON format",
			"details": err.Error(),
		})
		return
	}

	// SEGURIDAD: Añadir automáticamente filtro por subdominio
	userSubdomain, exists := c.Get("subdomain")
	if exists {
		// Verificar si es admin
		claims, _ := c.Get("claims")
		claimsMap, _ := claims.(map[string]interface{})
		role, _ := claimsMap["role"].(string)
		
		// Solo añadir filtro de subdomain si NO es admin
		if role != "admin" {
			subdomainFilter := firebase.QueryFilter{
				Field:    "subdomain",
				Operator: "==",
				Value:    userSubdomain.(string),
			}
			options.Filters = append(options.Filters, subdomainFilter)
		}
	}

	// Validar que al menos uno de los filtros sea project_id
	hasProjectFilter := false
	for _, filter := range options.Filters {
		if filter.Field == "project_id" && filter.Operator == "==" {
			hasProjectFilter = true
			break
		}
	}
	if !hasProjectFilter {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing required filter: project_id == <value>",
		})
		return
	}

	ctx := context.Background()
	docs, err := firestore.QueryDocuments(ctx, collection, options)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to query documents",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"documents":  docs,
		"count":      len(docs),
		"collection": collection,
		"query":      options,
	})
}