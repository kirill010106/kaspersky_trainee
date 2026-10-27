package httpapi

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/kirill010106/kaspersky_trainee/internal/domain"
	"github.com/kirill010106/kaspersky_trainee/internal/httpapi/generated"
	"github.com/kirill010106/kaspersky_trainee/internal/service"
)

const databaseTimeout = 3 * time.Second
const maxRequestBody = 32 * 1024

type handlers struct {
	service *service.Service
}

func (h *handlers) getThreat(w http.ResponseWriter, r *http.Request) {
	md5 := chi.URLParam(r, "md5")

	ctx, cancel := context.WithTimeout(r.Context(), databaseTimeout)
	defer cancel()

	threat, err := h.service.Get(ctx, md5)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, threatResponse(threat))
}

func threatResponse(threat domain.Threat) generated.ThreatResponse {
	return generated.ThreatResponse{
		Md5:         threat.MD5,
		Name:        threat.Name,
		Description: threat.Description,
		Type:        generated.ThreatType(threat.Type),
		Severity:    generated.Severity(threat.Severity),
		CreatedAt:   threat.CreatedAt.UTC(),
		UpdatedAt:   threat.UpdatedAt.UTC(),
	}
}

func writeServiceError(w http.ResponseWriter, err error) {
	if _, ok := errors.AsType[*domain.ValidationError](err); ok {
		writeJSON(w, http.StatusBadRequest, generated.ErrorResponse{
			Message: "invalid request",
		})
		return
	}

	if errors.Is(err, service.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, generated.ErrorResponse{
			Message: "threat not found",
		})
		return
	}

	if errors.Is(err, service.ErrAlreadyExists) {
		writeJSON(w, http.StatusConflict, generated.ErrorResponse{
			Message: "threat already exists",
		})
		return
	}

	writeJSON(w, http.StatusInternalServerError, generated.ErrorResponse{
		Message: "internal server error",
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"internal server error"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (h *handlers) createThreat(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			writeJSON(w, http.StatusRequestEntityTooLarge, generated.ErrorResponse{
				Message: "request body too large",
			})
			return
		}

		writeJSON(w, http.StatusBadRequest, generated.ErrorResponse{
			Message: "invalid request body",
		})
		return
	}

	var request generated.ThreatCreateRequest

	if err := json.Unmarshal(body, &request, json.RejectUnknownMembers(true)); err != nil {
		writeJSON(w, http.StatusBadRequest, generated.ErrorResponse{
			Message: "invalid JSON",
		})
		return
	}

	description := ""
	if request.Description != nil {
		description = *request.Description
	}

	data := domain.ThreatData{
		Name:        request.Name,
		Description: description,
		Type:        domain.ThreatType(request.Type),
		Severity:    domain.Severity(request.Severity),
	}

	ctx, cancel := context.WithTimeout(r.Context(), databaseTimeout)
	defer cancel()

	threat, err := h.service.Create(ctx, request.Md5, data)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	w.Header().Set("Location", "/api/v1/info/"+threat.MD5)
	writeJSON(w, http.StatusCreated, threatResponse(threat))
}
