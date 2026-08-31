package web

import (
	"encoding/json"
	"net/http"
	"strconv"

	"golang.org/x/crypto/bcrypt"

	"github.com/sismedika/otlp-proxy/internal/store"
)

// consumeFlash reads and clears the one-time flash cookie.
func (s *Server) consumeFlash(w http.ResponseWriter, r *http.Request) *FlashData {
	data, ok := s.flash.Get(r)
	s.flash.Clear(w)
	if !ok {
		return nil
	}
	return data
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	tenants, err := s.store.ListTenants(r.Context())
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Database Error", "Unable to load tenants.")
		return
	}
	expiringMap, _ := s.store.ExpiringCertsByTenant(r.Context(), 168)

	v := s.baseView(r, "Tenants")
	v.Tenants = tenants
	v.ExpiringMap = expiringMap
	v.Flash = s.consumeFlash(w, r)
	s.render(w, "index", v)
}

func (s *Server) tenantNew(w http.ResponseWriter, r *http.Request) {
	v := s.baseView(r, "New Tenant")
	v.Editing = false
	s.render(w, "tenant_form", v)
}

func (s *Server) tenantEdit(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	tenant, err := s.store.LookupTenantByID(r.Context(), id)
	if err != nil || tenant == nil {
		s.renderError(w, r, http.StatusNotFound, "Tenant Not Found", "The requested tenant does not exist or has been deleted.")
		return
	}
	v := s.baseView(r, "Edit Tenant")
	v.Editing = true
	v.Tenant = tenant
	s.render(w, "tenant_form", v)
}

// parseRateLimits reads the optional rate-limit form fields. Empty fields are
// nil (unlimited); daily quota is entered in MB and stored in bytes.
func parseRateLimits(r *http.Request) *store.RateLimitParams {
	limits := &store.RateLimitParams{}
	if v := r.FormValue("rate_limit_rps"); v != "" {
		if val, err := strconv.ParseInt(v, 10, 64); err == nil && val > 0 {
			limits.RateLimitRPS = &val
		}
	}
	if v := r.FormValue("burst_bytes"); v != "" {
		if val, err := strconv.ParseInt(v, 10, 64); err == nil && val > 0 {
			limits.BurstBytes = &val
		}
	}
	if v := r.FormValue("daily_byte_quota"); v != "" {
		if val, err := strconv.ParseInt(v, 10, 64); err == nil && val > 0 {
			val = val * 1048576
			limits.DailyByteQuota = &val
		}
	}
	return limits
}

func (s *Server) tenantCreate(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	description := r.FormValue("description")
	limits := parseRateLimits(r)

	tenant, err := s.store.CreateTenant(r.Context(), name, description, limits)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.flash.Set(w, FlashData{Kind: "apikey", Key: tenant.APIKey, Tenant: tenant.Name})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) tenantUpdate(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	name := r.FormValue("name")
	description := r.FormValue("description")
	active := r.FormValue("active") == "on"
	limits := parseRateLimits(r)

	if err := s.store.UpdateTenant(r.Context(), id, name, description, active, limits); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) tenantDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := s.store.DeleteTenant(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) tenantRegenerate(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	tenant, err := s.store.LookupTenantByID(r.Context(), id)
	if err != nil || tenant == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	newKey, err := s.store.RegenerateKey(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.flash.Set(w, FlashData{Kind: "apikey", Key: newKey, Tenant: tenant.Name})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) usagePage(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	tenant, err := s.store.LookupTenantByID(r.Context(), id)
	if err != nil || tenant == nil {
		s.renderError(w, r, http.StatusNotFound, "Tenant Not Found", "The requested tenant does not exist or has been deleted.")
		return
	}
	v := s.baseView(r, "Usage")
	v.Tenant = tenant
	v.TenantID = id
	v.QuotaUsed, _ = s.store.GetDailyByteUsage(r.Context(), id)
	if tenant.DailyByteQuota != nil {
		v.QuotaTotal = *tenant.DailyByteQuota
	}
	s.render(w, "tenant_usage", v)
}

func (s *Server) usageData(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rng := r.URL.Query().Get("range")
	if rng == "" {
		rng = "7d"
	}

	data, err := s.store.GetUsageData(r.Context(), id, rng)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Database Error", "Unable to load users.")
		return
	}
	v := s.baseView(r, "Admin users")
	v.Users = users
	s.render(w, "users", v)
}

func (s *Server) userCreate(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		http.Error(w, "username and password required", http.StatusBadRequest)
		return
	}
	if len(password) < 12 {
		http.Error(w, "password must be at least 12 characters", http.StatusBadRequest)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.store.CreateUser(r.Context(), username, string(hash)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) userDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	_ = s.store.DeleteUser(r.Context(), id)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}
