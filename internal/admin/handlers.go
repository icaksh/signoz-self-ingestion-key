package admin

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/sismedika/otlp-proxy/internal/ca"
	"github.com/sismedika/otlp-proxy/internal/store"
)

type Handlers struct {
	store              *store.Store
	tmpl               *template.Template
	caClient           *ca.Client
	downloadManager    *ca.DownloadManager
	caExternalHostname string
	caSyslogPort       int
	certLifetime       time.Duration
}

type FormData struct {
	Action string
	Target string
	Swap   string
	Tenant store.Tenant
}

type IndexData struct {
	Tenants []store.Tenant
}

type UsagePage struct {
	Tenant store.Tenant
}

type UsersPage struct {
	Users []store.User
}

func NewHandlers(st *store.Store, tmpl *template.Template, caClient *ca.Client, dl *ca.DownloadManager, caExternalHostname string, caSyslogPort int, certLifetime time.Duration) *Handlers {
	return &Handlers{
		store:              st,
		tmpl:               tmpl,
		caClient:           caClient,
		downloadManager:    dl,
		caExternalHostname: caExternalHostname,
		caSyslogPort:       caSyslogPort,
		certLifetime:       certLifetime,
	}
}

func (h *Handlers) render(w http.ResponseWriter, name string, data any) {
	if err := h.tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("[admin] template error: %v", err)
	}
}

func (h *Handlers) Index(w http.ResponseWriter, r *http.Request) {
	tenants, err := h.store.ListTenants(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.render(w, "index", IndexData{Tenants: tenants})
}

func (h *Handlers) NewForm(w http.ResponseWriter, r *http.Request) {
	data := FormData{
		Action: "/tenants",
		Target: "#tenant-list",
		Swap:   "beforeend",
	}
	h.render(w, "tenant_form", data)
}

// parseRateLimits reads the optional rate-limit form fields. Empty fields
// become nil (unlimited). Daily quota is entered in MB and stored as bytes.
func parseRateLimits(r *http.Request) *store.RateLimitParams {
	limits := &store.RateLimitParams{}
	if v := r.FormValue("rate_limit_rps"); v != "" {
		val, _ := strconv.ParseInt(v, 10, 64)
		if val > 0 {
			limits.RateLimitRPS = &val
		}
	}
	if v := r.FormValue("burst_bytes"); v != "" {
		val, _ := strconv.ParseInt(v, 10, 64)
		if val > 0 {
			limits.BurstBytes = &val
		}
	}
	if v := r.FormValue("daily_byte_quota"); v != "" {
		val, _ := strconv.ParseInt(v, 10, 64)
		if val > 0 {
			val = val * 1048576 // convert MB to bytes
			limits.DailyByteQuota = &val
		}
	}
	return limits
}

func (h *Handlers) CancelForm(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(""))
}

func (h *Handlers) Create(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	description := r.FormValue("description")
	limits := parseRateLimits(r)

	tenant, err := h.store.CreateTenant(r.Context(), name, description, limits)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Tenant.APIKey holds the full plaintext key — rendered once in the response body.
	h.render(w, "tenant_row", tenant)
}

func (h *Handlers) EditForm(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	tenant, err := h.store.LookupTenantByID(r.Context(), id)
	if err != nil || tenant == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	data := FormData{
		Action: "/tenants/" + strconv.FormatInt(id, 10),
		Target: "#tenant-" + strconv.FormatInt(id, 10),
		Swap:   "outerHTML",
		Tenant: *tenant,
	}
	h.render(w, "tenant_form", data)
}

func (h *Handlers) Update(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	name := r.FormValue("name")
	description := r.FormValue("description")
	active := r.FormValue("active") == "on"
	limits := parseRateLimits(r)

	if err := h.store.UpdateTenant(r.Context(), id, name, description, active, limits); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tenant, _ := h.store.LookupTenantByID(r.Context(), id)
	h.render(w, "tenant_row", tenant)
}

func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := h.store.DeleteTenant(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handlers) RegenerateKey(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	tenant, err := h.store.LookupTenantByID(r.Context(), id)
	if err != nil || tenant == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	newKey, err := h.store.RegenerateKey(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tenant.APIKey = newKey
	tenant.KeyPrefix = newKey[:12]
	// Full plaintext key returned once in the response body.
	h.render(w, "tenant_row", tenant)
}

func (h *Handlers) UsagePage(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	tenant, err := h.store.LookupTenantByID(r.Context(), id)
	if err != nil || tenant == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	h.render(w, "tenant_usage", UsagePage{Tenant: *tenant})
}

func (h *Handlers) UsageData(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rng := r.URL.Query().Get("range")
	if rng == "" {
		rng = "7d"
	}

	data, err := h.store.GetUsageData(r.Context(), id, rng)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// QuotaFragment renders the daily quota progress bar (HTMX fragment).
func (h *Handlers) QuotaFragment(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	tenant, err := h.store.LookupTenantByID(r.Context(), id)
	if err != nil || tenant == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	used, err := h.store.GetDailyByteUsage(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := struct {
		Used  int64
		Quota int64
	}{
		Used:  used,
		Quota: 0,
	}
	if tenant.DailyByteQuota != nil {
		data.Quota = *tenant.DailyByteQuota
	}
	h.render(w, "quota_fragment", data)
}

// --- user management ---

func (h *Handlers) UsersPage(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.ListUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.render(w, "users", UsersPage{Users: users})
}

func (h *Handlers) CreateUser(w http.ResponseWriter, r *http.Request) {
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
		log.Printf("[admin] bcrypt error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.store.CreateUser(r.Context(), username, string(hash)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	users, _ := h.store.ListUsers(r.Context())
	h.render(w, "user_list", UsersPage{Users: users})
}

func (h *Handlers) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	_ = h.store.DeleteUser(r.Context(), id)
	users, _ := h.store.ListUsers(r.Context())
	h.render(w, "user_list", UsersPage{Users: users})
}

func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: "session", Value: "", Path: "/",
		HttpOnly: true, MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func maskKey(k string) string {
	if len(k) <= 8 {
		return strings.Repeat("*", len(k))
	}
	return k[:4] + "..." + k[len(k)-4:]
}
