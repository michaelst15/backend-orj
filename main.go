package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/phpdave11/gofpdf"
	"github.com/xuri/excelize/v2"
)

type adminSession struct {
	Token     string
	Email     string
	Name      string
	CreatedAt time.Time
}

type api struct {
	allowedOrigins  map[string]struct{}
	allowAllCORS    bool
	db              *pgxpool.Pool
	absensiKeyMu    sync.Mutex
	absensiKey      absensiKeyCache
	presentasiMu    sync.Mutex
	presentasiKk    int
	presentasiAt    time.Time
	sessionsMu      sync.Mutex
	sessionsByToken map[string]*adminSession
	sessionsByEmail map[string]*adminSession
}

type absensiFamily struct {
	IP      string   `json:"ip"`
	Display string   `json:"display"`
	Suami   string   `json:"suami"`
	Isteri  string   `json:"isteri"`
	Anak    []string `json:"anak"`
	Boru    []string `json:"boru"`
}

type absensiKeyPick struct {
	KeyColumn       string
	CandidateCounts map[string]int
}

type absensiKeyCache struct {
	tableName string
	nameCol   string
	hubCol    string
	expected  int
	pick      absensiKeyPick
	cachedAt  time.Time
}

func main() {
	if err := loadDotEnv(filepath.Join(".", ".env")); err != nil {
		log.Fatalf("load .env failed: %v", err)
	}

	port := envInt("PORT", 8080)
	allowedOrigins := envStrings("CORS_ORIGINS", []string{
		"*",
		"http://localhost:5173",
		"http://127.0.0.1:5173",
	})

	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))

	var db *pgxpool.Pool
	if databaseURL != "" {
		dbCtx, dbCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dbCancel()

		conn, err := pgxpool.New(dbCtx, databaseURL)
		if err != nil {
			log.Fatalf("db connect failed: %v", err)
		}
		if err := conn.Ping(dbCtx); err != nil {
			conn.Close()
			log.Fatalf("db ping failed: %v", err)
		}
		if err := ensureAdminAccountsTable(dbCtx, conn); err != nil {
			conn.Close()
			log.Fatalf("ensure admin_accounts table failed: %v", err)
		}
		if err := ensureAdminActivityLogTable(dbCtx, conn); err != nil {
			conn.Close()
			log.Fatalf("ensure admin_activity_log table failed: %v", err)
		}
		if err := ensureDaftarKehadiranTable(dbCtx, conn); err != nil {
			conn.Close()
			log.Fatalf("ensure daftar_kehadiran table failed: %v", err)
		}
		if err := ensureRekapHadirTable(dbCtx, conn); err != nil {
			conn.Close()
			log.Fatalf("ensure rekap_hadir table failed: %v", err)
		}
		if err := ensureDataBaruTable(dbCtx, conn); err != nil {
			conn.Close()
			log.Fatalf("ensure data_baru table failed: %v", err)
		}
		db = conn
		defer db.Close()
	} else {
		log.Printf("DATABASE_URL not set, running without database connection")
	}

	handler := newAPI(allowedOrigins, db).routes()

	server := &http.Server{
		Addr:              ":" + strconv.Itoa(port),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("backend listening on http://localhost:%d", port)

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	_ = server.Shutdown(ctx)
}

func newAPI(allowedOrigins []string, db *pgxpool.Pool) *api {
	m := make(map[string]struct{}, len(allowedOrigins))
	allowAll := false
	for _, origin := range allowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin == "" {
			continue
		}
		if origin == "*" {
			allowAll = true
			continue
		}
		m[origin] = struct{}{}
	}
	return &api{
		allowedOrigins:  m,
		allowAllCORS:    allowAll,
		db:              db,
		sessionsByToken: make(map[string]*adminSession),
		sessionsByEmail: make(map[string]*adminSession),
	}
}

func generateToken() string {
	b := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		b = []byte(fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid()))
	}
	return fmt.Sprintf("%x", b)
}

func (a *api) createSession(email, name string) *adminSession {
	a.sessionsMu.Lock()
	defer a.sessionsMu.Unlock()

	token := generateToken()
	session := &adminSession{
		Token:     token,
		Email:     email,
		Name:      name,
		CreatedAt: time.Now(),
	}

	a.sessionsByToken[token] = session
	a.sessionsByEmail[email] = session
	return session
}

func (a *api) getSession(token string) *adminSession {
	if token == "" {
		return nil
	}
	a.sessionsMu.Lock()
	defer a.sessionsMu.Unlock()
	return a.sessionsByToken[token]
}

func (a *api) destroySession(token string) {
	if token == "" {
		return
	}
	a.sessionsMu.Lock()
	defer a.sessionsMu.Unlock()

	session := a.sessionsByToken[token]
	if session != nil {
		delete(a.sessionsByToken, token)
		delete(a.sessionsByEmail, session.Email)
	}
}

func ensureRekapHadirTable(ctx context.Context, db *pgxpool.Pool) error {
	if db == nil {
		return nil
	}
	_, err := db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS rekap_hadir (
			ompu_key text PRIMARY KEY,
			ompu_label text NOT NULL,
			kk integer NOT NULL DEFAULT 0,
			updated_at timestamptz NOT NULL DEFAULT now()
		)
	`)
	return err
}

func ensureDataBaruTable(ctx context.Context, db *pgxpool.Pool) error {
	if db == nil {
		return nil
	}
	_, err := db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS data_baru (
			id BIGSERIAL PRIMARY KEY,
			nama_lengkap text NOT NULL,
			email text,
			telepon text,
			domisili text,
			pesan text,
			is_read boolean NOT NULL DEFAULT false,
			created_at timestamptz NOT NULL DEFAULT now()
		)
	`)
	if err != nil {
		return err
	}
	_, err = db.Exec(ctx, `
		ALTER TABLE data_baru ADD COLUMN IF NOT EXISTS telepon text
	`)
	return err
}

func normalizeOmpuKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		if r >= 'a' && r <= 'z' {
			b.WriteRune(r)
			continue
		}
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
			continue
		}
	}
	return b.String()
}

func pickFirstOmpu(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		switch r {
		case '/', ',', ';', '|':
			return true
		default:
			return false
		}
	})
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

func mapOmpuToRekapKey(ompu string) (string, string) {
	first := pickFirstOmpu(ompu)
	key := normalizeOmpuKey(first)
	switch key {
	case "otuan":
		return "otuan", "O. TUAN"
	case "osotargoling":
		return "osotargoling", "O. SOTARGOLING"
	case "omogot":
		return "omogot", "O. MOGOT"
	case "odatup":
		return "odatup", "O. DATU P."
	default:
		return "", ""
	}
}

func recomputeRekapHadir(ctx context.Context, db *pgxpool.Pool) error {
	if db == nil {
		return nil
	}
	if err := ensureRekapHadirTable(ctx, db); err != nil {
		return err
	}
	type rekapRow struct {
		key   string
		label string
	}
	expected := []rekapRow{
		{key: "otuan", label: "O. TUAN"},
		{key: "osotargoling", label: "O. SOTARGOLING"},
		{key: "omogot", label: "O. MOGOT"},
		{key: "odatup", label: "O. DATU P."},
	}

	counts := map[string]int{
		"otuan":        0,
		"osotargoling": 0,
		"omogot":       0,
		"odatup":       0,
	}

	rows, err := db.Query(ctx, `SELECT ip, ompu FROM daftar_kehadiran`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ip, ompu string
		if err := rows.Scan(&ip, &ompu); err != nil {
			rows.Close()
			return err
		}
		k, _ := mapOmpuToRekapKey(ompu)
		if k == "" {
			continue
		}
		counts[k]++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `TRUNCATE TABLE rekap_hadir`); err != nil {
		return err
	}
	for _, r := range expected {
		if _, err := tx.Exec(ctx, `
			INSERT INTO rekap_hadir (ompu_key, ompu_label, kk, updated_at)
			VALUES ($1, $2, $3, now())
			ON CONFLICT (ompu_key) DO UPDATE
			SET ompu_label = EXCLUDED.ompu_label,
			    kk = EXCLUDED.kk,
			    updated_at = now()
		`, r.key, r.label, counts[r.key]); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (a *api) getAbsensiKey(ctx context.Context, tableName string, nameCol string, hubCol string, expected int) (absensiKeyPick, error) {
	if a.db == nil {
		return absensiKeyPick{KeyColumn: "", CandidateCounts: map[string]int{}}, nil
	}

	a.absensiKeyMu.Lock()
	cache := a.absensiKey
	if cache.tableName == tableName &&
		cache.nameCol == nameCol &&
		cache.hubCol == hubCol &&
		cache.expected == expected &&
		cache.pick.KeyColumn != "" &&
		time.Since(cache.cachedAt) < 10*time.Minute {
		pick := cache.pick
		a.absensiKeyMu.Unlock()
		return pick, nil
	}
	a.absensiKeyMu.Unlock()

	pick, err := pickAbsensiKey(ctx, a.db, tableName, nameCol, hubCol, expected)
	if err != nil {
		return pick, err
	}
	if pick.KeyColumn != "" {
		a.absensiKeyMu.Lock()
		a.absensiKey = absensiKeyCache{
			tableName: tableName,
			nameCol:   nameCol,
			hubCol:    hubCol,
			expected:  expected,
			pick:      pick,
			cachedAt:  time.Now(),
		}
		a.absensiKeyMu.Unlock()
	}
	return pick, nil
}

func (a *api) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Session-Token")
		if token == "" {
			token = strings.TrimSpace(r.URL.Query().Get("token"))
		}

		session := a.getSession(token)
		if session == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":      false,
				"message": "sesi tidak valid atau sudah kadaluarsa",
			})
			return
		}

		next.ServeHTTP(w, r)
	}
}

func (a *api) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		dbOK := false
		if a.db != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			dbOK = a.db.Ping(ctx) == nil
			cancel()
		}
		a.writeJSON(w, http.StatusOK, map[string]any{
			"ok":   true,
			"dbOk": dbOK,
			"time": time.Now().UTC().Format(time.RFC3339),
		})
	})

	mux.HandleFunc("POST /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")

		adminAccounts := []struct {
			email    string
			password string
			name     string
		}{
			{"admin1@gmail.com", "admin123", "Admin 1"},
			{"admin2@gmail.com", "admin123", "Admin 2"},
			{"admin3@gmail.com", "admin123", "Admin 3"},
			{"admin4@gmail.com", "admin123", "Admin 4"},
			{"admin5@gmail.com", "admin123", "Admin 5"},
			{"admin6@gmail.com", "admin123", "Admin 6"},
		}

		var body struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			Force    bool   `json:"force"`
		}
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&body); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "payload tidak valid",
			})
			return
		}

		email := strings.TrimSpace(body.Email)
		password := strings.TrimSpace(body.Password)
		force := body.Force

		if email == "" || password == "" {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "email dan password wajib diisi",
			})
			return
		}

		var matchedAdmin *struct {
			email    string
			password string
			name     string
		}
		for _, acc := range adminAccounts {
			if acc.email == email && acc.password == password {
				matchedAdmin = &acc
				break
			}
		}

		if matchedAdmin == nil {
			a.writeJSON(w, http.StatusUnauthorized, map[string]any{
				"ok":      false,
				"message": "email atau password salah",
			})
			return
		}

		a.sessionsMu.Lock()
		existingSession, hasActiveSession := a.sessionsByEmail[email]
		a.sessionsMu.Unlock()

		if hasActiveSession && !force {
			a.writeJSON(w, http.StatusConflict, map[string]any{
				"ok":              false,
				"message":         "Akun sedang digunakan",
				"requireForce":    true,
				"activeSessionAt": existingSession.CreatedAt.UnixMilli(),
			})
			return
		}

		session := a.createSession(matchedAdmin.email, matchedAdmin.name)

		a.writeJSON(w, http.StatusOK, map[string]any{
			"ok":    true,
			"token": session.Token,
			"email": session.Email,
			"name":  session.Name,
		})
	})

	mux.HandleFunc("POST /api/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		token := r.Header.Get("X-Session-Token")
		if token == "" {
			token = strings.TrimSpace(r.URL.Query().Get("token"))
		}
		a.destroySession(token)
		a.writeJSON(w, http.StatusOK, map[string]any{
			"ok": true,
		})
	})

	mux.HandleFunc("GET /api/auth/me", a.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		token := r.Header.Get("X-Session-Token")
		if token == "" {
			token = strings.TrimSpace(r.URL.Query().Get("token"))
		}

		session := a.getSession(token)
		if session == nil {
			a.writeJSON(w, http.StatusUnauthorized, map[string]any{
				"ok":      false,
				"message": "sesi tidak valid",
			})
			return
		}

		a.writeJSON(w, http.StatusOK, map[string]any{
			"ok":    true,
			"email": session.Email,
			"name":  session.Name,
		})
	}))

	mux.HandleFunc("POST /api/data-baru", func(w http.ResponseWriter, r *http.Request) {
		if a.db == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"ok":      false,
				"message": "database belum terhubung",
			})
			return
		}

		var body struct {
			NamaLengkap string `json:"nama_lengkap"`
			Email       string `json:"email"`
			Telepon     string `json:"telepon"`
			Domisili    string `json:"domisili"`
			Pesan       string `json:"pesan"`
		}
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&body); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "payload tidak valid",
			})
			return
		}

		namaLengkap := strings.TrimSpace(body.NamaLengkap)
		email := strings.TrimSpace(body.Email)
		telepon := strings.TrimSpace(body.Telepon)
		domisili := strings.TrimSpace(body.Domisili)
		pesan := strings.TrimSpace(body.Pesan)

		if namaLengkap == "" {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "nama lengkap wajib diisi",
			})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		_, err := a.db.Exec(ctx, `
			INSERT INTO data_baru (nama_lengkap, email, telepon, domisili, pesan)
			VALUES ($1, $2, $3, $4, $5)
		`, namaLengkap, email, telepon, domisili, pesan)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal menyimpan data",
			})
			return
		}

		a.writeJSON(w, http.StatusOK, map[string]any{
			"ok": true,
		})
	})

	mux.HandleFunc("GET /api/data-baru", a.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if a.db == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"ok":      false,
				"message": "database belum terhubung",
			})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		rows, err := a.db.Query(ctx, `
			SELECT id, nama_lengkap, email, telepon, domisili, pesan, is_read, created_at
			FROM data_baru
			ORDER BY created_at DESC
		`)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal mengambil data",
			})
			return
		}
		defer rows.Close()

		type dataBaru struct {
			ID          int64     `json:"id"`
			NamaLengkap string    `json:"nama_lengkap"`
			Email       string    `json:"email"`
			Telepon     string    `json:"telepon"`
			Domisili    string    `json:"domisili"`
			Pesan       string    `json:"pesan"`
			IsRead      bool      `json:"is_read"`
			CreatedAt   time.Time `json:"created_at"`
		}
		var data []dataBaru
		for rows.Next() {
			var d dataBaru
			if err := rows.Scan(&d.ID, &d.NamaLengkap, &d.Email, &d.Telepon, &d.Domisili, &d.Pesan, &d.IsRead, &d.CreatedAt); err != nil {
				continue
			}
			data = append(data, d)
		}

		a.writeJSON(w, http.StatusOK, map[string]any{
			"ok":   true,
			"data": data,
		})
	}))

	mux.HandleFunc("PUT /api/data-baru/{id}/read", a.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if a.db == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"ok":      false,
				"message": "database belum terhubung",
			})
			return
		}

		idStr := r.PathValue("id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "id tidak valid",
			})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		_, err = a.db.Exec(ctx, `
			UPDATE data_baru
			SET is_read = true
			WHERE id = $1
		`, id)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal memperbarui status",
			})
			return
		}

		a.writeJSON(w, http.StatusOK, map[string]any{
			"ok": true,
		})
	}))

	mux.HandleFunc("GET /api/metrics", a.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		families := 0
		ruasOrj := 0
		keluargaSuami := 0
		keluargaIstri := 0
		keluargaAnak := 0
		keluargaBoru := 0
		keluargaDolidoli := 0
		keluargaNamabaju := 0
		ruasOrjAnak := 0
		ruasOrjBoru := 0
		kehadiranKk := 0
		kehadiranDewasa := 0
		kehadiranAnak := 0
		if a.db != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
			defer cancel()

			families = countRowsByNameColumn(ctx, a.db, "keluarga")
			ruasOrj = countRowsByNameColumn(ctx, a.db, "ruasORJ")
			keluargaSuami = countRowsByColumnRegex(ctx, a.db, "keluarga", []string{"hub"}, "\\msuami")
			keluargaIstri = countRowsByColumnRegex(ctx, a.db, "keluarga", []string{"hub"}, "\\mistri|\\misteri")
			keluargaAnak = countRowsByColumnRegex(ctx, a.db, "keluarga", []string{"hub"}, "\\manak")
			keluargaBoru = countRowsByColumnRegex(ctx, a.db, "keluarga", []string{"hub"}, "\\mboru")
			keluargaDolidoli = countRowsByColumnRegex(ctx, a.db, "keluarga", []string{"hub"}, "\\mdoli\\W*doli")
			keluargaNamabaju = countRowsByColumnRegex(ctx, a.db, "keluarga", []string{"hub"}, "\\mnamar\\W*baju|\\mnamarbaju")
			ruasOrjAnak = countRowsByColumnRegex(ctx, a.db, "ruasORJ", []string{"ruas"}, "\\manak")
			ruasOrjBoru = countRowsByColumnRegex(ctx, a.db, "ruasORJ", []string{"ruas"}, "\\mboru")
			_ = a.db.QueryRow(ctx, `
				SELECT COUNT(*)::int,
				       COALESCE(SUM(dewasa), 0)::int,
				       COALESCE(SUM(anak), 0)::int
				FROM daftar_kehadiran
			`).Scan(&kehadiranKk, &kehadiranDewasa, &kehadiranAnak)
		}
		clans := 18
		verified := int(float64(families) * 0.92)
		pending := families - verified

		a.writeJSON(w, http.StatusOK, map[string]any{
			"ok":       true,
			"families": families,
			"ruasOrj":  ruasOrj,
			"keluarga": map[string]any{
				"suami":     keluargaSuami,
				"istri":     keluargaIstri,
				"anak":      keluargaAnak,
				"boru":      keluargaBoru,
				"dolidoli":  keluargaDolidoli,
				"namarbaju": keluargaNamabaju,
			},
			"ruasOrjDetail": map[string]any{
				"anak": ruasOrjAnak,
				"boru": ruasOrjBoru,
			},
			"kehadiran": map[string]any{
				"kk":     kehadiranKk,
				"dewasa": kehadiranDewasa,
				"anak":   kehadiranAnak,
				"jiwa":   kehadiranDewasa + kehadiranAnak,
			},
			"clans":          clans,
			"verified":       verified,
			"pending":        pending,
			"realtimeOnline": 2,
		})
	}))

	handleKehadiranMetrics := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if a.db == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"ok":      false,
				"message": "database belum terhubung",
			})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		kk := 0
		dewasa := 0
		anak := 0
		if err := a.db.QueryRow(ctx, `
			SELECT COUNT(*)::int,
			       COALESCE(SUM(dewasa), 0)::int,
			       COALESCE(SUM(anak), 0)::int
			FROM daftar_kehadiran
		`).Scan(&kk, &dewasa, &anak); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal mengambil metrics kehadiran",
			})
			return
		}

		a.writeJSON(w, http.StatusOK, map[string]any{
			"ok": true,
			"kehadiran": map[string]any{
				"kk":     kk,
				"dewasa": dewasa,
				"anak":   anak,
				"jiwa":   dewasa + anak,
			},
		})
	}

	mux.HandleFunc("GET /api/kehadiran/metrics", a.requireAuth(handleKehadiranMetrics))
	mux.HandleFunc("/api/kehadiran/metrics", a.requireAuth(handleKehadiranMetrics))

	handleKehadiranRekap := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if a.db == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"ok":      false,
				"message": "database belum terhubung",
			})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		if err := recomputeRekapHadir(ctx, a.db); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal update rekap hadir",
			})
			return
		}

		loadRows := func() ([]map[string]any, error) {
			rows, err := a.db.Query(ctx, `
				SELECT ompu_key, ompu_label, kk
				FROM rekap_hadir
				ORDER BY ompu_key
			`)
			if err != nil {
				return nil, err
			}
			defer rows.Close()

			out := make([]map[string]any, 0, 8)
			for rows.Next() {
				var key, label string
				var kk int
				if err := rows.Scan(&key, &label, &kk); err != nil {
					return nil, err
				}
				out = append(out, map[string]any{
					"key":   key,
					"label": label,
					"kk":    kk,
				})
			}
			if err := rows.Err(); err != nil {
				return nil, err
			}
			return out, nil
		}

		out, err := loadRows()
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal mengambil rekap hadir",
			})
			return
		}

		a.writeJSON(w, http.StatusOK, map[string]any{
			"ok":   true,
			"rows": out,
		})
	}

	mux.HandleFunc("GET /api/kehadiran/rekap", a.requireAuth(handleKehadiranRekap))
	mux.HandleFunc("/api/kehadiran/rekap", a.requireAuth(handleKehadiranRekap))

	mux.HandleFunc("GET /api/absensi/keluarga", a.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if a.db == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"ok":      false,
				"message": "database belum terhubung",
			})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		tableName, err := detectTableName(ctx, a.db, "keluarga")
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal membaca metadata tabel",
			})
			return
		}
		if tableName == "" {
			a.writeJSON(w, http.StatusNotFound, map[string]any{
				"ok":      false,
				"message": "tabel keluarga tidak ditemukan",
			})
			return
		}

		nameCol, err := detectNameColumn(ctx, a.db, tableName)
		if err != nil || nameCol == "" {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "kolom nama tidak ditemukan pada tabel keluarga",
			})
			return
		}

		hubCol, err := detectColumnByCandidates(ctx, a.db, tableName, []string{"hub", "sebagai", "status"}, []string{"hub", "sebagai", "status"})
		if err != nil || hubCol == "" {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "kolom hub tidak ditemukan pada tabel keluarga",
			})
			return
		}

		keyPick, err := a.getAbsensiKey(ctx, tableName, nameCol, hubCol, 1861)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal menentukan kolom kunci keluarga",
			})
			return
		}
		ipCol := keyPick.KeyColumn
		if ipCol == "" {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "kolom kunci keluarga tidak ditemukan",
			})
			return
		}

		query := fmt.Sprintf(`
			SELECT %s::text, %s::text, %s::text
			FROM %s
			WHERE NULLIF(BTRIM(%s::text), '') IS NOT NULL
			  AND BTRIM(%s::text) <> '?'
			  AND NULLIF(BTRIM(%s::text), '') IS NOT NULL
			  AND BTRIM(%s::text) <> '?'
		`, quoteIdent(ipCol), quoteIdent(nameCol), quoteIdent(hubCol), quoteIdent(tableName),
			quoteIdent(ipCol), quoteIdent(ipCol), quoteIdent(nameCol), quoteIdent(nameCol))

		rows, err := a.db.Query(ctx, query)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal mengambil data keluarga",
			})
			return
		}
		defer rows.Close()

		type agg struct {
			ip    string
			suami map[string]struct{}
			istri map[string]struct{}
			anak  map[string]struct{}
			boru  map[string]struct{}
		}

		groups := map[string]*agg{}

		for rows.Next() {
			var ip, name, hub string
			if err := rows.Scan(&ip, &name, &hub); err != nil {
				a.writeJSON(w, http.StatusInternalServerError, map[string]any{
					"ok":      false,
					"message": "gagal membaca data",
				})
				return
			}
			ip = strings.TrimSpace(ip)
			name = strings.TrimSpace(name)
			hub = strings.TrimSpace(hub)
			if isUnknownValue(ip) || isUnknownValue(name) || strings.Contains(name, "?") {
				continue
			}

			kind := classifyHub(hub)
			if kind == "" {
				continue
			}

			g, ok := groups[ip]
			if !ok {
				g = &agg{
					ip:    ip,
					suami: map[string]struct{}{},
					istri: map[string]struct{}{},
					anak:  map[string]struct{}{},
					boru:  map[string]struct{}{},
				}
				groups[ip] = g
			}

			switch kind {
			case "suami":
				g.suami[name] = struct{}{}
				delete(g.anak, name)
				delete(g.boru, name)
			case "istri":
				g.istri[name] = struct{}{}
				delete(g.anak, name)
				delete(g.boru, name)
			case "anak":
				if _, ok := g.suami[name]; ok {
					break
				}
				if _, ok := g.istri[name]; ok {
					break
				}
				g.anak[name] = struct{}{}
			case "boru":
				if _, ok := g.suami[name]; ok {
					break
				}
				if _, ok := g.istri[name]; ok {
					break
				}
				g.boru[name] = struct{}{}
			}
		}
		if err := rows.Err(); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal membaca data",
			})
			return
		}

		families := make([]absensiFamily, 0, len(groups))
		groupCountSuami := 0
		groupCountIstri := 0
		groupCountCouple := 0
		for _, g := range groups {
			suamiList := keysSorted(g.suami)
			istriList := keysSorted(g.istri)
			anakList := keysSorted(g.anak)
			boruList := keysSorted(g.boru)

			if len(suamiList) > 0 {
				groupCountSuami++
			}
			if len(istriList) > 0 {
				groupCountIstri++
			}
			if len(suamiList) > 0 && len(istriList) > 0 {
				groupCountCouple++
			}

			if len(suamiList) != 1 || len(istriList) != 1 {
				continue
			}

			suami := suamiList[0]
			isteri := istriList[0]

			display := fmt.Sprintf("%s / %s", dashIfEmpty(suami), dashIfEmpty(isteri))
			families = append(families, absensiFamily{
				IP:      g.ip,
				Display: display,
				Suami:   suami,
				Isteri:  isteri,
				Anak:    anakList,
				Boru:    boruList,
			})
		}

		sort.Slice(families, func(i, j int) bool {
			return families[i].Display < families[j].Display
		})

		distinctIP := 0
		distinctIPSuami := 0
		distinctIPIstri := 0
		rowsSuami := 0
		rowsIstri := 0

		_ = a.db.QueryRow(ctx, fmt.Sprintf(`
			SELECT COUNT(DISTINCT %s::text)
			FROM %s
			WHERE NULLIF(BTRIM(%s::text), '') IS NOT NULL
			  AND BTRIM(%s::text) <> '?'
		`, quoteIdent(ipCol), quoteIdent(tableName), quoteIdent(ipCol), quoteIdent(ipCol))).Scan(&distinctIP)

		suamiPattern := "\\msuami"
		istriPattern := "\\mistri|\\misteri"
		_ = a.db.QueryRow(ctx, fmt.Sprintf(`
			SELECT COUNT(DISTINCT %s::text)
			FROM %s
			WHERE NULLIF(BTRIM(%s::text), '') IS NOT NULL
			  AND BTRIM(%s::text) <> '?'
			  AND NULLIF(BTRIM(%s::text), '') IS NOT NULL
			  AND BTRIM(%s::text) <> '?'
			  AND NULLIF(BTRIM(%s::text), '') IS NOT NULL
			  AND (BTRIM(%s::text) ~* $1)
		`, quoteIdent(ipCol), quoteIdent(tableName),
			quoteIdent(ipCol), quoteIdent(ipCol),
			quoteIdent(nameCol), quoteIdent(nameCol),
			quoteIdent(hubCol), quoteIdent(hubCol)), suamiPattern).Scan(&distinctIPSuami)

		_ = a.db.QueryRow(ctx, fmt.Sprintf(`
			SELECT COUNT(DISTINCT %s::text)
			FROM %s
			WHERE NULLIF(BTRIM(%s::text), '') IS NOT NULL
			  AND BTRIM(%s::text) <> '?'
			  AND NULLIF(BTRIM(%s::text), '') IS NOT NULL
			  AND BTRIM(%s::text) <> '?'
			  AND NULLIF(BTRIM(%s::text), '') IS NOT NULL
			  AND (BTRIM(%s::text) ~* $1)
		`, quoteIdent(ipCol), quoteIdent(tableName),
			quoteIdent(ipCol), quoteIdent(ipCol),
			quoteIdent(nameCol), quoteIdent(nameCol),
			quoteIdent(hubCol), quoteIdent(hubCol)), istriPattern).Scan(&distinctIPIstri)

		_ = a.db.QueryRow(ctx, fmt.Sprintf(`
			SELECT COUNT(*)
			FROM %s
			WHERE NULLIF(BTRIM(%s::text), '') IS NOT NULL
			  AND BTRIM(%s::text) <> '?'
			  AND NULLIF(BTRIM(%s::text), '') IS NOT NULL
			  AND BTRIM(%s::text) <> '?'
			  AND NULLIF(BTRIM(%s::text), '') IS NOT NULL
			  AND (BTRIM(%s::text) ~* $1)
		`, quoteIdent(tableName),
			quoteIdent(ipCol), quoteIdent(ipCol),
			quoteIdent(nameCol), quoteIdent(nameCol),
			quoteIdent(hubCol), quoteIdent(hubCol)), suamiPattern).Scan(&rowsSuami)

		_ = a.db.QueryRow(ctx, fmt.Sprintf(`
			SELECT COUNT(*)
			FROM %s
			WHERE NULLIF(BTRIM(%s::text), '') IS NOT NULL
			  AND BTRIM(%s::text) <> '?'
			  AND NULLIF(BTRIM(%s::text), '') IS NOT NULL
			  AND BTRIM(%s::text) <> '?'
			  AND NULLIF(BTRIM(%s::text), '') IS NOT NULL
			  AND (BTRIM(%s::text) ~* $1)
		`, quoteIdent(tableName),
			quoteIdent(ipCol), quoteIdent(ipCol),
			quoteIdent(nameCol), quoteIdent(nameCol),
			quoteIdent(hubCol), quoteIdent(hubCol)), istriPattern).Scan(&rowsIstri)

		a.writeJSON(w, http.StatusOK, map[string]any{
			"ok":       true,
			"count":    len(families),
			"families": families,
			"columns": map[string]any{
				"table": tableName,
				"ip":    ipCol,
				"nama":  nameCol,
				"hub":   hubCol,
			},
			"stats": map[string]any{
				"distinctIP":      distinctIP,
				"distinctIPSuami": distinctIPSuami,
				"distinctIPIstri": distinctIPIstri,
				"rowsSuami":       rowsSuami,
				"rowsIstri":       rowsIstri,
				"groupSuami":      groupCountSuami,
				"groupIstri":      groupCountIstri,
				"groupCouple":     groupCountCouple,
			},
			"keyCandidates": keyPick.CandidateCounts,
		})
	}))

	mux.HandleFunc("GET /api/absensi/detail", a.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if a.db == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"ok":      false,
				"message": "database belum terhubung",
			})
			return
		}

		ipValue := strings.TrimSpace(r.URL.Query().Get("ip"))
		if ipValue == "" {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "parameter ip wajib diisi",
			})
			return
		}
		debugEnabled := strings.TrimSpace(r.URL.Query().Get("debug")) == "1"
		debugInfo := map[string]any{}

		timeout := 60 * time.Second
		if debugEnabled {
			timeout = 120 * time.Second
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		if debugEnabled {
			lookup := func(substr string) []string {
				substr = strings.ToLower(strings.TrimSpace(substr))
				if substr == "" {
					return nil
				}
				pattern := "%" + substr + "%"
				rows, err := a.db.Query(ctx, `
					SELECT table_schema, table_name
					FROM information_schema.tables
					WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
					  AND LOWER(table_name) LIKE $1
					ORDER BY CASE WHEN table_schema = 'public' THEN 0 ELSE 1 END, table_schema, table_name
					LIMIT 20
				`, pattern)
				if err != nil {
					return []string{"<error>"}
				}
				defer rows.Close()
				out := make([]string, 0, 8)
				for rows.Next() {
					var s, t string
					if err := rows.Scan(&s, &t); err != nil {
						continue
					}
					if s == "" || strings.EqualFold(s, "public") {
						out = append(out, t)
					} else {
						out = append(out, s+"."+t)
					}
				}
				return out
			}
			debugInfo["tablesLikeOmpu"] = lookup("ompu")
			debugInfo["tablesLikeRuas"] = lookup("ruas")
		}

		keluargaTable, err := detectTableName(ctx, a.db, "keluarga")
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal membaca metadata tabel keluarga",
			})
			return
		}
		if keluargaTable == "" {
			a.writeJSON(w, http.StatusNotFound, map[string]any{
				"ok":      false,
				"message": "tabel keluarga tidak ditemukan",
			})
			return
		}

		nameCol, err := detectNameColumn(ctx, a.db, keluargaTable)
		if err != nil || nameCol == "" {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "kolom nama tidak ditemukan pada tabel keluarga",
			})
			return
		}

		hubCol, err := detectColumnByCandidates(ctx, a.db, keluargaTable, []string{"hub", "sebagai", "status"}, []string{"hub", "sebagai", "status"})
		if err != nil || hubCol == "" {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "kolom hub tidak ditemukan pada tabel keluarga",
			})
			return
		}

		keyPick, err := a.getAbsensiKey(ctx, keluargaTable, nameCol, hubCol, 1861)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal menentukan kolom kunci keluarga",
			})
			return
		}
		keyCol := keyPick.KeyColumn
		if keyCol == "" {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "kolom kunci keluarga tidak ditemukan",
			})
			return
		}
		if debugEnabled {
			debugInfo["ipValue"] = ipValue
			debugInfo["keluargaTable"] = keluargaTable
			debugInfo["keyCol"] = keyCol
			debugInfo["nameCol"] = nameCol
			debugInfo["hubCol"] = hubCol
		}

		keluargaIPCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, keluargaTable, []string{
			"ip",
			"ipkeluarga",
			"ip_kk",
			"ipkk",
			"ip_orj",
			"iporj",
			"ipruas",
			"ip_ruas",
		})
		if keluargaIPCol == "" {
			keluargaIPCol, _ = detectColumnByCandidates(
				ctx,
				a.db,
				keluargaTable,
				[]string{"ip", "ipkeluarga", "ip_kk", "ipkk", "ip_orj", "iporj", "ipruas", "ip_ruas"},
				[]string{"ip"},
			)
		}
		if debugEnabled {
			debugInfo["keluargaIPCol"] = keluargaIPCol
		}
		alamatCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, keluargaTable, []string{
			"alamat",
			"domisili",
			"kota",
			"kabupaten",
			"kab",
			"kecamatan",
			"kec",
			"kelurahan",
			"kel",
			"provinsi",
			"prov",
			"wilayah",
			"daerah",
			"alamat_lengkap",
			"alamatlengkap",
			"alamat_rumah",
			"alamatrumah",
			"alamat_tinggal",
			"alamattinggal",
			"alamat_sekarang",
			"alamatsekarang",
			"alamat_1",
			"alamat1",
			"jalan",
			"jln",
			"jl",
			"address",
		})
		if alamatCol == "" {
			alamatCol, _ = detectColumnByCandidates(ctx, a.db, keluargaTable, []string{"alamat", "domisili", "address"}, []string{"alamat", "domisili", "address"})
		}
		if debugEnabled {
			debugInfo["alamatColKeluarga"] = alamatCol
		}
		sundutCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, keluargaTable, []string{"sundut"})
		if sundutCol == "" {
			sundutCol, _ = detectColumnByCandidates(ctx, a.db, keluargaTable, []string{"sundut"}, []string{"sundut"})
		}
		if debugEnabled {
			debugInfo["sundutCol"] = sundutCol
		}

		ipExpr := "NULL::text"
		if keluargaIPCol != "" {
			ipExpr = fmt.Sprintf("%s::text", quoteIdent(keluargaIPCol))
		}
		alamatExpr := "NULL::text"
		if alamatCol != "" {
			alamatExpr = fmt.Sprintf("%s::text", quoteIdent(alamatCol))
		}
		sundutExpr := "NULL::text"
		if sundutCol != "" {
			sundutExpr = fmt.Sprintf("%s::text", quoteIdent(sundutCol))
		}

		query := fmt.Sprintf(`
			SELECT %s::text, %s::text, %s AS _ip, %s AS _alamat, %s AS _sundut
			FROM %s
			WHERE %s::text = $1
			  AND NULLIF(BTRIM(%s::text), '') IS NOT NULL
			  AND BTRIM(%s::text) <> '?'
		`, quoteIdent(nameCol), quoteIdent(hubCol), ipExpr, alamatExpr, sundutExpr,
			quoteIdent(keluargaTable),
			quoteIdent(keyCol),
			quoteIdent(nameCol), quoteIdent(nameCol))

		rows, err := a.db.Query(ctx, query, ipValue)
		if err != nil {
			resp := map[string]any{
				"ok":      false,
				"message": "gagal mengambil detail keluarga",
			}
			if debugEnabled {
				resp["error"] = err.Error()
				resp["query"] = query
				resp["arg"] = ipValue
			}
			a.writeJSON(w, http.StatusInternalServerError, resp)
			return
		}
		defer rows.Close()

		suami := ""
		isteri := ""
		alamat := ""
		sundut := ""
		telp := ""
		keluargaIPValue := ""

		for rows.Next() {
			var n, h string
			var ipText *string
			var aText *string
			var sText *string
			if err := rows.Scan(&n, &h, &ipText, &aText, &sText); err != nil {
				a.writeJSON(w, http.StatusInternalServerError, map[string]any{
					"ok":      false,
					"message": "gagal membaca detail keluarga",
				})
				return
			}

			n = strings.TrimSpace(n)
			h = strings.TrimSpace(h)
			if keluargaIPValue == "" && ipText != nil {
				value := strings.TrimSpace(*ipText)
				if !isUnknownValue(value) && !strings.Contains(value, "?") {
					keluargaIPValue = value
				}
			}

			if alamat == "" && aText != nil {
				value := strings.TrimSpace(*aText)
				if !isUnknownValue(value) && !strings.Contains(value, "?") {
					alamat = value
				}
			}
			if sundut == "" && sText != nil {
				value := strings.TrimSpace(*sText)
				if !isUnknownValue(value) && !strings.Contains(value, "?") {
					sundut = value
				}
			}

			if isUnknownValue(n) || strings.Contains(n, "?") {
				continue
			}

			kind := classifyHub(h)
			if kind == "" {
				continue
			}

			if kind == "suami" && suami == "" {
				suami = n
			}
			if kind == "istri" && isteri == "" {
				isteri = n
			}
		}
		if err := rows.Err(); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal membaca detail keluarga",
			})
			return
		}

		if suami == "" && isteri == "" {
			a.writeJSON(w, http.StatusNotFound, map[string]any{
				"ok":      false,
				"message": "detail keluarga tidak ditemukan",
			})
			return
		}

		if keluargaIPValue == "" {
			allText, _ := listTextColumns(ctx, a.db, keluargaTable)
			cols := make([]string, 0, len(allText))
			for _, c := range allText {
				n := normalizeKey(c)
				if strings.Contains(n, "ruasid") || n == normalizeKey(keyCol) {
					continue
				}
				if strings.Contains(n, "ip") {
					cols = append(cols, c)
				}
			}
			sort.Strings(cols)
			for _, col := range cols {
				if v, err := querySingleTextByKey(ctx, a.db, keluargaTable, col, keyCol, ipValue); err == nil && v != "" {
					keluargaIPValue = strings.TrimSpace(v)
					if keluargaIPValue != "" && !isUnknownValue(keluargaIPValue) && !strings.Contains(keluargaIPValue, "?") {
						break
					}
					keluargaIPValue = ""
				}
			}
		}
		if debugEnabled {
			debugInfo["keluargaIPValue"] = keluargaIPValue
		}

		joinValues := make([]string, 0, 8)
		if keluargaIPValue != "" {
			joinValues = append(joinValues, keluargaIPValue)
		}
		joinValues = append(joinValues, ipValue)
		extraJoinCandidates := []string{
			"registrasi",
			"reg",
			"no_reg",
			"noreg",
			"kk",
			"no_kk",
			"nomorkk",
			"idkk",
			"id_kk",
		}
		for _, cand := range extraJoinCandidates {
			col, _ := detectColumnByNormalizedCandidates(ctx, a.db, keluargaTable, []string{cand})
			if col == "" {
				continue
			}
			if v, err := querySingleTextByKey(ctx, a.db, keluargaTable, col, keyCol, ipValue); err == nil && v != "" {
				joinValues = append(joinValues, v)
			}
		}
		{
			seen := map[string]struct{}{}
			unique := make([]string, 0, len(joinValues))
			for _, v := range joinValues {
				v = strings.TrimSpace(v)
				if v == "" || isUnknownValue(v) {
					continue
				}
				if _, ok := seen[v]; ok {
					continue
				}
				seen[v] = struct{}{}
				unique = append(unique, v)
			}
			joinValues = unique
		}
		if debugEnabled {
			debugInfo["joinValues"] = joinValues
			debugInfo["suami"] = suami
			debugInfo["isteri"] = isteri
			debugInfo["alamatBefore"] = alamat
			debugInfo["telpBefore"] = ""
		}

		if alamat == "" || telp == "" {
			ruasTableFast, _ := detectTableName(ctx, a.db, "ruasORJ")
			if ruasTableFast == "" {
				ruasTableFast, _ = detectTableName(ctx, a.db, "ruas")
			}

			if ruasTableFast != "" {
				ruasCols, _ := listColumns(ctx, a.db, ruasTableFast)
				ruasNormToActual := map[string]string{}
				for _, c := range ruasCols {
					n := normalizeKey(c)
					if n == "" {
						continue
					}
					if _, ok := ruasNormToActual[n]; !ok {
						ruasNormToActual[n] = c
					}
				}
				resolveRuasCol := func(candidate string) string {
					n := normalizeKey(candidate)
					if n == "" {
						return ""
					}
					if actual, ok := ruasNormToActual[n]; ok {
						return actual
					}
					return ""
				}

				telpCandidates := []string{
					"mobile",
					"hp",
					"no_hp",
					"nohp",
					"nomor_hp",
					"nomorhp",
					"whatsapp",
					"wa",
					"telp",
					"nomortelp",
					"telepon",
					"phone",
				}

				ruasAlamatCol := resolveRuasCol("alamat")

				seenTelp := map[string]struct{}{}
				telpCols := make([]string, 0, len(telpCandidates))
				for _, cand := range telpCandidates {
					actual := resolveRuasCol(cand)
					if actual == "" {
						continue
					}
					key := strings.ToLower(actual)
					if _, ok := seenTelp[key]; ok {
						continue
					}
					seenTelp[key] = struct{}{}
					telpCols = append(telpCols, actual)
				}

				type keyAttempt struct {
					col   string
					value string
				}
				attempts := make([]keyAttempt, 0, 6)
				if keyActualCol := resolveRuasCol(keyCol); keyActualCol != "" && strings.TrimSpace(ipValue) != "" {
					attempts = append(attempts, keyAttempt{col: keyActualCol, value: ipValue})
				}
				if ruasidCol := resolveRuasCol("ruasid"); ruasidCol != "" && strings.TrimSpace(ipValue) != "" {
					attempts = append(attempts, keyAttempt{col: ruasidCol, value: ipValue})
				}
				if ridCol := resolveRuasCol("rid"); ridCol != "" && strings.TrimSpace(ipValue) != "" {
					attempts = append(attempts, keyAttempt{col: ridCol, value: ipValue})
				}
				if ipCol := resolveRuasCol("ip"); ipCol != "" && strings.TrimSpace(keluargaIPValue) != "" {
					attempts = append(attempts, keyAttempt{col: ipCol, value: keluargaIPValue})
				}

				seenAttempt := map[string]struct{}{}
				uniqueAttempts := make([]keyAttempt, 0, len(attempts))
				for _, a2 := range attempts {
					key := strings.ToLower(strings.TrimSpace(a2.col)) + "|" + strings.TrimSpace(a2.value)
					if a2.col == "" || strings.TrimSpace(a2.value) == "" {
						continue
					}
					if _, ok := seenAttempt[key]; ok {
						continue
					}
					seenAttempt[key] = struct{}{}
					uniqueAttempts = append(uniqueAttempts, a2)
				}
				attempts = uniqueAttempts

				for _, a2 := range attempts {
					if alamat == "" && ruasAlamatCol != "" {
						if got, err := querySingleTextByKey(ctx, a.db, ruasTableFast, ruasAlamatCol, a2.col, a2.value); err == nil && got != "" {
							alamat = got
						}
					}

					if telp == "" && len(telpCols) > 0 {
						best := ""
						bestScore := -1
						for _, col := range telpCols {
							if got, err := querySingleTextByKey(ctx, a.db, ruasTableFast, col, a2.col, a2.value); err == nil && got != "" {
								candidate := formatMobile(got)
								score := scoreMobile(candidate)
								if score > bestScore {
									bestScore = score
									best = candidate
								}
							}
						}
						if bestScore >= 0 {
							telp = best
						}
					}

					if alamat != "" && telp != "" {
						break
					}
				}
			}
		}

		if alamat == "" {
			alamatCandidates := []string{
				"alamat",
				"domisili",
				"kota",
				"kabupaten",
				"kab",
				"kecamatan",
				"kec",
				"kelurahan",
				"kel",
				"provinsi",
				"prov",
				"wilayah",
				"daerah",
				"alamat_lengkap",
				"alamatlengkap",
				"alamat_rumah",
				"alamatrumah",
				"alamat_tinggal",
				"alamattinggal",
				"alamat_sekarang",
				"alamatsekarang",
				"alamat_1",
				"alamat1",
				"jalan",
				"jln",
				"jl",
				"address",
			}
			seen := map[string]struct{}{}
			actualCols := make([]string, 0, len(alamatCandidates))
			for _, cand := range alamatCandidates {
				actual, _ := detectColumnByNormalizedCandidates(ctx, a.db, keluargaTable, []string{cand})
				if actual == "" {
					actual, _ = detectColumnByCandidates(ctx, a.db, keluargaTable, []string{cand}, []string{cand})
				}
				if actual == "" {
					continue
				}
				key := strings.ToLower(actual)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				actualCols = append(actualCols, actual)
			}
			for _, col := range actualCols {
				if got, err := querySingleTextByKey(ctx, a.db, keluargaTable, col, keyCol, ipValue); err == nil && got != "" {
					alamat = got
					break
				}
			}
		}
		if alamat == "" {
			allText, _ := listTextColumns(ctx, a.db, keluargaTable)
			seen := map[string]struct{}{}
			cols := make([]string, 0, len(allText))
			for _, c := range allText {
				n := normalizeKey(c)
				if !(strings.Contains(n, "alamat") ||
					strings.Contains(n, "domisili") ||
					strings.Contains(n, "address") ||
					strings.Contains(n, "kota") ||
					strings.Contains(n, "kab") ||
					strings.Contains(n, "kec") ||
					strings.Contains(n, "kel") ||
					strings.Contains(n, "prov") ||
					strings.Contains(n, "wilayah") ||
					strings.Contains(n, "daerah") ||
					strings.Contains(n, "jalan") ||
					strings.Contains(n, "jln") ||
					strings.Contains(n, "jl")) {
					continue
				}
				l := strings.ToLower(c)
				if _, ok := seen[l]; ok {
					continue
				}
				seen[l] = struct{}{}
				cols = append(cols, c)
			}
			sort.Strings(cols)
			for _, col := range cols {
				if got, err := querySingleTextByKey(ctx, a.db, keluargaTable, col, keyCol, ipValue); err == nil && got != "" {
					alamat = got
					break
				}
			}
		}

		subOmpu := ""
		ompuTable, _ := detectTableName(ctx, a.db, "ompu")
		if ompuTable == "" {
			ompuTable, _ = detectTableByColumnAndKeys(ctx, a.db, []string{"subompu", "sub_ompu"}, []string{"ompu"}, []string{
				"ip",
				keyCol,
				"ruasid",
				"rid",
				"id",
			})
		}
		if debugEnabled {
			debugInfo["ompuTable"] = ompuTable
			if ompuTable != "" {
				if cols, err := listColumns(ctx, a.db, ompuTable); err == nil && len(cols) > 0 {
					if len(cols) > 40 {
						debugInfo["ompuColumns"] = append([]string{}, cols[:40]...)
					} else {
						debugInfo["ompuColumns"] = cols
					}
				}
			}
		}
		if ompuTable != "" {
			subOmpuCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, ompuTable, []string{"subompu", "sub_ompu"})
			if subOmpuCol == "" {
				subOmpuCol, _ = detectColumnByCandidates(ctx, a.db, ompuTable, []string{"subompu", "sub_ompu"}, []string{"subompu"})
			}

			ompuIPCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, ompuTable, []string{"ip"})
			if ompuIPCol == "" {
				ompuIPCol, _ = detectColumnByCandidates(ctx, a.db, ompuTable, []string{"ip"}, []string{"ip"})
			}
			if debugEnabled {
				debugInfo["subOmpuCol"] = subOmpuCol
				debugInfo["ompuIPCol"] = ompuIPCol
			}
			if subOmpuCol != "" && ompuIPCol != "" && keluargaIPValue != "" {
				if got, err := querySingleTextByKey(ctx, a.db, ompuTable, subOmpuCol, ompuIPCol, keluargaIPValue); err == nil && got != "" {
					subOmpu = formatPomparan(got)
				}
			}
			if subOmpu == "" && subOmpuCol != "" && ompuIPCol != "" && len(joinValues) > 0 {
				for _, key := range joinValues {
					if got, err := querySingleTextByKey(ctx, a.db, ompuTable, subOmpuCol, ompuIPCol, key); err == nil && got != "" {
						subOmpu = formatPomparan(got)
						break
					}
				}
			}
			if subOmpu != "" {
				goto afterOmpuLookup
			}

			ompuJoinCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, ompuTable, []string{
				"ip",
				keyCol,
				strings.ToLower(keyCol),
				"ruasid",
				"ruas_id",
				"idruas",
				"id_ruas",
				"kk",
				"idkk",
				"id_kk",
				"noreg",
				"no_reg",
				"reg",
			})
			if ompuJoinCol == "" {
				ompuJoinCol, _ = detectColumnByCandidates(
					ctx,
					a.db,
					ompuTable,
					[]string{"ip", keyCol, strings.ToLower(keyCol), "ruasid", "kk", "idkk", "id_kk", "noreg", "reg"},
					[]string{"ip", keyCol, "ruas", "kk", "idkk", "reg"},
				)
			}
			if debugEnabled {
				debugInfo["ompuJoinCol"] = ompuJoinCol
			}

			if subOmpuCol != "" && ompuJoinCol != "" && len(joinValues) > 0 {
				for _, key := range joinValues {
					if got, err := querySingleTextByKey(ctx, a.db, ompuTable, subOmpuCol, ompuJoinCol, key); err == nil && got != "" {
						subOmpu = formatPomparan(got)
						break
					}
				}
			}
			if subOmpu != "" {
				goto afterOmpuLookup
			}

			ompuKeyCols := make([]string, 0, 8)
			if keyCol != "" {
				ompuKeyCols = append(ompuKeyCols, keyCol, strings.ToLower(keyCol))
			}
			ompuKeyCols = append(ompuKeyCols,
				"ip",
				"rid",
				"ruasid",
				"ruas_id",
				"idruas",
				"id_ruas",
				"idsub",
				"kk",
				"idkk",
				"id_kk",
				"noreg",
				"reg",
				"no_reg",
				"nomorkk",
				"no_kk",
				"id",
				"idruasorj",
				"id_ruasorj",
			)

			resolvedOmpuKeyCols := make([]string, 0, len(ompuKeyCols))
			for _, cand := range ompuKeyCols {
				if cand == "" {
					continue
				}
				actual, _ := detectColumnByNormalizedCandidates(ctx, a.db, ompuTable, []string{cand})
				if actual == "" {
					actual, _ = detectColumnByCandidates(ctx, a.db, ompuTable, []string{cand}, []string{cand})
				}
				if actual != "" {
					resolvedOmpuKeyCols = append(resolvedOmpuKeyCols, actual)
				}
			}

			keyValues := joinValues
			if subOmpuCol != "" && len(resolvedOmpuKeyCols) > 0 {
				if got, _ := firstNonEmptyByAnyKey(ctx, a.db, ompuTable, subOmpuCol, resolvedOmpuKeyCols, keyValues); got != "" {
					subOmpu = formatPomparan(got)
				}
			}
		}
	afterOmpuLookup:
		telp = strings.TrimSpace(telp)
		keluargaTelpCandidates := []string{
			"mobile",
			"hp",
			"no_hp",
			"nohp",
			"nomor_hp",
			"nomorhp",
			"whatsapp",
			"wa",
			"telp",
			"nomortelp",
			"telepon",
			"phone",
		}
		if telp == "" {
			seenKeluargaTelp := map[string]struct{}{}
			keluargaTelpCols := make([]string, 0, len(keluargaTelpCandidates))
			for _, cand := range keluargaTelpCandidates {
				actual, _ := detectColumnByNormalizedCandidates(ctx, a.db, keluargaTable, []string{cand})
				if actual == "" {
					actual, _ = detectColumnByCandidates(ctx, a.db, keluargaTable, []string{cand}, []string{cand})
				}
				if actual == "" {
					continue
				}
				key := strings.ToLower(actual)
				if _, ok := seenKeluargaTelp[key]; ok {
					continue
				}
				seenKeluargaTelp[key] = struct{}{}
				keluargaTelpCols = append(keluargaTelpCols, actual)
			}
			for _, col := range keluargaTelpCols {
				if got, err := querySingleTextByKey(ctx, a.db, keluargaTable, col, keyCol, ipValue); err == nil && got != "" {
					candidate := formatMobile(got)
					if score := scoreMobile(candidate); score > scoreMobile(telp) {
						telp = candidate
					}
				}
			}

			allText, _ := listTextColumns(ctx, a.db, keluargaTable)
			seen := map[string]struct{}{}
			cols := make([]string, 0, len(allText))
			for _, c := range allText {
				n := normalizeKey(c)
				if !(strings.Contains(n, "hp") ||
					strings.Contains(n, "telp") ||
					strings.Contains(n, "telepon") ||
					strings.Contains(n, "phone") ||
					strings.Contains(n, "mobile") ||
					strings.Contains(n, "whatsapp") ||
					strings.Contains(n, "handphone") ||
					strings.Contains(n, "nohp") ||
					strings.Contains(n, "nomorhp") ||
					strings.Contains(n, "nomorhp")) {
					continue
				}
				l := strings.ToLower(c)
				if _, ok := seen[l]; ok {
					continue
				}
				seen[l] = struct{}{}
				cols = append(cols, c)
			}
			sort.Strings(cols)
			for _, col := range cols {
				if got, err := querySingleTextByKey(ctx, a.db, keluargaTable, col, keyCol, ipValue); err == nil && got != "" {
					candidate := formatMobile(got)
					if score := scoreMobile(candidate); score > scoreMobile(telp) {
						telp = candidate
					}
				}
			}
		}

		if alamat == "" || telp == "" {
			a2, t2, _ := bestAbsensiFallback(ctx, a.db, keluargaTable, keyCol, ipValue)
			if alamat == "" && a2 != "" {
				alamat = a2
			}
			if telp == "" && t2 != "" {
				telp = t2
			}
		}

		ruasTable, _ := detectTableName(ctx, a.db, "ruasORJ")
		if ruasTable == "" {
			ruasTable, _ = detectTableName(ctx, a.db, "ruas")
		}
		if ruasTable == "" {
			ruasTable, _ = detectTableByColumnAndKeys(ctx, a.db, []string{"alamat"}, []string{"ruas"}, []string{
				keyCol,
				"rid",
				"ip",
				"ruasid",
				"ruas_id",
				"idruas",
				"id_ruas",
				"kk",
				"idkk",
				"id_kk",
				"registrasi",
				"noreg",
				"no_reg",
				"reg",
				"id",
			})
		}
		if debugEnabled {
			debugInfo["ruasTable"] = ruasTable
			if ruasTable != "" {
				if cols, err := listColumns(ctx, a.db, ruasTable); err == nil && len(cols) > 0 {
					if len(cols) > 60 {
						debugInfo["ruasColumns"] = append([]string{}, cols[:60]...)
					} else {
						debugInfo["ruasColumns"] = cols
					}
				}
			}
		}
		if ruasTable != "" && (telp == "" || alamat == "") {
			needTelp := telp == ""

			telpCandidates := []string{
				"mobile",
				"hp",
				"no_hp",
				"nohp",
				"nomor_hp",
				"nomorhp",
				"whatsapp",
				"wa",
				"telp",
				"nomortelp",
				"telepon",
				"phone",
			}

			directKeyCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, ruasTable, []string{keyCol, strings.ToLower(keyCol), "ruasid", "rid", "ip", "id"})
			if directKeyCol == "" {
				directKeyCol, _ = detectColumnByCandidates(ctx, a.db, ruasTable, []string{keyCol, strings.ToLower(keyCol), "ruasid", "rid", "ip", "id"}, []string{keyCol, "ruas", "rid", "ip", "id"})
			}
			if directKeyCol != "" {
				ruasAlamatCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, ruasTable, []string{"alamat"})
				if ruasAlamatCol == "" {
					ruasAlamatCol, _ = detectColumnByCandidates(ctx, a.db, ruasTable, []string{"alamat"}, []string{"alamat"})
				}

				seenTelp := map[string]struct{}{}
				telpCols := make([]string, 0, len(telpCandidates))
				for _, cand := range telpCandidates {
					actual, _ := detectColumnByNormalizedCandidates(ctx, a.db, ruasTable, []string{cand})
					if actual == "" {
						actual, _ = detectColumnByCandidates(ctx, a.db, ruasTable, []string{cand}, []string{cand})
					}
					if actual == "" {
						continue
					}
					key := strings.ToLower(actual)
					if _, ok := seenTelp[key]; ok {
						continue
					}
					seenTelp[key] = struct{}{}
					telpCols = append(telpCols, actual)
				}

				type keyAttempt struct {
					col   string
					value string
				}
				attempts := make([]keyAttempt, 0, 6)

				keyActualCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, ruasTable, []string{keyCol})
				if keyActualCol == "" {
					keyActualCol, _ = detectColumnByCandidates(ctx, a.db, ruasTable, []string{keyCol}, []string{keyCol})
				}
				if keyActualCol != "" && strings.TrimSpace(ipValue) != "" {
					attempts = append(attempts, keyAttempt{col: keyActualCol, value: ipValue})
				}

				if keyActualCol == "" {
					ruasidCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, ruasTable, []string{"ruasid"})
					if ruasidCol == "" {
						ruasidCol, _ = detectColumnByCandidates(ctx, a.db, ruasTable, []string{"ruasid"}, []string{"ruasid"})
					}
					if ruasidCol != "" && strings.TrimSpace(ipValue) != "" {
						attempts = append(attempts, keyAttempt{col: ruasidCol, value: ipValue})
					}
				}

				ridCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, ruasTable, []string{"rid"})
				if ridCol == "" {
					ridCol, _ = detectColumnByCandidates(ctx, a.db, ruasTable, []string{"rid"}, []string{"rid"})
				}
				if ridCol != "" && strings.TrimSpace(ipValue) != "" {
					attempts = append(attempts, keyAttempt{col: ridCol, value: ipValue})
				}

				ipCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, ruasTable, []string{"ip"})
				if ipCol == "" {
					ipCol, _ = detectColumnByCandidates(ctx, a.db, ruasTable, []string{"ip"}, []string{"ip"})
				}
				if ipCol != "" && strings.TrimSpace(keluargaIPValue) != "" {
					attempts = append(attempts, keyAttempt{col: ipCol, value: keluargaIPValue})
				}

				seenAttempt := map[string]struct{}{}
				uniqueAttempts := make([]keyAttempt, 0, len(attempts))
				for _, a2 := range attempts {
					key := strings.ToLower(strings.TrimSpace(a2.col)) + "|" + strings.TrimSpace(a2.value)
					if a2.col == "" || strings.TrimSpace(a2.value) == "" {
						continue
					}
					if _, ok := seenAttempt[key]; ok {
						continue
					}
					seenAttempt[key] = struct{}{}
					uniqueAttempts = append(uniqueAttempts, a2)
				}
				attempts = uniqueAttempts

				for _, a2 := range attempts {
					if alamat == "" && ruasAlamatCol != "" {
						if got, err := querySingleTextByKey(ctx, a.db, ruasTable, ruasAlamatCol, a2.col, a2.value); err == nil && got != "" {
							alamat = got
						}
					}

					if telp == "" && len(telpCols) > 0 {
						best := ""
						bestScore := -1
						for _, col := range telpCols {
							if got, err := querySingleTextByKey(ctx, a.db, ruasTable, col, a2.col, a2.value); err == nil && got != "" {
								candidate := formatMobile(got)
								score := scoreMobile(candidate)
								if score > bestScore {
									bestScore = score
									best = candidate
								}
							}
						}
						if bestScore >= 0 {
							telp = best
						}
					}

					if alamat != "" && telp != "" {
						break
					}
				}
			}

			needTelp = telp == ""
			ruasJoinCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, ruasTable, []string{
				keyCol,
				strings.ToLower(keyCol),
				"ruasid",
				"ruas_id",
				"ruas_id",
				"idruas",
				"id_ruas",
				"ip",
				"kk",
				"idkk",
				"id_kk",
				"registrasi",
				"noreg",
				"no_reg",
				"reg",
			})
			if ruasJoinCol == "" {
				ruasJoinCol, _ = detectColumnByCandidates(
					ctx,
					a.db,
					ruasTable,
					[]string{keyCol, strings.ToLower(keyCol), "ruasid", "ip", "kk", "idkk", "id_kk", "noreg", "reg"},
					[]string{keyCol, "ruas", "ip", "kk", "idkk", "reg"},
				)
			}

			ruasKeyCols := make([]string, 0, 24)
			if ruasJoinCol != "" {
				ruasKeyCols = append(ruasKeyCols, ruasJoinCol)
			}
			if keyCol != "" {
				ruasKeyCols = append(ruasKeyCols, keyCol, strings.ToLower(keyCol))
			}
			ruasKeyCols = append(ruasKeyCols,
				"rid",
				"ip",
				"ruasid",
				"ruas_id",
				"idruas",
				"id_ruas",
				"idsub",
				"kk",
				"idkk",
				"id_kk",
				"registrasi",
				"noreg",
				"no_reg",
				"reg",
				"no_kk",
				"nomorkk",
				"id",
				"idruasorj",
				"id_ruasorj",
			)

			resolvedRuasKeyCols := make([]string, 0, len(ruasKeyCols))
			seenResolved := map[string]struct{}{}
			for _, cand := range ruasKeyCols {
				if cand == "" {
					continue
				}
				actual, _ := detectColumnByNormalizedCandidates(ctx, a.db, ruasTable, []string{cand})
				if actual == "" {
					actual, _ = detectColumnByCandidates(ctx, a.db, ruasTable, []string{cand}, []string{cand})
				}
				if actual == "" {
					continue
				}
				l := strings.ToLower(actual)
				if _, ok := seenResolved[l]; ok {
					continue
				}
				seenResolved[l] = struct{}{}
				resolvedRuasKeyCols = append(resolvedRuasKeyCols, actual)
			}

			if len(resolvedRuasKeyCols) == 0 {
				allText, _ := listTextColumns(ctx, a.db, ruasTable)
				seen := map[string]struct{}{}
				for _, c := range allText {
					n := normalizeKey(c)
					if !(strings.Contains(n, "id") || strings.Contains(n, "ip") || strings.Contains(n, "kk") || strings.Contains(n, "reg") || strings.Contains(n, "ruas")) {
						continue
					}
					l := strings.ToLower(c)
					if _, ok := seen[l]; ok {
						continue
					}
					seen[l] = struct{}{}
					resolvedRuasKeyCols = append(resolvedRuasKeyCols, c)
				}
			}
			if debugEnabled {
				if len(resolvedRuasKeyCols) > 12 {
					debugInfo["resolvedRuasKeyCols"] = append([]string{}, resolvedRuasKeyCols[:12]...)
				} else {
					debugInfo["resolvedRuasKeyCols"] = resolvedRuasKeyCols
				}
			}

			keyValues := joinValues

			telpCols := []string(nil)
			if needTelp {
				seenTelp := map[string]struct{}{}
				cols := make([]string, 0, len(telpCandidates))
				for _, cand := range telpCandidates {
					actual, _ := detectColumnByNormalizedCandidates(ctx, a.db, ruasTable, []string{cand})
					if actual == "" {
						actual, _ = detectColumnByCandidates(ctx, a.db, ruasTable, []string{cand}, []string{cand})
					}
					if actual == "" {
						continue
					}
					key := strings.ToLower(actual)
					if _, ok := seenTelp[key]; ok {
						continue
					}
					seenTelp[key] = struct{}{}
					cols = append(cols, actual)
				}
				if len(cols) == 0 {
					allText, _ := listTextColumns(ctx, a.db, ruasTable)
					seen := map[string]struct{}{}
					fallback := make([]string, 0, len(allText))
					for _, c := range allText {
						n := normalizeKey(c)
						if !(strings.Contains(n, "hp") ||
							strings.Contains(n, "telp") ||
							strings.Contains(n, "telepon") ||
							strings.Contains(n, "phone") ||
							strings.Contains(n, "mobile") ||
							strings.Contains(n, "whatsapp") ||
							strings.Contains(n, "handphone") ||
							strings.Contains(n, "nohp") ||
							strings.Contains(n, "nomorhp")) {
							continue
						}
						l := strings.ToLower(c)
						if _, ok := seen[l]; ok {
							continue
						}
						seen[l] = struct{}{}
						fallback = append(fallback, c)
					}
					sort.Strings(fallback)
					cols = fallback
				}
				telpCols = cols
			}
			if debugEnabled && len(telpCols) > 0 {
				if len(telpCols) > 12 {
					debugInfo["telpCols"] = append([]string{}, telpCols[:12]...)
				} else {
					debugInfo["telpCols"] = telpCols
				}
			}

			if needTelp && len(telpCols) > 0 && len(resolvedRuasKeyCols) > 0 {
				best := ""
				bestScore := -1
				for _, col := range telpCols {
					if got, _ := firstNonEmptyByAnyKey(ctx, a.db, ruasTable, col, resolvedRuasKeyCols, keyValues); got != "" {
						candidate := formatMobile(got)
						score := scoreMobile(candidate)
						if score > bestScore {
							bestScore = score
							best = candidate
						}
					}
				}
				if bestScore >= 0 {
					telp = best
				}
			}
			if needTelp && telp == "" && len(telpCols) > 0 {
				nameCol, _ := detectNameColumn(ctx, a.db, ruasTable)
				if nameCol != "" {
					names := []string{suami, isteri}
					best := ""
					bestScore := -1
					for _, col := range telpCols {
						for _, n := range names {
							if got, err := querySingleTextByExactName(ctx, a.db, ruasTable, col, nameCol, n); err == nil && got != "" {
								candidate := formatMobile(got)
								score := scoreMobile(candidate)
								if score > bestScore {
									bestScore = score
									best = candidate
								}
							}
						}
					}
					if bestScore >= 0 {
						telp = best
					}
				}
			}

			if alamat == "" {
				ruasAlamatCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, ruasTable, []string{"alamat"})
				if ruasAlamatCol == "" {
					ruasAlamatCol, _ = detectColumnByCandidates(ctx, a.db, ruasTable, []string{"alamat"}, []string{"alamat"})
				}
				if debugEnabled {
					debugInfo["ruasAlamatCol"] = ruasAlamatCol
				}
				if ruasAlamatCol != "" && len(resolvedRuasKeyCols) > 0 {
					if got, _ := firstNonEmptyByAnyKey(ctx, a.db, ruasTable, ruasAlamatCol, resolvedRuasKeyCols, keyValues); got != "" {
						alamat = got
					}
				}
				if alamat == "" && ruasAlamatCol != "" {
					nameCol, _ := detectNameColumn(ctx, a.db, ruasTable)
					if nameCol != "" {
						names := []string{suami, isteri}
						for _, n := range names {
							if got, err := querySingleTextByExactName(ctx, a.db, ruasTable, ruasAlamatCol, nameCol, n); err == nil && got != "" {
								alamat = got
								break
							}
						}
					}
				}
				if alamat == "" {
					allText, _ := listTextColumns(ctx, a.db, ruasTable)
					seen := map[string]struct{}{}
					cols := make([]string, 0, len(allText))
					for _, c := range allText {
						n := normalizeKey(c)
						if !(strings.Contains(n, "alamat") ||
							strings.Contains(n, "domisili") ||
							strings.Contains(n, "address") ||
							strings.Contains(n, "jalan") ||
							strings.Contains(n, "jln") ||
							strings.Contains(n, "jl")) {
							continue
						}
						l := strings.ToLower(c)
						if _, ok := seen[l]; ok {
							continue
						}
						seen[l] = struct{}{}
						cols = append(cols, c)
					}
					sort.Strings(cols)
					for _, col := range cols {
						if len(resolvedRuasKeyCols) > 0 {
							if got, _ := firstNonEmptyByAnyKey(ctx, a.db, ruasTable, col, resolvedRuasKeyCols, keyValues); got != "" {
								alamat = got
								break
							}
						}
						if alamat != "" {
							break
						}
					}
				}
			}

			if alamat == "" || telp == "" {
				a2, t2, _ := bestAbsensiFallback(ctx, a.db, ruasTable, firstOrEmpty(resolvedRuasKeyCols), firstOrEmpty(joinValues))
				if alamat == "" && a2 != "" {
					alamat = a2
				}
				if telp == "" && t2 != "" {
					telp = t2
				}
			}
			if alamat == "" || telp == "" {
				a2, t2, _ := bestAbsensiFallbackByName(ctx, a.db, ruasTable, []string{suami, isteri})
				if alamat == "" && a2 != "" {
					alamat = a2
				}
				if telp == "" && t2 != "" {
					telp = t2
				}
			}
		}

		keluarga := fmt.Sprintf("%s / %s", dashIfEmpty(suami), dashIfEmpty(isteri))
		resp := map[string]any{
			"ok":       true,
			"ip":       ipValue,
			"keluarga": keluarga,
			"suami":    suami,
			"isteri":   isteri,
			"subOmpu":  subOmpu,
			"alamat":   alamat,
			"sundut":   sundut,
			"telp":     telp,
		}
		if debugEnabled {
			debugInfo["alamatFinal"] = alamat
			debugInfo["telpFinal"] = telp
			debugInfo["subOmpuFinal"] = subOmpu
			resp["debug"] = debugInfo
		}
		a.writeJSON(w, http.StatusOK, resp)
	}))

	updateAbsensiDetail := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if a.db == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"ok":      false,
				"message": "database belum terhubung",
			})
			return
		}

		var body struct {
			IP       string `json:"ip"`
			Domisili string `json:"domisili"`
			Sundut   string `json:"sundut"`
			Telp     string `json:"telp"`
		}
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&body); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "payload tidak valid",
			})
			return
		}

		ipValue := strings.TrimSpace(body.IP)
		if ipValue == "" {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "ip wajib diisi",
			})
			return
		}
		domisili := strings.TrimSpace(body.Domisili)
		sundut := strings.TrimSpace(body.Sundut)
		telp := strings.TrimSpace(body.Telp)
		if domisili == "" && sundut == "" && telp == "" {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "tidak ada data yang diupdate",
			})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		keluargaTable, err := detectTableName(ctx, a.db, "keluarga")
		if err != nil || keluargaTable == "" {
			a.writeJSON(w, http.StatusNotFound, map[string]any{
				"ok":      false,
				"message": "tabel keluarga tidak ditemukan",
			})
			return
		}

		nameCol, err := detectNameColumn(ctx, a.db, keluargaTable)
		if err != nil || nameCol == "" {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "kolom nama tidak ditemukan pada tabel keluarga",
			})
			return
		}
		hubCol, err := detectColumnByCandidates(ctx, a.db, keluargaTable, []string{"hub", "sebagai", "status"}, []string{"hub", "sebagai", "status"})
		if err != nil || hubCol == "" {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "kolom hub tidak ditemukan pada tabel keluarga",
			})
			return
		}
		keyPick, err := a.getAbsensiKey(ctx, keluargaTable, nameCol, hubCol, 1861)
		if err != nil || keyPick.KeyColumn == "" {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "kolom kunci keluarga tidak ditemukan",
			})
			return
		}
		keyCol := keyPick.KeyColumn

		keluargaIPCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, keluargaTable, []string{
			"ip",
			"ipkeluarga",
			"ip_kk",
			"ipkk",
			"ip_orj",
			"iporj",
			"ipruas",
			"ip_ruas",
		})
		if keluargaIPCol == "" {
			keluargaIPCol, _ = detectColumnByCandidates(
				ctx,
				a.db,
				keluargaTable,
				[]string{"ip", "ipkeluarga", "ip_kk", "ipkk", "ip_orj", "iporj", "ipruas", "ip_ruas"},
				[]string{"ip"},
			)
		}

		keluargaIPValue := ""
		if keluargaIPCol != "" {
			var got *string
			q := fmt.Sprintf(`
				SELECT %s::text
				FROM %s
				WHERE %s::text = $1
				  AND NULLIF(BTRIM(%s::text), '') IS NOT NULL
				  AND BTRIM(%s::text) <> '?'
				LIMIT 1
			`, quoteIdent(keluargaIPCol), quoteIdent(keluargaTable), quoteIdent(keyCol), quoteIdent(keluargaIPCol), quoteIdent(keluargaIPCol))
			_ = a.db.QueryRow(ctx, q, ipValue).Scan(&got)
			if got != nil {
				value := strings.TrimSpace(*got)
				if !isUnknownValue(value) && !strings.Contains(value, "?") {
					keluargaIPValue = value
				}
			}
		}

		updated := map[string]any{}

		if sundut != "" {
			sundutCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, keluargaTable, []string{"sundut"})
			if sundutCol == "" {
				sundutCol, _ = detectColumnByCandidates(ctx, a.db, keluargaTable, []string{"sundut"}, []string{"sundut"})
			}
			if sundutCol != "" {
				q := fmt.Sprintf(`UPDATE %s SET %s = $1 WHERE %s::text = $2`, quoteIdent(keluargaTable), quoteIdent(sundutCol), quoteIdent(keyCol))
				res, err := a.db.Exec(ctx, q, sundut, ipValue)
				if err != nil {
					a.writeJSON(w, http.StatusInternalServerError, map[string]any{
						"ok":      false,
						"message": "gagal update sundut",
					})
					return
				}
				updated["sundutRows"] = res.RowsAffected()
			} else {
				updated["sundutRows"] = int64(0)
			}
		}

		if telp != "" {
			telpCandidates := []string{
				"mobile",
				"hp",
				"no_hp",
				"nohp",
				"nomor_hp",
				"nomorhp",
				"whatsapp",
				"wa",
				"telp",
				"nomortelp",
				"telepon",
				"phone",
			}
			telpCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, keluargaTable, telpCandidates)
			if telpCol == "" {
				telpCol, _ = detectColumnByCandidates(ctx, a.db, keluargaTable, telpCandidates, []string{"telp", "hp", "mobile"})
			}
			if telpCol != "" {
				q := fmt.Sprintf(`UPDATE %s SET %s = $1 WHERE %s::text = $2`, quoteIdent(keluargaTable), quoteIdent(telpCol), quoteIdent(keyCol))
				res, err := a.db.Exec(ctx, q, telp, ipValue)
				if err != nil {
					a.writeJSON(w, http.StatusInternalServerError, map[string]any{
						"ok":      false,
						"message": "gagal update telp",
					})
					return
				}
				updated["telpRows"] = res.RowsAffected()
			} else {
				updated["telpRows"] = int64(0)
			}

			ruasTable, _ := detectTableName(ctx, a.db, "ruasORJ")
			if ruasTable == "" {
				ruasTable, _ = detectTableName(ctx, a.db, "ruas")
			}
			if ruasTable != "" {
				ruasTelpCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, ruasTable, telpCandidates)
				if ruasTelpCol == "" {
					ruasTelpCol, _ = detectColumnByCandidates(ctx, a.db, ruasTable, telpCandidates, []string{"telp", "hp", "mobile"})
				}
				directKeyCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, ruasTable, []string{keyCol, strings.ToLower(keyCol), "ruasid", "rid", "ip", "id"})
				if directKeyCol == "" {
					directKeyCol, _ = detectColumnByCandidates(ctx, a.db, ruasTable, []string{keyCol, strings.ToLower(keyCol), "ruasid", "rid", "ip", "id"}, []string{keyCol, "ruasid", "rid", "ip", "id"})
				}
				if ruasTelpCol != "" && directKeyCol != "" {
					q := fmt.Sprintf(`UPDATE %s SET %s = $1 WHERE %s::text = $2 OR %s::text = $3`, quoteIdent(ruasTable), quoteIdent(ruasTelpCol), quoteIdent(directKeyCol), quoteIdent(directKeyCol))
					res, err := a.db.Exec(ctx, q, telp, ipValue, keluargaIPValue)
					if err != nil {
						a.writeJSON(w, http.StatusInternalServerError, map[string]any{
							"ok":      false,
							"message": "gagal update telp",
						})
						return
					}
					updated["telpRuasRows"] = res.RowsAffected()
				} else {
					updated["telpRuasRows"] = int64(0)
				}
			} else {
				updated["telpRuasRows"] = int64(0)
			}
		}

		if domisili != "" {
			alamatKeluargaCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, keluargaTable, []string{"alamat", "domisili", "address"})
			if alamatKeluargaCol == "" {
				alamatKeluargaCol, _ = detectColumnByCandidates(ctx, a.db, keluargaTable, []string{"alamat", "domisili", "address"}, []string{"alamat", "domisili", "address"})
			}
			if alamatKeluargaCol != "" {
				q := fmt.Sprintf(`UPDATE %s SET %s = $1 WHERE %s::text = $2`, quoteIdent(keluargaTable), quoteIdent(alamatKeluargaCol), quoteIdent(keyCol))
				res, err := a.db.Exec(ctx, q, domisili, ipValue)
				if err != nil {
					a.writeJSON(w, http.StatusInternalServerError, map[string]any{
						"ok":      false,
						"message": "gagal update domisili",
					})
					return
				}
				updated["domisiliKeluargaRows"] = res.RowsAffected()
			} else {
				updated["domisiliKeluargaRows"] = int64(0)
			}

			ruasTable, _ := detectTableName(ctx, a.db, "ruasORJ")
			if ruasTable == "" {
				ruasTable, _ = detectTableName(ctx, a.db, "ruas")
			}
			if ruasTable != "" {
				alamatCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, ruasTable, []string{"alamat", "address"})
				if alamatCol == "" {
					alamatCol, _ = detectColumnByCandidates(ctx, a.db, ruasTable, []string{"alamat", "address"}, []string{"alamat", "address"})
				}
				directKeyCol, _ := detectColumnByNormalizedCandidates(ctx, a.db, ruasTable, []string{keyCol, strings.ToLower(keyCol), "ruasid", "rid", "ip", "id"})
				if directKeyCol == "" {
					directKeyCol, _ = detectColumnByCandidates(ctx, a.db, ruasTable, []string{keyCol, strings.ToLower(keyCol), "ruasid", "rid", "ip", "id"}, []string{keyCol, "ruasid", "rid", "ip", "id"})
				}
				if alamatCol != "" && directKeyCol != "" {
					q := fmt.Sprintf(`UPDATE %s SET %s = $1 WHERE %s::text = $2 OR %s::text = $3`, quoteIdent(ruasTable), quoteIdent(alamatCol), quoteIdent(directKeyCol), quoteIdent(directKeyCol))
					res, err := a.db.Exec(ctx, q, domisili, ipValue, keluargaIPValue)
					if err != nil {
						a.writeJSON(w, http.StatusInternalServerError, map[string]any{
							"ok":      false,
							"message": "gagal update domisili",
						})
						return
					}
					updated["domisiliRows"] = res.RowsAffected()
				} else {
					updated["domisiliRows"] = int64(0)
				}
			} else {
				updated["domisiliRows"] = int64(0)
			}
		}

		a.writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"updated": updated,
		})
	}

	mux.HandleFunc("PATCH /api/absensi/detail", a.requireAuth(updateAbsensiDetail))
	mux.HandleFunc("POST /api/absensi/detail", a.requireAuth(updateAbsensiDetail))

	mux.HandleFunc("GET /api/absensi/kehadiran", a.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if a.db == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"ok":      false,
				"message": "database belum terhubung",
			})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		rows, err := a.db.Query(ctx, `
			SELECT ip, keluarga, mobile, dewasa, anak, ompu,
			       created_by_email, created_by_name,
			       (EXTRACT(EPOCH FROM updated_at) * 1000)::bigint AS updated_ms
			FROM daftar_kehadiran
			ORDER BY updated_at DESC
		`)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal mengambil data kehadiran",
			})
			return
		}
		defer rows.Close()

		out := make([]map[string]any, 0, 64)
		for rows.Next() {
			var ip, keluarga, mobile, ompu string
			var dewasa, anak int
			var updatedMs int64
			var createdByEmail *string
			var createdByName *string
			if err := rows.Scan(&ip, &keluarga, &mobile, &dewasa, &anak, &ompu, &createdByEmail, &createdByName, &updatedMs); err != nil {
				a.writeJSON(w, http.StatusInternalServerError, map[string]any{
					"ok":      false,
					"message": "gagal membaca data kehadiran",
				})
				return
			}
			out = append(out, map[string]any{
				"ip":             ip,
				"keluarga":       keluarga,
				"mobile":         mobile,
				"dewasa":         dewasa,
				"anak":           anak,
				"ompu":           ompu,
				"createdByEmail": createdByEmail,
				"createdByName":  createdByName,
				"updatedAt":      updatedMs,
			})
		}
		if err := rows.Err(); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal membaca data kehadiran",
			})
			return
		}

		a.writeJSON(w, http.StatusOK, map[string]any{
			"ok":   true,
			"rows": out,
		})
	}))

	mux.HandleFunc("POST /api/absensi/kehadiran", a.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if a.db == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"ok":      false,
				"message": "database belum terhubung",
			})
			return
		}

		var body struct {
			IP         string `json:"ip"`
			Keluarga   string `json:"keluarga"`
			Mobile     string `json:"mobile"`
			Dewasa     int    `json:"dewasa"`
			Anak       int    `json:"anak"`
			Ompu       string `json:"ompu"`
			AdminEmail string `json:"adminEmail"`
			AdminName  string `json:"adminName"`
		}
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&body); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "payload tidak valid",
			})
			return
		}

		ip := strings.TrimSpace(body.IP)
		keluarga := strings.TrimSpace(body.Keluarga)
		mobile := strings.TrimSpace(body.Mobile)
		ompu := strings.TrimSpace(body.Ompu)
		adminEmail := strings.TrimSpace(body.AdminEmail)
		adminName := strings.TrimSpace(body.AdminName)
		dewasa := body.Dewasa
		anak := body.Anak
		if ip == "" {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "ip wajib diisi",
			})
			return
		}
		if keluarga == "" {
			keluarga = "-"
		}
		if dewasa < 0 {
			dewasa = 0
		}
		if anak < 0 {
			anak = 0
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		var updatedMs int64
		var existingCreatedByEmail *string
		var existingCreatedByName *string

		_ = a.db.QueryRow(ctx, `
			SELECT created_by_email, created_by_name
			FROM daftar_kehadiran
			WHERE ip = $1
		`, ip).Scan(&existingCreatedByEmail, &existingCreatedByName)

		insertEmail := existingCreatedByEmail
		insertName := existingCreatedByName
		if insertEmail == nil && adminEmail != "" {
			insertEmail = &adminEmail
			insertName = &adminName
		}

		err := a.db.QueryRow(ctx, `
			INSERT INTO daftar_kehadiran (ip, keluarga, mobile, dewasa, anak, ompu, created_by_email, created_by_name, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
			ON CONFLICT (ip) DO UPDATE
			SET keluarga = EXCLUDED.keluarga,
			    mobile = EXCLUDED.mobile,
			    dewasa = EXCLUDED.dewasa,
			    anak = EXCLUDED.anak,
			    ompu = EXCLUDED.ompu,
			    updated_at = now()
			RETURNING (EXTRACT(EPOCH FROM updated_at) * 1000)::bigint
		`, ip, keluarga, mobile, dewasa, anak, ompu, insertEmail, insertName).Scan(&updatedMs)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal menyimpan data kehadiran",
			})
			return
		}

		if adminEmail != "" && adminName != "" {
			detailsJson, _ := json.Marshal(map[string]any{
				"dewasa": dewasa,
				"anak":   anak,
				"ompu":   ompu,
				"mobile": mobile,
			})
			_, _ = a.db.Exec(ctx, `
				INSERT INTO admin_activity_log (admin_email, admin_name, action, ip, keluarga, details)
				VALUES ($1, $2, 'add_kehadiran', $3, $4, $5)
			`, adminEmail, adminName, ip, keluarga, detailsJson)
		}

		if err := recomputeRekapHadir(ctx, a.db); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal update rekap hadir",
			})
			return
		}

		a.writeJSON(w, http.StatusOK, map[string]any{
			"ok": true,
			"row": map[string]any{
				"ip":             ip,
				"keluarga":       keluarga,
				"mobile":         mobile,
				"dewasa":         dewasa,
				"anak":           anak,
				"ompu":           ompu,
				"createdByEmail": insertEmail,
				"createdByName":  insertName,
				"updatedAt":      updatedMs,
			},
		})
	}))

	mux.HandleFunc("DELETE /api/absensi/kehadiran", a.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if a.db == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"ok":      false,
				"message": "database belum terhubung",
			})
			return
		}

		ip := strings.TrimSpace(r.URL.Query().Get("ip"))
		if ip == "" {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "ip wajib diisi",
			})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		_, err := a.db.Exec(ctx, `DELETE FROM daftar_kehadiran WHERE ip = $1`, ip)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal menghapus data kehadiran",
			})
			return
		}
		_ = recomputeRekapHadir(ctx, a.db)
		a.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))

	mux.HandleFunc("DELETE /api/absensi/kehadiran/all", a.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if a.db == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"ok":      false,
				"message": "database belum terhubung",
			})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		_, err := a.db.Exec(ctx, `TRUNCATE TABLE daftar_kehadiran`)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal menghapus semua data kehadiran",
			})
			return
		}
		_ = recomputeRekapHadir(ctx, a.db)
		a.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))

	mux.HandleFunc("GET /api/reports/keluarga.pdf", a.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if a.db == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"ok":      false,
				"message": "database belum terhubung",
			})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		cols := []reportColumn{
			{Header: "Nama", Candidates: []string{"nama", "name", "nama_lengkap"}},
			{Header: "Marga", Candidates: []string{"fam", "marga", "family", "fam_name"}},
			{Header: "Sebagai", Candidates: []string{"hub", "sebagai", "status"}},
			{Header: "Tanggal Lahir", Candidates: []string{"tgllahir", "tgl_lahir", "tanggal_lahir", "lahir"}},
			{Header: "Tanggal Wafat", Candidates: []string{"tglwafat", "tgl_wafat", "tanggal_wafat", "wafat"}},
			{Header: "Sundut", Candidates: []string{"sundut"}},
			{Header: "Nomor HP", Candidates: []string{"hp", "telp", "phone", "no_hp", "nomor_hp"}},
		}

		pdfBytes, err := buildReportPDF(ctx, a.db, "keluarga", "Rekap Data Keluarga", cols)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal membuat pdf",
			})
			return
		}

		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="rekap-keluarga.pdf"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pdfBytes)
	}))

	mux.HandleFunc("GET /api/reports/ruasorj.pdf", a.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if a.db == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"ok":      false,
				"message": "database belum terhubung",
			})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 80*time.Second)
		defer cancel()

		cols := []reportColumn{
			{Header: "Registrasi", Candidates: []string{"reg", "registrasi"}},
			{Header: "Nomor Registrasi", Candidates: []string{"noreg", "no_reg", "no_registrasi", "nomor_registrasi"}},
			{Header: "Ruas", Candidates: []string{"ruas"}},
			{Header: "Sundut", Candidates: []string{"sundut"}},
			{Header: "Nama", Candidates: []string{"nama", "name", "nama_lengkap"}},
			{Header: "Marga", Candidates: []string{"marga", "fam", "family"}},
			{Header: "Mertua", Candidates: []string{"mertua"}},
			{Header: "Alamat", Candidates: []string{"alamat", "address"}},
			{Header: "Camat", Candidates: []string{"camat", "kecamatan"}},
			{Header: "Kota", Candidates: []string{"kota", "kabupaten", "city"}},
			{Header: "Nomor HP", Candidates: []string{"telp", "hp", "phone", "no_hp", "nomor_hp"}},
			{Header: "Email", Candidates: []string{"email"}},
		}

		pdfBytes, err := buildReportPDF(ctx, a.db, "ruasORJ", "Rekap Data Ruas ORJ", cols)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal membuat pdf",
			})
			return
		}

		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="rekap-ruasorj.pdf"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pdfBytes)
	}))

	mux.HandleFunc("POST /api/import-excel", a.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if a.db == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"ok":      false,
				"message": "database belum terhubung",
			})
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 20<<20)
		if err := r.ParseMultipartForm(20 << 20); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "gagal membaca form upload",
			})
			return
		}

		rawTableName := strings.TrimSpace(r.FormValue("tableName"))
		tableName, err := validateTableName(rawTableName)
		if err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": err.Error(),
			})
			return
		}

		file, header, err := r.FormFile("file")
		if err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "file belum diupload",
			})
			return
		}
		defer file.Close()

		filename := strings.ToLower(strings.TrimSpace(header.Filename))
		if !strings.HasSuffix(filename, ".xlsx") {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "hanya mendukung file .xlsx",
			})
			return
		}

		content, err := io.ReadAll(file)
		if err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "gagal membaca file",
			})
			return
		}

		f, err := excelize.OpenReader(bytes.NewReader(content))
		if err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "file excel tidak valid",
			})
			return
		}
		defer func() { _ = f.Close() }()

		sheets := f.GetSheetList()
		if len(sheets) == 0 {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "sheet tidak ditemukan",
			})
			return
		}

		rows, err := f.GetRows(sheets[0])
		if err != nil || len(rows) == 0 {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "data excel kosong",
			})
			return
		}

		columns := normalizeHeaders(rows[0])
		if len(columns) == 0 {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":      false,
				"message": "judul kolom tidak ditemukan",
			})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		quotedTable := quoteIdent(tableName)
		colDefs := make([]string, 0, len(columns))
		quotedCols := make([]string, 0, len(columns))
		for _, c := range columns {
			quoted := quoteIdent(c)
			quotedCols = append(quotedCols, quoted)
			colDefs = append(colDefs, fmt.Sprintf("%s TEXT", quoted))
		}

		createSQL := fmt.Sprintf("CREATE TABLE %s (%s)", quotedTable, strings.Join(colDefs, ", "))
		if _, err := a.db.Exec(ctx, createSQL); err != nil {
			if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "42P07" {
				a.writeJSON(w, http.StatusConflict, map[string]any{
					"ok":      false,
					"message": "nama tabel sudah ada",
				})
				return
			}
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal membuat tabel",
			})
			return
		}

		tx, err := a.db.Begin(ctx)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal memulai transaksi",
			})
			return
		}
		defer func() { _ = tx.Rollback(ctx) }()

		placeholders := make([]string, len(columns))
		for i := range columns {
			placeholders[i] = fmt.Sprintf("$%d", i+1)
		}
		insertSQL := fmt.Sprintf(
			"INSERT INTO %s (%s) VALUES (%s)",
			quotedTable,
			strings.Join(quotedCols, ", "),
			strings.Join(placeholders, ", "),
		)

		var batch pgx.Batch
		inserted := 0
		for i := 1; i < len(rows); i++ {
			row := rows[i]
			args := make([]any, len(columns))
			for j := range columns {
				if j < len(row) {
					args[j] = row[j]
				} else {
					args[j] = ""
				}
			}
			batch.Queue(insertSQL, args...)
			inserted++
		}

		if inserted > 0 {
			br := tx.SendBatch(ctx, &batch)
			for i := 0; i < inserted; i++ {
				_, err := br.Exec()
				if err != nil {
					_ = br.Close()
					a.writeJSON(w, http.StatusInternalServerError, map[string]any{
						"ok":      false,
						"message": "gagal menyimpan data",
					})
					return
				}
			}
			_ = br.Close()
		}

		if err := tx.Commit(ctx); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":      false,
				"message": "gagal commit",
			})
			return
		}

		a.writeJSON(w, http.StatusOK, map[string]any{
			"ok":        true,
			"tableName": tableName,
			"columns":   columns,
			"inserted":  inserted,
		})
	}))

	mux.HandleFunc("GET /api/activity", a.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		a.writeJSON(w, http.StatusOK, []map[string]any{
			{"id": "act-1", "title": "Data keluarga baru masuk", "detail": "1 entri menunggu verifikasi", "time": now.Add(-20 * time.Second).UnixMilli()},
			{"id": "act-2", "title": "Absensi diperbarui", "detail": "2 anggota check-in", "time": now.Add(-85 * time.Second).UnixMilli()},
			{"id": "act-3", "title": "Sinkronisasi data selesai", "detail": "Tidak ada konflik", "time": now.Add(-11 * time.Minute).UnixMilli()},
		})
	}))

	mux.HandleFunc("GET /api/attendance", a.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		a.writeJSON(w, http.StatusOK, []map[string]any{
			{"id": "adm-1", "name": "Admin Utama", "role": "Admin", "status": "online", "lastSeen": now.UnixMilli()},
			{"id": "sek-1", "name": "Sekretariat", "role": "Operator", "status": "online", "lastSeen": now.Add(-15 * time.Second).UnixMilli()},
			{"id": "keg-1", "name": "Koordinator Kegiatan", "role": "Operator", "status": "away", "lastSeen": now.Add(-75 * time.Second).UnixMilli()},
			{"id": "ver-1", "name": "Verifikator Data", "role": "Admin", "status": "offline", "lastSeen": now.Add(-25 * time.Minute).UnixMilli()},
		})
	}))

	return a.withCORS(a.withLogging(mux))
}

func (a *api) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Truncate(time.Millisecond))
	})
}

func (a *api) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && (a.allowAllCORS || a.isAllowedOrigin(origin)) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Session-Token")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", "600")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *api) isAllowedOrigin(origin string) bool {
	if len(a.allowedOrigins) == 0 {
		return false
	}
	_, ok := a.allowedOrigins[origin]
	return ok
}

func (a *api) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return n
}

func envStrings(key string, fallback []string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}

var tableNameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`)

func validateTableName(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("nama tabel wajib diisi")
	}
	if !tableNameRe.MatchString(value) {
		return "", fmt.Errorf("nama tabel hanya boleh huruf/angka/underscore dan tidak boleh diawali angka")
	}
	return value, nil
}

func quoteIdent(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return `""`
	}
	parts := strings.Split(value, ".")
	quoted := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		quoted = append(quoted, `"`+strings.ReplaceAll(p, `"`, `""`)+`"`)
	}
	return strings.Join(quoted, ".")
}

func splitQualifiedTableName(table string) (string, string) {
	table = strings.TrimSpace(table)
	if table == "" {
		return "public", ""
	}
	if i := strings.IndexByte(table, '.'); i >= 0 {
		schema := strings.TrimSpace(table[:i])
		name := strings.TrimSpace(table[i+1:])
		if schema == "" {
			schema = "public"
		}
		return schema, name
	}
	return "public", table
}

func ensureAdminAccountsTable(ctx context.Context, db *pgxpool.Pool) error {
	if db == nil {
		return nil
	}
	_, err := db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS admin_accounts (
			id SERIAL PRIMARY KEY,
			email text UNIQUE NOT NULL,
			password text NOT NULL,
			name text NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now()
		)
	`)
	if err != nil {
		return err
	}

	adminAccounts := []struct {
		email    string
		password string
		name     string
	}{
		{"admin1@gmail.com", "admin123", "Admin 1"},
		{"admin2@gmail.com", "admin123", "Admin 2"},
		{"admin3@gmail.com", "admin123", "Admin 3"},
		{"admin4@gmail.com", "admin123", "Admin 4"},
		{"admin5@gmail.com", "admin123", "Admin 5"},
		{"admin6@gmail.com", "admin123", "Admin 6"},
	}

	for _, acc := range adminAccounts {
		_, err = db.Exec(ctx, `
			INSERT INTO admin_accounts (email, password, name)
			VALUES ($1, $2, $3)
			ON CONFLICT (email) DO NOTHING
		`, acc.email, acc.password, acc.name)
		if err != nil {
			return err
		}
	}

	return nil
}

func ensureAdminActivityLogTable(ctx context.Context, db *pgxpool.Pool) error {
	if db == nil {
		return nil
	}
	_, err := db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS admin_activity_log (
			id BIGSERIAL PRIMARY KEY,
			admin_email text NOT NULL,
			admin_name text NOT NULL,
			action text NOT NULL,
			ip text,
			keluarga text,
			details jsonb,
			created_at timestamptz NOT NULL DEFAULT now()
		)
	`)
	return err
}

func ensureDaftarKehadiranTable(ctx context.Context, db *pgxpool.Pool) error {
	if db == nil {
		return nil
	}
	_, err := db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS daftar_kehadiran (
			ip text PRIMARY KEY,
			keluarga text NOT NULL,
			mobile text NOT NULL DEFAULT '',
			dewasa integer NOT NULL DEFAULT 0,
			anak integer NOT NULL DEFAULT 0,
			ompu text NOT NULL DEFAULT '',
			created_by_email text,
			created_by_name text,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now()
		)
	`)
	if err != nil {
		return err
	}

	_, err = db.Exec(ctx, `
		ALTER TABLE daftar_kehadiran 
		ADD COLUMN IF NOT EXISTS created_by_email text,
		ADD COLUMN IF NOT EXISTS created_by_name text
	`)
	return err
}

func listColumns(ctx context.Context, db *pgxpool.Pool, tableName string) ([]string, error) {
	if db == nil {
		return nil, nil
	}
	schema, name := splitQualifiedTableName(tableName)
	if name == "" {
		return nil, nil
	}

	rows, err := db.Query(ctx, `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = $2
	`, schema, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]string, 0, 16)
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			return nil, err
		}
		out = append(out, col)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func detectTableByColumnAndKeys(ctx context.Context, db *pgxpool.Pool, columnCandidates []string, preferTableSubstrings []string, requiredKeyCandidates []string) (string, error) {
	if db == nil {
		return "", nil
	}

	normalizedCols := make([]string, 0, len(columnCandidates))
	for _, c := range columnCandidates {
		n := normalizeKey(c)
		if n != "" {
			normalizedCols = append(normalizedCols, n)
		}
	}
	if len(normalizedCols) == 0 {
		return "", nil
	}

	requiredKeyNorms := map[string]struct{}{}
	for _, k := range requiredKeyCandidates {
		n := normalizeKey(k)
		if n != "" {
			requiredKeyNorms[n] = struct{}{}
		}
	}

	type candidate struct {
		schema string
		table  string
		score  int
	}
	best := candidate{score: -1}

	for _, colNorm := range normalizedCols {
		rows, err := db.Query(ctx, `
			SELECT DISTINCT table_schema, table_name
			FROM information_schema.columns
			WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
			  AND LOWER(REPLACE(REPLACE(column_name, '_', ''), '-', '')) = $1
		`, colNorm)
		if err != nil {
			continue
		}

		for rows.Next() {
			var schema, table string
			if err := rows.Scan(&schema, &table); err != nil {
				rows.Close()
				return "", err
			}

			qualified := table
			if schema != "" && !strings.EqualFold(schema, "public") {
				qualified = schema + "." + table
			}

			cols, err := listColumns(ctx, db, qualified)
			if err != nil || len(cols) == 0 {
				continue
			}

			hasKey := false
			if len(requiredKeyNorms) == 0 {
				hasKey = true
			} else {
				for _, c := range cols {
					if _, ok := requiredKeyNorms[normalizeKey(c)]; ok {
						hasKey = true
						break
					}
				}
			}
			if !hasKey {
				continue
			}

			score := 0
			ln := strings.ToLower(table)
			for _, p := range preferTableSubstrings {
				p = strings.ToLower(strings.TrimSpace(p))
				if p != "" && strings.Contains(ln, p) {
					score += 10
				}
			}
			if strings.EqualFold(schema, "public") {
				score += 2
			}

			if score > best.score {
				best = candidate{schema: schema, table: table, score: score}
			}
		}
		rows.Close()
	}

	if best.score < 0 || best.table == "" {
		return "", nil
	}
	if best.schema == "" || strings.EqualFold(best.schema, "public") {
		return best.table, nil
	}
	return best.schema + "." + best.table, nil
}

func normalizeHeaders(header []string) []string {
	out := make([]string, 0, len(header))
	seen := map[string]int{}
	for i, raw := range header {
		name := strings.TrimSpace(raw)
		if name == "" {
			name = fmt.Sprintf("col_%d", i+1)
		}
		name = strings.ToLower(name)
		name = strings.ReplaceAll(name, " ", "_")
		name = strings.ReplaceAll(name, "-", "_")
		name = strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
				return r
			}
			return -1
		}, name)
		if name == "" {
			name = fmt.Sprintf("col_%d", i+1)
		}
		if name[0] >= '0' && name[0] <= '9' {
			name = "c_" + name
		}
		if len(name) > 63 {
			name = name[:63]
		}
		if count, ok := seen[name]; ok {
			count++
			seen[name] = count
			suffix := fmt.Sprintf("_%d", count)
			base := name
			if len(base)+len(suffix) > 63 {
				base = base[:63-len(suffix)]
			}
			name = base + suffix
		} else {
			seen[name] = 0
		}
		out = append(out, name)
	}
	return out
}

func detectTableName(ctx context.Context, db *pgxpool.Pool, desired string) (string, error) {
	if db == nil {
		return "", nil
	}

	var tableSchema, tableName string
	err := db.QueryRow(ctx, `
		SELECT table_schema, table_name
		FROM information_schema.tables
		WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
		  AND LOWER(table_name) = LOWER($1)
		ORDER BY CASE WHEN table_schema = 'public' THEN 0 ELSE 1 END, table_schema, table_name
		LIMIT 1
	`, desired).Scan(&tableSchema, &tableName)
	if err != nil {
		if err == pgx.ErrNoRows {
			desiredNorm := strings.ToLower(strings.ReplaceAll(desired, "_", ""))

			rows, listErr := db.Query(ctx, `
				SELECT table_schema, table_name
				FROM information_schema.tables
				WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
			`)
			if listErr != nil {
				return "", listErr
			}
			defer rows.Close()

			for rows.Next() {
				var schema, candidate string
				if err := rows.Scan(&schema, &candidate); err != nil {
					return "", err
				}
				candidateNorm := strings.ToLower(strings.ReplaceAll(candidate, "_", ""))
				if candidateNorm == desiredNorm {
					if schema == "" || strings.EqualFold(schema, "public") {
						return candidate, nil
					}
					return schema + "." + candidate, nil
				}
			}
			if err := rows.Err(); err != nil {
				return "", err
			}

			return "", nil
		}
		return "", err
	}
	if tableSchema == "" || strings.EqualFold(tableSchema, "public") {
		return tableName, nil
	}
	return tableSchema + "." + tableName, nil
}

func detectNameColumn(ctx context.Context, db *pgxpool.Pool, tableName string) (string, error) {
	if db == nil {
		return "", nil
	}

	schema, name := splitQualifiedTableName(tableName)
	if name == "" {
		return "", nil
	}

	rows, err := db.Query(ctx, `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = $2
	`, schema, name)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	lowerToActual := map[string]string{}
	existsLower := map[string]struct{}{}
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			return "", err
		}
		lower := strings.ToLower(col)
		if _, ok := lowerToActual[lower]; !ok {
			lowerToActual[lower] = col
		}
		existsLower[lower] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	candidates := []string{"nama", "name", "nama_lengkap", "nama_anggota", "full_name"}
	for _, c := range candidates {
		if _, ok := existsLower[c]; ok {
			return lowerToActual[c], nil
		}
	}

	for lower, actual := range lowerToActual {
		if strings.Contains(lower, "nama") {
			return actual, nil
		}
	}
	for lower, actual := range lowerToActual {
		if strings.Contains(lower, "name") {
			return actual, nil
		}
	}
	return "", nil
}

func countRowsByNameColumn(ctx context.Context, db *pgxpool.Pool, desiredTable string) int {
	if db == nil {
		return 0
	}

	tableName, err := detectTableName(ctx, db, desiredTable)
	if err != nil || tableName == "" {
		return 0
	}

	nameColumn, err := detectNameColumn(ctx, db, tableName)
	if err != nil || nameColumn == "" {
		return 0
	}

	count := 0
	_ = db.QueryRow(ctx, fmt.Sprintf(`
		SELECT COUNT(*)
		FROM %s
		WHERE NULLIF(BTRIM(%s::text), '') IS NOT NULL
		  AND BTRIM(%s::text) <> '?'
	`, quoteIdent(tableName), quoteIdent(nameColumn), quoteIdent(nameColumn))).Scan(&count)
	return count
}

func detectColumnByCandidates(ctx context.Context, db *pgxpool.Pool, tableName string, candidates []string, contains []string) (string, error) {
	if db == nil {
		return "", nil
	}

	schema, name := splitQualifiedTableName(tableName)
	if name == "" {
		return "", nil
	}

	rows, err := db.Query(ctx, `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = $2
	`, schema, name)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	lowerToActual := map[string]string{}
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			return "", err
		}
		lower := strings.ToLower(col)
		if _, ok := lowerToActual[lower]; !ok {
			lowerToActual[lower] = col
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	for _, c := range candidates {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		if actual, ok := lowerToActual[c]; ok {
			return actual, nil
		}
	}

	keys := make([]string, 0, len(lowerToActual))
	for lower := range lowerToActual {
		keys = append(keys, lower)
	}
	sort.Strings(keys)

	for _, sub := range contains {
		sub = strings.ToLower(strings.TrimSpace(sub))
		if sub == "" {
			continue
		}
		for _, lower := range keys {
			if strings.Contains(lower, sub) {
				return lowerToActual[lower], nil
			}
		}
	}

	return "", nil
}

func detectColumnByNormalizedCandidates(ctx context.Context, db *pgxpool.Pool, tableName string, candidates []string) (string, error) {
	if db == nil {
		return "", nil
	}

	schema, name := splitQualifiedTableName(tableName)
	if name == "" {
		return "", nil
	}

	rows, err := db.Query(ctx, `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = $2
	`, schema, name)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	normalizedToActual := map[string]string{}
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			return "", err
		}
		n := normalizeKey(col)
		if _, ok := normalizedToActual[n]; !ok {
			normalizedToActual[n] = col
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	for _, c := range candidates {
		n := normalizeKey(c)
		if n == "" {
			continue
		}
		if actual, ok := normalizedToActual[n]; ok {
			return actual, nil
		}
	}

	return "", nil
}

func querySingleTextByKey(ctx context.Context, db *pgxpool.Pool, tableName string, selectCol string, keyCol string, keyValue string) (string, error) {
	if db == nil || tableName == "" || selectCol == "" || keyCol == "" || strings.TrimSpace(keyValue) == "" {
		return "", nil
	}

	var val *string
	err := db.QueryRow(ctx, fmt.Sprintf(`
		SELECT %s::text
		FROM %s
		WHERE BTRIM(%s::text) = BTRIM($1::text)
		  AND NULLIF(BTRIM(%s::text), '') IS NOT NULL
		  AND BTRIM(%s::text) <> '?'
		LIMIT 1
	`, quoteIdent(selectCol), quoteIdent(tableName), quoteIdent(keyCol), quoteIdent(selectCol), quoteIdent(selectCol)), keyValue).Scan(&val)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	if val == nil {
		return "", nil
	}
	value := strings.TrimSpace(*val)
	if isUnknownValue(value) || strings.Contains(value, "?") {
		return "", nil
	}
	return value, nil
}

func querySingleTextByExactName(ctx context.Context, db *pgxpool.Pool, tableName string, selectCol string, nameCol string, nameValue string) (string, error) {
	if db == nil || tableName == "" || selectCol == "" || nameCol == "" || strings.TrimSpace(nameValue) == "" {
		return "", nil
	}

	var val *string
	err := db.QueryRow(ctx, fmt.Sprintf(`
		SELECT %s::text
		FROM %s
		WHERE LOWER(BTRIM(%s::text)) = LOWER(BTRIM($1::text))
		  AND NULLIF(BTRIM(%s::text), '') IS NOT NULL
		  AND BTRIM(%s::text) <> '?'
		LIMIT 1
	`, quoteIdent(selectCol), quoteIdent(tableName), quoteIdent(nameCol), quoteIdent(selectCol), quoteIdent(selectCol)), nameValue).Scan(&val)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	if val == nil {
		return "", nil
	}
	value := strings.TrimSpace(*val)
	if isUnknownValue(value) || strings.Contains(value, "?") {
		return "", nil
	}
	return value, nil
}

func querySingleTextByNameContains(ctx context.Context, db *pgxpool.Pool, tableName string, selectCol string, nameCol string, nameValue string) (string, error) {
	if db == nil || tableName == "" || selectCol == "" || nameCol == "" || strings.TrimSpace(nameValue) == "" {
		return "", nil
	}

	var val *string
	err := db.QueryRow(ctx, fmt.Sprintf(`
		SELECT %s::text
		FROM %s
		WHERE LOWER(BTRIM(%s::text)) LIKE ('%%' || LOWER(BTRIM($1::text)) || '%%')
		  AND NULLIF(BTRIM(%s::text), '') IS NOT NULL
		  AND BTRIM(%s::text) <> '?'
		LIMIT 1
	`, quoteIdent(selectCol), quoteIdent(tableName), quoteIdent(nameCol), quoteIdent(selectCol), quoteIdent(selectCol)), nameValue).Scan(&val)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	if val == nil {
		return "", nil
	}
	value := strings.TrimSpace(*val)
	if isUnknownValue(value) || strings.Contains(value, "?") {
		return "", nil
	}
	return value, nil
}

func firstNonEmptyByAnyKey(ctx context.Context, db *pgxpool.Pool, tableName string, selectCol string, keyCols []string, keyValues []string) (string, error) {
	seenKeyCols := map[string]struct{}{}
	uniqueKeyCols := make([]string, 0, len(keyCols))
	for _, c := range keyCols {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		l := strings.ToLower(c)
		if _, ok := seenKeyCols[l]; ok {
			continue
		}
		seenKeyCols[l] = struct{}{}
		uniqueKeyCols = append(uniqueKeyCols, c)
	}

	seenValues := map[string]struct{}{}
	uniqueValues := make([]string, 0, len(keyValues))
	for _, v := range keyValues {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seenValues[v]; ok {
			continue
		}
		seenValues[v] = struct{}{}
		uniqueValues = append(uniqueValues, v)
	}

	for _, keyCol := range uniqueKeyCols {
		for _, keyValue := range uniqueValues {
			got, err := querySingleTextByKey(ctx, db, tableName, selectCol, keyCol, keyValue)
			if err != nil {
				continue
			}
			if got != "" {
				return got, nil
			}
		}
	}
	return "", nil
}

func countRowsByColumnValues(ctx context.Context, db *pgxpool.Pool, desiredTable string, columnCandidates []string, values []string) int {
	if db == nil {
		return 0
	}

	tableName, err := detectTableName(ctx, db, desiredTable)
	if err != nil || tableName == "" {
		return 0
	}

	col, err := detectColumnByCandidates(ctx, db, tableName, columnCandidates, columnCandidates)
	if err != nil || col == "" {
		return 0
	}

	normalizedValues := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		normalizedValues = append(normalizedValues, v)
	}
	if len(normalizedValues) == 0 {
		return 0
	}

	count := 0
	_ = db.QueryRow(ctx, fmt.Sprintf(`
		SELECT COUNT(*)
		FROM %s
		WHERE NULLIF(BTRIM(%s::text), '') IS NOT NULL
		  AND BTRIM(%s::text) <> '?'
		  AND LOWER(BTRIM(%s::text)) = ANY($1)
	`, quoteIdent(tableName), quoteIdent(col), quoteIdent(col), quoteIdent(col)), normalizedValues).Scan(&count)
	return count
}

func countRowsByColumnRegex(ctx context.Context, db *pgxpool.Pool, desiredTable string, columnCandidates []string, pattern string) int {
	if db == nil {
		return 0
	}

	tableName, err := detectTableName(ctx, db, desiredTable)
	if err != nil || tableName == "" {
		return 0
	}

	col, err := detectColumnByCandidates(ctx, db, tableName, columnCandidates, columnCandidates)
	if err != nil || col == "" {
		return 0
	}

	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return 0
	}

	count := 0
	_ = db.QueryRow(ctx, fmt.Sprintf(`
		SELECT COUNT(*)
		FROM %s
		WHERE NULLIF(BTRIM(%s::text), '') IS NOT NULL
		  AND BTRIM(%s::text) <> '?'
		  AND (BTRIM(%s::text) ~* $1)
	`, quoteIdent(tableName), quoteIdent(col), quoteIdent(col), quoteIdent(col)), pattern).Scan(&count)
	return count
}

func classifyHub(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	v = strings.ReplaceAll(v, ".", " ")
	v = strings.ReplaceAll(v, "_", " ")
	v = strings.ReplaceAll(v, "-", " ")
	v = strings.Join(strings.Fields(v), " ")
	if isUnknownValue(v) {
		return ""
	}
	if strings.Contains(v, "suami") {
		return "suami"
	}
	if strings.Contains(v, "istri") || strings.Contains(v, "isteri") {
		return "istri"
	}
	if strings.Contains(v, "anak") {
		return "anak"
	}
	if strings.Contains(v, "boru") {
		return "boru"
	}
	return ""
}

func isUnknownValue(value string) bool {
	v := strings.TrimSpace(value)
	if v == "" {
		return true
	}
	all := true
	for _, r := range v {
		if r == ' ' || r == '.' || r == ',' {
			continue
		}
		if r != '?' && r != '-' {
			all = false
			break
		}
	}
	return all
}

func dashIfEmpty(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func formatPomparan(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	var b strings.Builder
	b.Grow(len(value))

	lastWasBar := false
	lastWasSpace := false
	for _, r := range value {
		if r >= '0' && r <= '9' {
			if !lastWasBar {
				b.WriteByte('|')
				lastWasBar = true
			}
			lastWasSpace = false
			continue
		}

		if r == '/' || r == ';' || r == ',' || r == '\n' || r == '\r' {
			if !lastWasBar {
				b.WriteByte('|')
				lastWasBar = true
			}
			lastWasSpace = false
			continue
		}

		if r == '\t' || r == ' ' {
			if lastWasBar || lastWasSpace {
				continue
			}
			b.WriteByte(' ')
			lastWasSpace = true
			lastWasBar = false
			continue
		}

		b.WriteRune(r)
		lastWasBar = r == '|'
		lastWasSpace = false
	}

	raw := strings.TrimSpace(b.String())
	if raw == "" {
		return ""
	}

	partsRaw := strings.Split(raw, "|")
	parts := make([]string, 0, len(partsRaw))
	seen := map[string]struct{}{}
	for _, p := range partsRaw {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		p = strings.Join(strings.Fields(p), " ")
		if p == "" {
			continue
		}
		key := strings.ToLower(p)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		parts = append(parts, p)
	}

	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " / ")
}

func formatMobile(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	partsRaw := strings.FieldsFunc(value, func(r rune) bool {
		return r == '/' || r == ';' || r == ',' || r == '|' || r == '\n' || r == '\r'
	})

	best := ""
	bestScore := -1
	for _, part := range partsRaw {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		normalized := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, part)
		normalized = strings.TrimSpace(normalized)
		if normalized == "" {
			continue
		}

		var digitsB strings.Builder
		digitsB.Grow(len(normalized))
		for _, r := range normalized {
			if r >= '0' && r <= '9' {
				digitsB.WriteRune(r)
			}
		}
		digits := digitsB.String()
		if len(digits) < 6 {
			continue
		}

		score := len(digits)
		if strings.HasPrefix(digits, "08") || strings.HasPrefix(digits, "628") || strings.HasPrefix(normalized, "+628") {
			score += 20
		}
		if score > bestScore {
			bestScore = score
			best = normalized
		}
	}

	best = strings.TrimSpace(best)
	if best == "" || isUnknownValue(best) {
		return ""
	}
	return best
}

func scoreMobile(value string) int {
	value = strings.TrimSpace(value)
	if value == "" || isUnknownValue(value) {
		return -1
	}
	digitCount := 0
	for _, r := range value {
		if r >= '0' && r <= '9' {
			digitCount++
		}
	}
	if digitCount < 6 {
		return -1
	}
	score := digitCount
	digitsOnly := make([]rune, 0, len(value))
	for _, r := range value {
		if r >= '0' && r <= '9' {
			digitsOnly = append(digitsOnly, r)
		}
	}
	digits := string(digitsOnly)
	if strings.HasPrefix(digits, "08") || strings.HasPrefix(digits, "628") || strings.HasPrefix(value, "+628") {
		score += 20
	}
	return score
}

func anyToString(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return fmt.Sprint(v)
	}
}

func bestAbsensiFallback(ctx context.Context, db *pgxpool.Pool, tableName string, keyCol string, keyValue string) (string, string, error) {
	if db == nil || tableName == "" || keyCol == "" || strings.TrimSpace(keyValue) == "" {
		return "", "", nil
	}

	query := fmt.Sprintf(`
		SELECT *
		FROM %s
		WHERE BTRIM(%s::text) = BTRIM($1::text)
		LIMIT 50
	`, quoteIdent(tableName), quoteIdent(keyCol))

	rows, err := db.Query(ctx, query, keyValue)
	if err != nil {
		return "", "", err
	}
	defer rows.Close()

	alamat := ""
	alamatScore := -1
	telp := ""
	telpScore := -1

	addressTokens := []string{"alamat", "domisili", "address", "jalan", "jln", "jl", "kota", "kab", "kecamatan", "kec", "kelurahan", "kel", "prov", "wilayah", "daerah"}
	phoneTokens := []string{"hp", "telp", "telepon", "phone", "mobile", "wa", "whatsapp", "handphone", "nohp", "nomorhp"}
	addressValueTokens := []string{"jl", "jln", "jalan", "rt", "rw", "blok", "perum", "kp", "kamp", "dusun", "desa", "kel", "kec", "kab", "kota", "prov", "gang", "gg", "no"}

	fieldDescs := rows.FieldDescriptions()
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return "", "", err
		}
		for i := 0; i < len(fieldDescs) && i < len(vals); i++ {
			col := strings.ToLower(string(fieldDescs[i].Name))
			raw := strings.TrimSpace(anyToString(vals[i]))
			if raw == "" || isUnknownValue(raw) || strings.Contains(raw, "?") {
				continue
			}

			maybeAddressCol := false
			for _, t := range addressTokens {
				if strings.Contains(col, t) {
					maybeAddressCol = true
					break
				}
			}
			if maybeAddressCol {
				score := len([]rune(raw))
				lowerVal := strings.ToLower(raw)
				if strings.Contains(lowerVal, "jl") || strings.Contains(lowerVal, "jln") || strings.Contains(lowerVal, "rt") {
					score += 30
				}
				if score > alamatScore {
					alamatScore = score
					alamat = raw
				}
			} else if alamat == "" {
				lowerVal := strings.ToLower(raw)
				hasAddrToken := false
				for _, t := range addressValueTokens {
					if strings.Contains(lowerVal, t) {
						hasAddrToken = true
						break
					}
				}
				if hasAddrToken && len([]rune(raw)) >= 12 {
					score := len([]rune(raw))
					if score > alamatScore {
						alamatScore = score
						alamat = raw
					}
				}
			}

			maybePhoneCol := false
			for _, t := range phoneTokens {
				if strings.Contains(col, t) {
					maybePhoneCol = true
					break
				}
			}
			candidate := formatMobile(raw)
			score := scoreMobile(candidate)
			if score >= 0 {
				onlyDigits := strings.TrimPrefix(candidate, "+")
				if strings.HasPrefix(onlyDigits, "08") || strings.HasPrefix(onlyDigits, "628") {
					if maybePhoneCol || score >= 30 {
						if score > telpScore {
							telpScore = score
							telp = candidate
						}
					}
				} else if maybePhoneCol {
					if score > telpScore {
						telpScore = score
						telp = candidate
					}
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return "", "", err
	}
	return alamat, telp, nil
}

func bestAbsensiFallbackByName(ctx context.Context, db *pgxpool.Pool, tableName string, names []string) (string, string, error) {
	if db == nil || tableName == "" {
		return "", "", nil
	}

	normalizedNames := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" || isUnknownValue(n) || strings.Contains(n, "?") {
			continue
		}
		normalizedNames = append(normalizedNames, n)
	}
	if len(normalizedNames) == 0 {
		return "", "", nil
	}

	textCols, err := listTextColumns(ctx, db, tableName)
	if err != nil {
		return "", "", err
	}
	nameCols := make([]string, 0, 8)
	seen := map[string]struct{}{}
	priority := []string{"nama", "name", "nama_lengkap", "namaanggota", "full_name"}
	for _, p := range priority {
		actual, _ := detectColumnByNormalizedCandidates(ctx, db, tableName, []string{p})
		if actual == "" {
			continue
		}
		l := strings.ToLower(actual)
		if _, ok := seen[l]; ok {
			continue
		}
		seen[l] = struct{}{}
		nameCols = append(nameCols, actual)
	}
	for _, c := range textCols {
		l := strings.ToLower(c)
		if _, ok := seen[l]; ok {
			continue
		}
		n := normalizeKey(c)
		if strings.Contains(n, "nama") || strings.Contains(n, "name") {
			seen[l] = struct{}{}
			nameCols = append(nameCols, c)
		}
	}
	if len(nameCols) == 0 {
		return "", "", nil
	}

	alamat := ""
	alamatScore := -1
	telp := ""
	telpScore := -1

	addressTokens := []string{"alamat", "domisili", "address", "jalan", "jln", "jl", "kota", "kab", "kecamatan", "kec", "kelurahan", "kel", "prov", "wilayah", "daerah"}
	phoneTokens := []string{"hp", "telp", "telepon", "phone", "mobile", "wa", "whatsapp", "handphone", "nohp", "nomorhp"}
	addressValueTokens := []string{"jl", "jln", "jalan", "rt", "rw", "blok", "perum", "kp", "kamp", "dusun", "desa", "kel", "kec", "kab", "kota", "prov", "gang", "gg", "no"}

	for _, nameCol := range nameCols {
		for _, nameValue := range normalizedNames {
			for _, mode := range []string{"exact", "contains"} {
				where := ""
				if mode == "exact" {
					where = fmt.Sprintf("LOWER(BTRIM(%s::text)) = LOWER(BTRIM($1::text))", quoteIdent(nameCol))
				} else {
					where = fmt.Sprintf("LOWER(BTRIM(%s::text)) LIKE ('%%' || LOWER(BTRIM($1::text)) || '%%')", quoteIdent(nameCol))
				}
				query := fmt.Sprintf(`
					SELECT *
					FROM %s
					WHERE %s
					LIMIT 10
				`, quoteIdent(tableName), where)

				rows, err := db.Query(ctx, query, nameValue)
				if err != nil {
					continue
				}
				fieldDescs := rows.FieldDescriptions()
				for rows.Next() {
					vals, err := rows.Values()
					if err != nil {
						rows.Close()
						return "", "", err
					}
					for i := 0; i < len(fieldDescs) && i < len(vals); i++ {
						col := strings.ToLower(string(fieldDescs[i].Name))
						raw := strings.TrimSpace(anyToString(vals[i]))
						if raw == "" || isUnknownValue(raw) || strings.Contains(raw, "?") {
							continue
						}

						maybeAddressCol := false
						for _, t := range addressTokens {
							if strings.Contains(col, t) {
								maybeAddressCol = true
								break
							}
						}
						if maybeAddressCol {
							score := len([]rune(raw))
							lowerVal := strings.ToLower(raw)
							if strings.Contains(lowerVal, "jl") || strings.Contains(lowerVal, "jln") || strings.Contains(lowerVal, "rt") {
								score += 30
							}
							if score > alamatScore {
								alamatScore = score
								alamat = raw
							}
						}
						if alamat == "" {
							lowerVal := strings.ToLower(raw)
							hasAddrToken := false
							for _, t := range addressValueTokens {
								if strings.Contains(lowerVal, t) {
									hasAddrToken = true
									break
								}
							}
							if hasAddrToken && len([]rune(raw)) >= 12 {
								score := len([]rune(raw))
								if score > alamatScore {
									alamatScore = score
									alamat = raw
								}
							}
						}

						maybePhoneCol := false
						for _, t := range phoneTokens {
							if strings.Contains(col, t) {
								maybePhoneCol = true
								break
							}
						}
						candidate := formatMobile(raw)
						score := scoreMobile(candidate)
						if score >= 0 {
							onlyDigits := strings.TrimPrefix(candidate, "+")
							if strings.HasPrefix(onlyDigits, "08") || strings.HasPrefix(onlyDigits, "628") {
								if maybePhoneCol || score >= 30 {
									if score > telpScore {
										telpScore = score
										telp = candidate
									}
								}
							} else if maybePhoneCol {
								if score > telpScore {
									telpScore = score
									telp = candidate
								}
							}
						}
					}
				}
				rows.Close()

				if alamatScore >= 0 && telpScore >= 0 {
					return alamat, telp, nil
				}
			}
		}
	}

	return alamat, telp, nil
}

func keysSorted(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		k = strings.TrimSpace(k)
		if isUnknownValue(k) {
			continue
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func firstOrEmpty(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func pickAbsensiKey(ctx context.Context, db *pgxpool.Pool, tableName string, nameCol string, hubCol string, expected int) (absensiKeyPick, error) {
	out := absensiKeyPick{
		KeyColumn:       "",
		CandidateCounts: map[string]int{},
	}
	if db == nil {
		return out, nil
	}

	schema, name := splitQualifiedTableName(tableName)
	if name == "" {
		return out, nil
	}

	rows, err := db.Query(ctx, `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = $2
	`, schema, name)
	if err != nil {
		return out, err
	}
	defer rows.Close()

	normalizedToActual := map[string]string{}
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			return out, err
		}
		n := normalizeKey(col)
		if _, ok := normalizedToActual[n]; !ok {
			normalizedToActual[n] = col
		}
	}
	if err := rows.Err(); err != nil {
		return out, err
	}

	candidates := []string{
		"ip",
		"kk",
		"no_kk",
		"nokk",
		"nomor_kk",
		"nomorkk",
		"id_kk",
		"idkk",
		"noreg",
		"no_reg",
		"reg",
		"registrasi",
		"id_keluarga",
		"idkeluarga",
	}

	type stat struct {
		col   string
		count int
	}
	stats := make([]stat, 0, 32)

	suamiPattern := "\\msuami"
	istriPattern := "\\mistri|\\misteri"
	coupleFor := func(actual string) int {
		if actual == "" {
			return 0
		}
		couples := 0
		_ = db.QueryRow(ctx, fmt.Sprintf(`
			SELECT COUNT(*)
			FROM (
				SELECT %s::text AS k
				FROM %s
				WHERE NULLIF(BTRIM(%s::text), '') IS NOT NULL
				  AND BTRIM(%s::text) <> '?'
				  AND NULLIF(BTRIM(%s::text), '') IS NOT NULL
				  AND BTRIM(%s::text) <> '?'
				  AND NULLIF(BTRIM(%s::text), '') IS NOT NULL
				  AND (BTRIM(%s::text) ~* $1 OR BTRIM(%s::text) ~* $2)
				GROUP BY k
				HAVING BOOL_OR(BTRIM(%s::text) ~* $1) AND BOOL_OR(BTRIM(%s::text) ~* $2)
			) x
		`, quoteIdent(actual), quoteIdent(tableName),
			quoteIdent(actual), quoteIdent(actual),
			quoteIdent(nameCol), quoteIdent(nameCol),
			quoteIdent(hubCol),
			quoteIdent(hubCol), quoteIdent(hubCol),
			quoteIdent(hubCol), quoteIdent(hubCol)), suamiPattern, istriPattern).Scan(&couples)
		return couples
	}

	if actual, ok := normalizedToActual["ip"]; ok && actual != "" && actual != nameCol && actual != hubCol {
		couples := coupleFor(actual)
		out.CandidateCounts[actual] = couples
		if expected > 0 && couples >= (expected*60)/100 {
			out.KeyColumn = actual
			return out, nil
		}
	}

	for _, c := range candidates {
		actual, ok := normalizedToActual[normalizeKey(c)]
		if !ok || actual == "" {
			continue
		}
		couples := coupleFor(actual)
		out.CandidateCounts[actual] = couples
		stats = append(stats, stat{col: actual, count: couples})
	}

	textCols, _ := listTextColumns(ctx, db, tableName)
	for _, c := range textCols {
		if c == "" || c == nameCol || c == hubCol {
			continue
		}
		if _, ok := out.CandidateCounts[c]; ok {
			continue
		}
		couples := coupleFor(c)
		out.CandidateCounts[c] = couples
		stats = append(stats, stat{col: c, count: couples})
	}

	if len(stats) == 0 {
		return out, nil
	}

	best := stats[0]
	bestScore := absInt(best.count - expected)
	for i := 1; i < len(stats); i++ {
		s := stats[i]
		if s.count <= 0 {
			continue
		}
		score := absInt(s.count - expected)
		if score < bestScore {
			best = s
			bestScore = score
		}
	}

	out.KeyColumn = best.col
	return out, nil
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func listTextColumns(ctx context.Context, db *pgxpool.Pool, tableName string) ([]string, error) {
	if db == nil {
		return nil, nil
	}

	schema, name := splitQualifiedTableName(tableName)
	if name == "" {
		return nil, nil
	}

	rows, err := db.Query(ctx, `
		SELECT column_name, data_type, udt_name
		FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = $2
	`, schema, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]string, 0, 16)
	for rows.Next() {
		var col, dataType, udtName string
		if err := rows.Scan(&col, &dataType, &udtName); err != nil {
			return nil, err
		}
		dataType = strings.ToLower(strings.TrimSpace(dataType))
		udtName = strings.ToLower(strings.TrimSpace(udtName))
		if dataType == "text" || dataType == "character varying" || dataType == "character" || udtName == "citext" {
			out = append(out, col)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func countRowsByTokens(ctx context.Context, db *pgxpool.Pool, desiredTable string, columnCandidates []string, tokens []string) int {
	if db == nil {
		return 0
	}

	tableName, err := detectTableName(ctx, db, desiredTable)
	if err != nil || tableName == "" {
		return 0
	}

	normalizedTokens := make([]string, 0, len(tokens))
	for _, t := range tokens {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		normalizedTokens = append(normalizedTokens, t)
	}
	if len(normalizedTokens) == 0 {
		return 0
	}

	seenColumns := map[string]struct{}{}
	columnsToTry := make([]string, 0, len(columnCandidates))
	for _, c := range columnCandidates {
		actual, err := detectColumnByCandidates(ctx, db, tableName, []string{c}, []string{c})
		if err != nil || actual == "" {
			continue
		}
		lower := strings.ToLower(actual)
		if _, ok := seenColumns[lower]; ok {
			continue
		}
		seenColumns[lower] = struct{}{}
		columnsToTry = append(columnsToTry, actual)
	}

	if len(columnsToTry) == 0 {
		allText, err := listTextColumns(ctx, db, tableName)
		if err != nil {
			return 0
		}
		for _, c := range allText {
			lower := strings.ToLower(c)
			if _, ok := seenColumns[lower]; ok {
				continue
			}
			seenColumns[lower] = struct{}{}
			columnsToTry = append(columnsToTry, c)
		}
	}

	patterns := make([]any, 0, len(normalizedTokens))
	for _, t := range normalizedTokens {
		patterns = append(patterns, "%"+t+"%")
	}

	best := 0
	for _, col := range columnsToTry {
		orParts := make([]string, 0, len(patterns))
		for i := range patterns {
			orParts = append(orParts, fmt.Sprintf("LOWER(BTRIM(%s::text)) LIKE $%d", quoteIdent(col), i+1))
		}
		sql := fmt.Sprintf(`
			SELECT COUNT(*)
			FROM %s
			WHERE NULLIF(BTRIM(%s::text), '') IS NOT NULL
			  AND BTRIM(%s::text) <> '?'
			  AND (%s)
		`, quoteIdent(tableName), quoteIdent(col), quoteIdent(col), strings.Join(orParts, " OR "))

		count := 0
		if err := db.QueryRow(ctx, sql, patterns...).Scan(&count); err != nil {
			continue
		}
		if count > best {
			best = count
		}
	}

	if best == 0 {
		allText, err := listTextColumns(ctx, db, tableName)
		if err != nil {
			return 0
		}

		for _, col := range allText {
			if _, ok := seenColumns[strings.ToLower(col)]; ok {
				continue
			}

			orParts := make([]string, 0, len(patterns))
			for i := range patterns {
				orParts = append(orParts, fmt.Sprintf("LOWER(BTRIM(%s::text)) LIKE $%d", quoteIdent(col), i+1))
			}
			sql := fmt.Sprintf(`
				SELECT COUNT(*)
				FROM %s
				WHERE NULLIF(BTRIM(%s::text), '') IS NOT NULL
				  AND BTRIM(%s::text) <> '?'
				  AND (%s)
			`, quoteIdent(tableName), quoteIdent(col), quoteIdent(col), strings.Join(orParts, " OR "))

			count := 0
			if err := db.QueryRow(ctx, sql, patterns...).Scan(&count); err != nil {
				continue
			}
			if count > best {
				best = count
			}
		}
	}

	return best
}

func countNonEmptyByColumnCandidates(ctx context.Context, db *pgxpool.Pool, desiredTable string, columnCandidates []string) int {
	if db == nil {
		return 0
	}

	tableName, err := detectTableName(ctx, db, desiredTable)
	if err != nil || tableName == "" {
		return 0
	}

	col, err := detectColumnByCandidates(ctx, db, tableName, columnCandidates, columnCandidates)
	if err != nil || col == "" {
		return 0
	}

	count := 0
	_ = db.QueryRow(ctx, fmt.Sprintf(`
		SELECT COUNT(*)
		FROM %s
		WHERE NULLIF(BTRIM(%s::text), '') IS NOT NULL
		  AND BTRIM(%s::text) <> '?'
	`, quoteIdent(tableName), quoteIdent(col), quoteIdent(col))).Scan(&count)
	return count
}

func loadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if os.Getenv(key) != "" {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		_ = os.Setenv(key, value)
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

type reportColumn struct {
	Header     string
	Candidates []string
}

func normalizeKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "_", "")
	value = strings.ReplaceAll(value, "-", "")
	return value
}

func sanitizePDFText(value string) string {
	if value == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		if r <= 255 {
			b.WriteRune(r)
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}

func cropText(value string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(value)
	if len(r) <= max {
		return value
	}
	if max <= 3 {
		return string(r[:max])
	}
	return string(r[:max-3]) + "..."
}

func resolveReportColumns(ctx context.Context, db *pgxpool.Pool, tableName string, cols []reportColumn) ([]string, []string, error) {
	rows, err := db.Query(ctx, `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1
	`, tableName)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	lowerToActual := map[string]string{}
	normalizedToActual := map[string]string{}
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			return nil, nil, err
		}
		lower := strings.ToLower(col)
		if _, ok := lowerToActual[lower]; !ok {
			lowerToActual[lower] = col
		}
		n := normalizeKey(col)
		if _, ok := normalizedToActual[n]; !ok {
			normalizedToActual[n] = col
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	headers := make([]string, 0, len(cols))
	actualCols := make([]string, 0, len(cols))
	for _, c := range cols {
		headers = append(headers, c.Header)
		actual := ""
		for _, cand := range c.Candidates {
			candLower := strings.ToLower(strings.TrimSpace(cand))
			if candLower == "" {
				continue
			}
			if v, ok := lowerToActual[candLower]; ok {
				actual = v
				break
			}
			if v, ok := normalizedToActual[normalizeKey(candLower)]; ok {
				actual = v
				break
			}
		}
		if actual == "" {
			for lower, v := range lowerToActual {
				for _, cand := range c.Candidates {
					candLower := strings.ToLower(strings.TrimSpace(cand))
					if candLower == "" {
						continue
					}
					if strings.Contains(lower, candLower) {
						actual = v
						break
					}
				}
				if actual != "" {
					break
				}
			}
		}
		actualCols = append(actualCols, actual)
	}

	return headers, actualCols, nil
}

func buildReportPDF(ctx context.Context, db *pgxpool.Pool, desiredTable string, title string, cols []reportColumn) ([]byte, error) {
	tableName, err := detectTableName(ctx, db, desiredTable)
	if err != nil || tableName == "" {
		return nil, fmt.Errorf("table not found")
	}

	headers, actualCols, err := resolveReportColumns(ctx, db, tableName, cols)
	if err != nil {
		return nil, err
	}

	selectParts := make([]string, 0, len(actualCols))
	for _, col := range actualCols {
		if col == "" {
			selectParts = append(selectParts, "''")
			continue
		}
		selectParts = append(selectParts, fmt.Sprintf("COALESCE(%s::text,'')", quoteIdent(col)))
	}

	where := ""
	args := []any{}
	nameCol, _ := detectNameColumn(ctx, db, tableName)
	if nameCol != "" {
		where = fmt.Sprintf("WHERE NULLIF(BTRIM(%s::text), '') IS NOT NULL AND BTRIM(%s::text) <> '?'", quoteIdent(nameCol), quoteIdent(nameCol))
	}

	orderBy := ""
	if nameCol != "" {
		orderBy = fmt.Sprintf("ORDER BY BTRIM(%s::text) ASC", quoteIdent(nameCol))
	}

	query := fmt.Sprintf("SELECT %s FROM %s %s %s", strings.Join(selectParts, ", "), quoteIdent(tableName), where, orderBy)
	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	outRows := make([][]string, 0, 256)
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			return nil, err
		}
		record := make([]string, 0, len(values))
		for _, v := range values {
			if v == nil {
				record = append(record, "")
				continue
			}
			record = append(record, fmt.Sprint(v))
		}
		outRows = append(outRows, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	orientation := "P"
	if len(headers) > 8 {
		orientation = "L"
	}
	pdf := gofpdf.New(orientation, "mm", "A4", "")
	pdf.SetMargins(10, 10, 10)
	pdf.SetAutoPageBreak(true, 12)
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 14)
	pdf.CellFormat(0, 8, sanitizePDFText(title), "", 1, "L", false, 0, "")
	pdf.Ln(2)

	pageW, _ := pdf.GetPageSize()
	left, top, right, bottom := pdf.GetMargins()
	usableW := pageW - left - right
	colW := usableW / float64(len(headers))

	headerLineH := 4.8
	bodyLineH := 4.2
	fontSize := 8.0
	if len(headers) > 10 {
		fontSize = 6.8
	}
	if len(headers) > 14 {
		fontSize = 6.2
	}

	pageH := 297.0
	if orientation == "L" {
		pageH = 210.0
	}

	splitLines := func(style string, size float64, text string) [][]byte {
		pdf.SetFont("Arial", style, size)
		return pdf.SplitLines([]byte(sanitizePDFText(text)), colW)
	}

	drawRow := func(style string, size float64, lineH float64, texts []string) {
		linesPerCell := make([][][]byte, len(texts))
		maxLines := 1
		for i := range texts {
			lines := splitLines(style, size, texts[i])
			if len(lines) == 0 {
				lines = [][]byte{[]byte("")}
			}
			linesPerCell[i] = lines
			if len(lines) > maxLines {
				maxLines = len(lines)
			}
		}

		rowH := float64(maxLines) * lineH
		if pdf.GetY()+rowH > pageH-bottom {
			pdf.AddPage()
			pdf.SetY(top)
		}

		startY := pdf.GetY()
		pdf.SetFont("Arial", style, size)
		for i := range texts {
			x := left + float64(i)*colW
			pdf.Rect(x, startY, colW, rowH, "D")
			pdf.SetXY(x, startY)
			pdf.MultiCell(colW, lineH, sanitizePDFText(texts[i]), "", "L", false)
		}
		pdf.SetXY(left, startY+rowH)
	}

	drawRow("B", 8.5, headerLineH, headers)

	for _, row := range outRows {
		values := make([]string, len(headers))
		for i := range headers {
			if i < len(row) {
				values[i] = row[i]
			}
		}

		if pdf.GetY()+bodyLineH > pageH-bottom {
			pdf.AddPage()
			pdf.SetY(top)
			drawRow("B", 8.5, headerLineH, headers)
		}
		drawRow("", fontSize, bodyLineH, values)
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
