package apiserver

import (
	"context"
	"educationHTTP-restAPI/internal/app/model"
	"educationHTTP-restAPI/internal/app/store"
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
	"net/http"
	"strconv"
	"time"
)

const (
	sessionName        = "Amkhadsession"
	ctxKeyUser  ctxKey = iota
	ctxKeyRequestID
)

var (
	errIncorrectEmailOrPassword = errors.New("incorrect email or password")
	errNotAuthenticated         = errors.New("not authenticated")
)

type ctxKey int8

type Server struct {
	router       *mux.Router
	logger       *logrus.Logger
	store        store.Store
	sessionStore sessions.Store
}

func newServer(store store.Store, sessionStore sessions.Store) *Server {
	s := &Server{
		router:       mux.NewRouter(),
		logger:       logrus.New(),
		store:        store,
		sessionStore: sessionStore,
	}

	s.configureRouter()

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) configureRouter() {
	s.router.Use(s.setRequestID)
	s.router.Use(s.logRequest)
	s.router.Use(handlers.CORS(handlers.AllowedOrigins([]string{"*"})))
	s.router.HandleFunc("/users", s.handleUsersCreate()).Methods("POST")
	s.router.HandleFunc("/sessions", s.handleSessionsCreate()).Methods("POST")
	s.router.HandleFunc("/refresh-token", s.handleTokenRefresh()).Methods("POST")
	s.router.HandleFunc("/logout", s.handleLogout()).Methods("POST")

	// /private/***
	private := s.router.PathPrefix("/private").Subrouter()
	private.Use(s.authenticateUser)
	private.HandleFunc("/whoami", s.handleWhoami()).Methods("GET")
}

func (s *Server) setRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.New().String()
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyRequestID, id)))
	})
}

func (s *Server) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := s.logger.WithFields(logrus.Fields{
			"remote_addr": r.RemoteAddr,
			"request_id":  r.Context().Value(ctxKeyRequestID),
		})
		logger.Infof("started %s %s", r.Method, r.RequestURI)

		start := time.Now()
		rw := &responseWriter{w, http.StatusOK}
		next.ServeHTTP(rw, r)

		logger.Infof(
			"completed with %d %s in %v",
			rw.code,
			http.StatusText(rw.code),
			time.Now().Sub(start))
	})
}

func (s *Server) authenticateUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || len(authHeader) < 8 || authHeader[:7] != "Bearer " {
			s.error(w, r, http.StatusUnauthorized, errNotAuthenticated)
			return
		}
		tokenStr := authHeader[7:]

		claims := &tokenClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return accessSecret, nil
		})
		if err != nil || !token.Valid {
			s.error(w, r, http.StatusUnauthorized, errNotAuthenticated)
			return
		}

		u, err := s.store.User().Find(claims.UserID)
		if err != nil {
			s.error(w, r, http.StatusUnauthorized, errNotAuthenticated)
			return
		}

		ctx := context.WithValue(r.Context(), ctxKeyUser, u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) handleWhoami() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.respond(w, r, http.StatusOK, r.Context().Value(ctxKeyUser).(*model.User))
	}
}

func (s *Server) handleUsersCreate() http.HandlerFunc {
	type request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
		}

		u := &model.User{
			Email:    req.Email,
			Password: req.Password,
		}
		if err := s.store.User().Create(u); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		u.Sanitize()
		s.respond(w, r, http.StatusCreated, u)
	}
}

func (s *Server) handleSessionsCreate() http.HandlerFunc {
	type request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var req request
		var resp response
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		u, err := s.store.User().FindByEmail(req.Email)
		if err != nil || !u.ComparePassword(req.Password) {
			s.error(w, r, http.StatusUnauthorized, errIncorrectEmailOrPassword)
			return
		}

		//existingTokens, err := s.store.RefreshToken().CountByUserID(u.ID)
		//if err != nil {
		//	s.error(w, r, http.StatusInternalServerError, err)
		//	return
		//}
		//if existingTokens > 0 {
		//	s.error(w, r, http.StatusBadRequest, errors.New("already authenticated"))
		//	return
		//}

		accessToken, err := generateAccessToken(u.ID)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}
		resp.AccessToken = accessToken

		refreshToken, jti, expiresAt, err := generateRefreshToken(u.ID)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}
		resp.RefreshToken = refreshToken

		// Сохраняем в БД
		if err := s.store.RefreshToken().Save(jti, u.ID, expiresAt); err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		s.respond(w, r, http.StatusOK, resp)
	}
}

func (s *Server) error(w http.ResponseWriter, r *http.Request, code int, err error) {
	s.respond(w, r, code, map[string]string{"error": err.Error()})
}

func (s *Server) respond(w http.ResponseWriter, r *http.Request, code int, data interface{}) {
	w.WriteHeader(code)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

func (s *Server) handleTokenRefresh() http.HandlerFunc {
	type request struct {
		RefreshToken string `json:"refresh_token"`
	}

	type response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var req request
		var resp response
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		token, err := jwt.ParseWithClaims(req.RefreshToken, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
			return refreshSecret, nil
		})
		if err != nil || !token.Valid {
			s.error(w, r, http.StatusUnauthorized, err)
			return
		}

		claims, ok := token.Claims.(*jwt.RegisteredClaims)
		if !ok {
			s.error(w, r, http.StatusUnauthorized, errors.New("invalid token claims"))
			return
		}

		// Проверяем, что токен ещё существует в БД
		exists, err := s.store.RefreshToken().Exists(claims.ID)
		if err != nil || !exists {
			s.error(w, r, http.StatusUnauthorized, errors.New("refresh token expired or revoked"))
			return
		}

		// Создаём новый Access токен
		userID, _ := strconv.Atoi(claims.Subject)
		accessToken, err := generateAccessToken(userID)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}
		resp.AccessToken = accessToken

		// Удаляем старый токен
		if err := s.store.RefreshToken().Delete(claims.ID); err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		refreshToken, jti, expiresAt, err := generateRefreshToken(userID)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}
		resp.RefreshToken = refreshToken

		// Сохраняем в БД
		if err := s.store.RefreshToken().Save(jti, userID, expiresAt); err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		s.respond(w, r, http.StatusOK, resp)
	}
}

func (s *Server) handleLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("refresh_token")
		if err != nil {
			s.error(w, r, http.StatusUnauthorized, errNotAuthenticated)
			return
		}

		// Парсим токен, чтобы достать jti
		token, err := jwt.ParseWithClaims(cookie.Value, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
			return refreshSecret, nil
		})
		if err != nil || !token.Valid {
			s.error(w, r, http.StatusUnauthorized, errors.New("invalid token"))
			return
		}

		claims, ok := token.Claims.(*jwt.RegisteredClaims)
		if !ok {
			s.error(w, r, http.StatusUnauthorized, errors.New("invalid claims"))
			return
		}

		// Удаляем refresh token из БД
		_ = s.store.RefreshToken().Delete(claims.ID)

		// Удаляем куку
		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})

		s.respond(w, r, http.StatusOK, map[string]string{"message": "logged out"})
	}
}

func (s *Server) StartRefreshTokenCleanup(interval time.Duration, stopChan <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := s.store.CleanUpExpiredRefreshTokens()
			if err != nil {
				s.logger.Errorf("failed to cleanup expired refresh tokens: %v", err)
			} else {
				s.logger.Info("expired refresh tokens cleaned up successfully")
			}
		case <-stopChan:
			s.logger.Info("stopping refresh token cleanup goroutine")
			return
		}
	}
}
