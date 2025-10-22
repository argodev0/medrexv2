package iam

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/medrex/dlt-emr/pkg/database"
	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
)

// UserRepository implements user data persistence
type UserRepository struct {
	db     *database.DB
	logger logger.Logger
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *database.DB, log logger.Logger) *UserRepository {
	return &UserRepository{
		db:     db,
		logger: log,
	}
}

// Create creates a new user in the database
func (r *UserRepository) Create(user *types.User) error {
	query := `
		INSERT INTO users (id, username, email, role, organization, 
			is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	// For development, we'll store email in plain text

	_, err := r.db.Exec(query,
		user.ID,
		user.Username,
		user.Email,
		user.Role,
		user.Organization,
		user.IsActive,
		user.CreatedAt,
		user.UpdatedAt,
	)

	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			switch pqErr.Code {
			case "23505": // unique_violation
				if strings.Contains(pqErr.Detail, "username") {
					return &types.MedrexError{
						Type:    types.ErrorTypeValidation,
						Code:    "USERNAME_EXISTS",
						Message: "Username already exists",
					}
				}
				return &types.MedrexError{
					Type:    types.ErrorTypeValidation,
					Code:    "DUPLICATE_USER",
					Message: "User already exists",
				}
			}
		}
		return fmt.Errorf("failed to create user: %w", err)
	}

	r.logger.Info("User created successfully", "user_id", user.ID, "username", user.Username)
	return nil
}

// GetByID retrieves a user by ID
func (r *UserRepository) GetByID(id string) (*types.User, error) {
	query := `
		SELECT id, username, email, role, organization, 
			is_active, created_at, updated_at
		FROM users 
		WHERE id = $1`

	var user types.User

	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.Role,
		&user.Organization,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, &types.MedrexError{
				Type:    types.ErrorTypeNotFound,
				Code:    "USER_NOT_FOUND",
				Message: "User not found",
			}
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return &user, nil
}

// GetByUsername retrieves a user by username
func (r *UserRepository) GetByUsername(username string) (*types.User, error) {
	query := `
		SELECT id, username, email, role, organization, 
			is_active, created_at, updated_at
		FROM users 
		WHERE username = $1`

	var user types.User

	err := r.db.QueryRow(query, username).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.Role,
		&user.Organization,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, &types.MedrexError{
				Type:    types.ErrorTypeNotFound,
				Code:    "USER_NOT_FOUND",
				Message: "User not found",
			}
		}
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}

	return &user, nil
}

// GetByEmail retrieves a user by email
func (r *UserRepository) GetByEmail(email string) (*types.User, error) {
	query := `
		SELECT id, username, email, role, organization, 
			is_active, created_at, updated_at
		FROM users 
		WHERE email = $1`

	var user types.User

	err := r.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.Role,
		&user.Organization,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, &types.MedrexError{
				Type:    types.ErrorTypeNotFound,
				Code:    "USER_NOT_FOUND",
				Message: "User not found",
			}
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return &user, nil
}

// Update updates user information
func (r *UserRepository) Update(id string, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return fmt.Errorf("no updates provided")
	}

	// Build dynamic update query
	setParts := make([]string, 0, len(updates))
	args := make([]interface{}, 0, len(updates)+1)
	argIndex := 1

	for field, value := range updates {
		switch field {
		case "email":
			// Encrypt email before storage (placeholder)
			setParts = append(setParts, fmt.Sprintf("encrypted_email = $%d", argIndex))
			args = append(args, []byte(value.(string)))
		case "role", "organization", "is_active", "last_login":
			setParts = append(setParts, fmt.Sprintf("%s = $%d", field, argIndex))
			args = append(args, value)
		default:
			return fmt.Errorf("invalid field for update: %s", field)
		}
		argIndex++
	}

	// Always update the updated_at timestamp
	setParts = append(setParts, fmt.Sprintf("updated_at = $%d", argIndex))
	args = append(args, time.Now())
	argIndex++

	// Add user ID as the last parameter
	args = append(args, id)

	query := fmt.Sprintf("UPDATE users SET %s WHERE id = $%d", 
		strings.Join(setParts, ", "), argIndex)

	result, err := r.db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return &types.MedrexError{
			Type:    types.ErrorTypeNotFound,
			Code:    "USER_NOT_FOUND",
			Message: "User not found",
		}
	}

	r.logger.Info("User updated successfully", "user_id", id, "fields", len(setParts))
	return nil
}

// Delete soft deletes a user (sets is_active to false)
func (r *UserRepository) Delete(id string) error {
	return r.Update(id, map[string]interface{}{
		"is_active": false,
	})
}

// List retrieves users with filtering and pagination
func (r *UserRepository) List(filters map[string]interface{}, limit, offset int) ([]*types.User, error) {
	baseQuery := `
		SELECT id, username, email, role, organization, 
			is_active, created_at, updated_at
		FROM users`

	whereParts := make([]string, 0)
	args := make([]interface{}, 0)
	argIndex := 1

	// Build WHERE clause from filters
	for field, value := range filters {
		switch field {
		case "role", "organization", "is_active":
			whereParts = append(whereParts, fmt.Sprintf("%s = $%d", field, argIndex))
			args = append(args, value)
			argIndex++
		case "username":
			whereParts = append(whereParts, fmt.Sprintf("username ILIKE $%d", argIndex))
			args = append(args, "%"+value.(string)+"%")
			argIndex++
		}
	}

	query := baseQuery
	if len(whereParts) > 0 {
		query += " WHERE " + strings.Join(whereParts, " AND ")
	}

	query += " ORDER BY created_at DESC"

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, limit)
		argIndex++
	}

	if offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIndex)
		args = append(args, offset)
	}

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*types.User
	for rows.Next() {
		var user types.User

		err := rows.Scan(
			&user.ID,
			&user.Username,
			&user.Email,
			&user.Role,
			&user.Organization,
			&user.IsActive,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user row: %w", err)
		}

		users = append(users, &user)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating user rows: %w", err)
	}

	r.logger.Info("Listed users successfully", "count", len(users), "filters", len(filters))
	return users, nil
}