package scheduling

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/medrex/dlt-emr/pkg/database"
	"github.com/medrex/dlt-emr/pkg/interfaces"
	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
)

// Repository implements the SchedulingRepository interface
type Repository struct {
	db     *database.DB
	logger logger.Logger
}

// NewRepository creates a new scheduling repository
func NewRepository(db *database.DB, log logger.Logger) interfaces.SchedulingRepository {
	return &Repository{
		db:     db,
		logger: log,
	}
}

// CreateAppointment creates a new appointment
func (r *Repository) CreateAppointment(apt *types.Appointment) error {
	query := `
		INSERT INTO appointments (
			id, patient_id, provider_id, appointment_type, start_time, end_time, 
			status, encrypted_notes, encryption_key_id, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	_, err := r.db.Exec(query,
		apt.ID,
		apt.PatientID,
		apt.ProviderID,
		apt.Type,
		apt.StartTime,
		apt.EndTime,
		apt.Status,
		nil, // encrypted_notes - will be implemented with encryption
		nil, // encryption_key_id - will be set when encryption is implemented
		apt.PatientID, // created_by - using patient_id for now
		apt.PatientID, // updated_by - using patient_id for now
	)

	if err != nil {
		r.logger.Error("Failed to create appointment: %v", err)
		return fmt.Errorf("failed to create appointment: %w", err)
	}

	r.logger.Info("Created appointment %s for patient %s with provider %s", apt.ID, apt.PatientID, apt.ProviderID)
	return nil
}

// GetAppointmentByID retrieves an appointment by ID
func (r *Repository) GetAppointmentByID(id string) (*types.Appointment, error) {
	query := `
		SELECT id, patient_id, provider_id, appointment_type, start_time, end_time, 
			   status, created_at, updated_at
		FROM appointments 
		WHERE id = $1`

	apt := &types.Appointment{}
	err := r.db.QueryRow(query, id).Scan(
		&apt.ID,
		&apt.PatientID,
		&apt.ProviderID,
		&apt.Type,
		&apt.StartTime,
		&apt.EndTime,
		&apt.Status,
		&apt.CreatedAt,
		&apt.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("appointment not found: %s", id)
		}
		r.logger.Error("Failed to get appointment %s: %v", id, err)
		return nil, fmt.Errorf("failed to get appointment: %w", err)
	}

	return apt, nil
}

// UpdateAppointment updates an existing appointment
func (r *Repository) UpdateAppointment(id string, updates *types.AppointmentUpdates) error {
	setParts := []string{}
	args := []interface{}{}
	argIndex := 1

	if updates.StartTime != nil {
		setParts = append(setParts, fmt.Sprintf("start_time = $%d", argIndex))
		args = append(args, *updates.StartTime)
		argIndex++
	}

	if updates.EndTime != nil {
		setParts = append(setParts, fmt.Sprintf("end_time = $%d", argIndex))
		args = append(args, *updates.EndTime)
		argIndex++
	}

	if updates.Status != nil {
		setParts = append(setParts, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, string(*updates.Status))
		argIndex++
	}

	if updates.Location != nil {
		setParts = append(setParts, fmt.Sprintf("location = $%d", argIndex))
		args = append(args, *updates.Location)
		argIndex++
	}

	if len(setParts) == 0 {
		return fmt.Errorf("no updates provided")
	}

	setParts = append(setParts, fmt.Sprintf("updated_at = $%d", argIndex))
	args = append(args, time.Now())
	argIndex++

	query := fmt.Sprintf("UPDATE appointments SET %s WHERE id = $%d", strings.Join(setParts, ", "), argIndex)
	args = append(args, id)

	result, err := r.db.Exec(query, args...)
	if err != nil {
		r.logger.Error("Failed to update appointment %s: %v", id, err)
		return fmt.Errorf("failed to update appointment: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("appointment not found: %s", id)
	}

	r.logger.Info("Updated appointment %s", id)
	return nil
}

// DeleteAppointment soft deletes an appointment (sets status to cancelled)
func (r *Repository) DeleteAppointment(id string) error {
	query := `UPDATE appointments SET status = 'cancelled', updated_at = $1 WHERE id = $2`

	result, err := r.db.Exec(query, time.Now(), id)
	if err != nil {
		r.logger.Error("Failed to delete appointment %s: %v", id, err)
		return fmt.Errorf("failed to delete appointment: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("appointment not found: %s", id)
	}

	r.logger.Info("Deleted appointment %s", id)
	return nil
}

// GetAppointments retrieves appointments based on filters
func (r *Repository) GetAppointments(filters *types.AppointmentFilters) ([]*types.Appointment, error) {
	query := `
		SELECT id, patient_id, provider_id, appointment_type, start_time, end_time, 
			   status, created_at, updated_at
		FROM appointments 
		WHERE 1=1`

	args := []interface{}{}
	argIndex := 1

	if filters.PatientID != "" {
		query += fmt.Sprintf(" AND patient_id = $%d", argIndex)
		args = append(args, filters.PatientID)
		argIndex++
	}

	if filters.ProviderID != "" {
		query += fmt.Sprintf(" AND provider_id = $%d", argIndex)
		args = append(args, filters.ProviderID)
		argIndex++
	}

	if filters.Status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIndex)
		args = append(args, string(filters.Status))
		argIndex++
	}

	if filters.Type != "" {
		query += fmt.Sprintf(" AND appointment_type = $%d", argIndex)
		args = append(args, string(filters.Type))
		argIndex++
	}

	if !filters.FromDate.IsZero() {
		query += fmt.Sprintf(" AND start_time >= $%d", argIndex)
		args = append(args, filters.FromDate)
		argIndex++
	}

	if !filters.ToDate.IsZero() {
		query += fmt.Sprintf(" AND start_time <= $%d", argIndex)
		args = append(args, filters.ToDate)
		argIndex++
	}

	query += " ORDER BY start_time ASC"

	if filters.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, filters.Limit)
		argIndex++
	}

	if filters.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIndex)
		args = append(args, filters.Offset)
	}

	rows, err := r.db.Query(query, args...)
	if err != nil {
		r.logger.Error("Failed to get appointments: %v", err)
		return nil, fmt.Errorf("failed to get appointments: %w", err)
	}
	defer rows.Close()

	var appointments []*types.Appointment
	for rows.Next() {
		apt := &types.Appointment{}
		err := rows.Scan(
			&apt.ID,
			&apt.PatientID,
			&apt.ProviderID,
			&apt.Type,
			&apt.StartTime,
			&apt.EndTime,
			&apt.Status,
			&apt.CreatedAt,
			&apt.UpdatedAt,
		)
		if err != nil {
			r.logger.Error("Failed to scan appointment: %v", err)
			return nil, fmt.Errorf("failed to scan appointment: %w", err)
		}
		appointments = append(appointments, apt)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating appointments: %w", err)
	}

	return appointments, nil
}

// CreateProvider creates a new provider
func (r *Repository) CreateProvider(provider *types.Provider) error {
	query := `
		INSERT INTO providers (id, user_id, specialty, license_number, department, is_active)
		VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := r.db.Exec(query,
		provider.ID,
		provider.UserID,
		provider.Specialty,
		provider.LicenseNumber,
		provider.Department,
		provider.IsActive,
	)

	if err != nil {
		r.logger.Error("Failed to create provider: %v", err)
		return fmt.Errorf("failed to create provider: %w", err)
	}

	r.logger.Info("Created provider %s for user %s", provider.ID, provider.UserID)
	return nil
}

// GetProviderByID retrieves a provider by ID
func (r *Repository) GetProviderByID(id string) (*types.Provider, error) {
	query := `
		SELECT id, user_id, specialty, license_number, department, is_active, created_at, updated_at
		FROM providers 
		WHERE id = $1`

	provider := &types.Provider{}
	err := r.db.QueryRow(query, id).Scan(
		&provider.ID,
		&provider.UserID,
		&provider.Specialty,
		&provider.LicenseNumber,
		&provider.Department,
		&provider.IsActive,
		&provider.CreatedAt,
		&provider.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("provider not found: %s", id)
		}
		r.logger.Error("Failed to get provider %s: %v", id, err)
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}

	return provider, nil
}

// GetProviderByUserID retrieves a provider by user ID
func (r *Repository) GetProviderByUserID(userID string) (*types.Provider, error) {
	query := `
		SELECT id, user_id, specialty, license_number, department, is_active, created_at, updated_at
		FROM providers 
		WHERE user_id = $1`

	provider := &types.Provider{}
	err := r.db.QueryRow(query, userID).Scan(
		&provider.ID,
		&provider.UserID,
		&provider.Specialty,
		&provider.LicenseNumber,
		&provider.Department,
		&provider.IsActive,
		&provider.CreatedAt,
		&provider.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("provider not found for user: %s", userID)
		}
		r.logger.Error("Failed to get provider for user %s: %v", userID, err)
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}

	return provider, nil
}

// UpdateProvider updates an existing provider
func (r *Repository) UpdateProvider(id string, updates map[string]interface{}) error {
	setParts := []string{}
	args := []interface{}{}
	argIndex := 1

	for field, value := range updates {
		setParts = append(setParts, fmt.Sprintf("%s = $%d", field, argIndex))
		args = append(args, value)
		argIndex++
	}

	if len(setParts) == 0 {
		return fmt.Errorf("no updates provided")
	}

	setParts = append(setParts, fmt.Sprintf("updated_at = $%d", argIndex))
	args = append(args, time.Now())
	argIndex++

	query := fmt.Sprintf("UPDATE providers SET %s WHERE id = $%d", strings.Join(setParts, ", "), argIndex)
	args = append(args, id)

	result, err := r.db.Exec(query, args...)
	if err != nil {
		r.logger.Error("Failed to update provider %s: %v", id, err)
		return fmt.Errorf("failed to update provider: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("provider not found: %s", id)
	}

	r.logger.Info("Updated provider %s", id)
	return nil
}

// GetProviders retrieves providers based on filters
func (r *Repository) GetProviders(filters map[string]interface{}, limit, offset int) ([]*types.Provider, error) {
	query := `
		SELECT id, user_id, specialty, license_number, department, is_active, created_at, updated_at
		FROM providers 
		WHERE 1=1`

	args := []interface{}{}
	argIndex := 1

	for field, value := range filters {
		query += fmt.Sprintf(" AND %s = $%d", field, argIndex)
		args = append(args, value)
		argIndex++
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
		r.logger.Error("Failed to get providers: %v", err)
		return nil, fmt.Errorf("failed to get providers: %w", err)
	}
	defer rows.Close()

	var providers []*types.Provider
	for rows.Next() {
		provider := &types.Provider{}
		err := rows.Scan(
			&provider.ID,
			&provider.UserID,
			&provider.Specialty,
			&provider.LicenseNumber,
			&provider.Department,
			&provider.IsActive,
			&provider.CreatedAt,
			&provider.UpdatedAt,
		)
		if err != nil {
			r.logger.Error("Failed to scan provider: %v", err)
			return nil, fmt.Errorf("failed to scan provider: %w", err)
		}
		providers = append(providers, provider)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating providers: %w", err)
	}

	return providers, nil
}

// GetConflictingAppointments finds appointments that conflict with a given time slot
func (r *Repository) GetConflictingAppointments(providerID string, timeSlot *types.TimeSlot) ([]*types.Appointment, error) {
	query := `
		SELECT id, patient_id, provider_id, appointment_type, start_time, end_time, 
			   status, created_at, updated_at
		FROM appointments 
		WHERE provider_id = $1 
		  AND status NOT IN ('cancelled', 'completed')
		  AND (
		    (start_time < $3 AND end_time > $2) OR
		    (start_time >= $2 AND start_time < $3)
		  )`

	rows, err := r.db.Query(query, providerID, timeSlot.StartTime, timeSlot.EndTime)
	if err != nil {
		r.logger.Error("Failed to get conflicting appointments: %v", err)
		return nil, fmt.Errorf("failed to get conflicting appointments: %w", err)
	}
	defer rows.Close()

	var appointments []*types.Appointment
	for rows.Next() {
		apt := &types.Appointment{}
		err := rows.Scan(
			&apt.ID,
			&apt.PatientID,
			&apt.ProviderID,
			&apt.Type,
			&apt.StartTime,
			&apt.EndTime,
			&apt.Status,
			&apt.CreatedAt,
			&apt.UpdatedAt,
		)
		if err != nil {
			r.logger.Error("Failed to scan conflicting appointment: %v", err)
			return nil, fmt.Errorf("failed to scan conflicting appointment: %w", err)
		}
		appointments = append(appointments, apt)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating conflicting appointments: %w", err)
	}

	return appointments, nil
}

// GetProviderSchedule retrieves all appointments for a provider on a specific date
func (r *Repository) GetProviderSchedule(providerID string, date string) ([]*types.Appointment, error) {
	startDate, err := time.Parse("2006-01-02", date)
	if err != nil {
		return nil, fmt.Errorf("invalid date format: %w", err)
	}

	endDate := startDate.Add(24 * time.Hour)

	query := `
		SELECT id, patient_id, provider_id, appointment_type, start_time, end_time, 
			   status, created_at, updated_at
		FROM appointments 
		WHERE provider_id = $1 
		  AND start_time >= $2 
		  AND start_time < $3
		  AND status NOT IN ('cancelled')
		ORDER BY start_time ASC`

	rows, err := r.db.Query(query, providerID, startDate, endDate)
	if err != nil {
		r.logger.Error("Failed to get provider schedule: %v", err)
		return nil, fmt.Errorf("failed to get provider schedule: %w", err)
	}
	defer rows.Close()

	var appointments []*types.Appointment
	for rows.Next() {
		apt := &types.Appointment{}
		err := rows.Scan(
			&apt.ID,
			&apt.PatientID,
			&apt.ProviderID,
			&apt.Type,
			&apt.StartTime,
			&apt.EndTime,
			&apt.Status,
			&apt.CreatedAt,
			&apt.UpdatedAt,
		)
		if err != nil {
			r.logger.Error("Failed to scan scheduled appointment: %v", err)
			return nil, fmt.Errorf("failed to scan scheduled appointment: %w", err)
		}
		appointments = append(appointments, apt)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating scheduled appointments: %w", err)
	}

	return appointments, nil
}