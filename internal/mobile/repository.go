package mobile

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/medrex/dlt-emr/pkg/types"
)

// Repository implements the MobileRepository interface
type Repository struct {
	db *sql.DB
}

// NewRepository creates a new mobile repository
func NewRepository(db *sql.DB) *Repository {
	return &Repository{
		db: db,
	}
}

// CPOE Orders Repository Methods

// CreateOrder creates a new CPOE order in the database
func (r *Repository) CreateOrder(order *types.CPOEOrder) error {
	query := `
		INSERT INTO cpoe_orders (
			id, patient_id, ordering_md, co_signing_md, order_type, 
			details, status, priority, requires_co_sign, co_signed_at,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err := r.db.Exec(query,
		order.ID, order.PatientID, order.OrderingMD, order.CoSigningMD,
		order.OrderType, order.Details, order.Status, order.Priority,
		order.RequiresCoSign, order.CoSignedAt, order.CreatedAt, order.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create CPOE order: %w", err)
	}

	return nil
}

// GetOrderByID retrieves a CPOE order by ID
func (r *Repository) GetOrderByID(id string) (*types.CPOEOrder, error) {
	query := `
		SELECT id, patient_id, ordering_md, co_signing_md, order_type,
			   details, status, priority, requires_co_sign, co_signed_at,
			   created_at, updated_at
		FROM cpoe_orders
		WHERE id = $1
	`

	order := &types.CPOEOrder{}
	err := r.db.QueryRow(query, id).Scan(
		&order.ID, &order.PatientID, &order.OrderingMD, &order.CoSigningMD,
		&order.OrderType, &order.Details, &order.Status, &order.Priority,
		&order.RequiresCoSign, &order.CoSignedAt, &order.CreatedAt, &order.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("CPOE order not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get CPOE order: %w", err)
	}

	return order, nil
}

// UpdateOrder updates a CPOE order
func (r *Repository) UpdateOrder(id string, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return fmt.Errorf("no updates provided")
	}

	// Build dynamic update query
	setParts := make([]string, 0, len(updates))
	args := make([]interface{}, 0, len(updates)+1)
	argIndex := 1

	for field, value := range updates {
		setParts = append(setParts, fmt.Sprintf("%s = $%d", field, argIndex))
		args = append(args, value)
		argIndex++
	}

	query := fmt.Sprintf("UPDATE cpoe_orders SET %s WHERE id = $%d", 
		strings.Join(setParts, ", "), argIndex)
	args = append(args, id)

	result, err := r.db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("failed to update CPOE order: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("CPOE order not found: %s", id)
	}

	return nil
}

// GetOrdersByUser retrieves CPOE orders for a user with filters
func (r *Repository) GetOrdersByUser(userID string, filters map[string]interface{}) ([]*types.CPOEOrder, error) {
	baseQuery := `
		SELECT id, patient_id, ordering_md, co_signing_md, order_type,
			   details, status, priority, requires_co_sign, co_signed_at,
			   created_at, updated_at
		FROM cpoe_orders
		WHERE ordering_md = $1
	`

	args := []interface{}{userID}
	argIndex := 2

	// Add filters
	whereClauses := []string{}
	for field, value := range filters {
		switch field {
		case "patient_id", "order_type", "status", "priority":
			whereClauses = append(whereClauses, fmt.Sprintf("%s = $%d", field, argIndex))
			args = append(args, value)
			argIndex++
		case "requires_co_sign":
			whereClauses = append(whereClauses, fmt.Sprintf("requires_co_sign = $%d", argIndex))
			args = append(args, value)
			argIndex++
		}
	}

	query := baseQuery
	if len(whereClauses) > 0 {
		query += " AND " + strings.Join(whereClauses, " AND ")
	}

	query += " ORDER BY created_at DESC"

	// Add limit if specified
	if limit, exists := filters["limit"]; exists {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, limit)
		argIndex++
	}

	// Add offset if specified
	if offset, exists := filters["offset"]; exists {
		query += fmt.Sprintf(" OFFSET $%d", argIndex)
		args = append(args, offset)
	}

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query CPOE orders: %w", err)
	}
	defer rows.Close()

	var orders []*types.CPOEOrder
	for rows.Next() {
		order := &types.CPOEOrder{}
		err := rows.Scan(
			&order.ID, &order.PatientID, &order.OrderingMD, &order.CoSigningMD,
			&order.OrderType, &order.Details, &order.Status, &order.Priority,
			&order.RequiresCoSign, &order.CoSignedAt, &order.CreatedAt, &order.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan CPOE order: %w", err)
		}
		orders = append(orders, order)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating CPOE orders: %w", err)
	}

	return orders, nil
}

// GetPendingOrders retrieves orders pending co-signature for a consultant
func (r *Repository) GetPendingOrders(consultantID string) ([]*types.CPOEOrder, error) {
	query := `
		SELECT id, patient_id, ordering_md, co_signing_md, order_type,
			   details, status, priority, requires_co_sign, co_signed_at,
			   created_at, updated_at
		FROM cpoe_orders
		WHERE co_signing_md = $1 AND status = 'pending'
		ORDER BY created_at ASC
	`

	rows, err := r.db.Query(query, consultantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending orders: %w", err)
	}
	defer rows.Close()

	var orders []*types.CPOEOrder
	for rows.Next() {
		order := &types.CPOEOrder{}
		err := rows.Scan(
			&order.ID, &order.PatientID, &order.OrderingMD, &order.CoSigningMD,
			&order.OrderType, &order.Details, &order.Status, &order.Priority,
			&order.RequiresCoSign, &order.CoSignedAt, &order.CreatedAt, &order.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan pending order: %w", err)
		}
		orders = append(orders, order)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating pending orders: %w", err)
	}

	return orders, nil
}

// Medication Administration Repository Methods

// CreateMedicationAdmin creates a new medication administration record
func (r *Repository) CreateMedicationAdmin(admin *types.MedicationAdministration) error {
	query := `
		INSERT INTO medication_administrations (
			id, order_id, patient_id, nurse_id, medication_id,
			dose, route, administered_at, notes, verified, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err := r.db.Exec(query,
		admin.ID, admin.OrderID, admin.PatientID, admin.NurseID,
		admin.MedicationID, admin.Dose, admin.Route, admin.AdministeredAt,
		admin.Notes, admin.Verified, admin.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create medication administration: %w", err)
	}

	return nil
}

// GetMedicationAdminByID retrieves a medication administration record by ID
func (r *Repository) GetMedicationAdminByID(id string) (*types.MedicationAdministration, error) {
	query := `
		SELECT id, order_id, patient_id, nurse_id, medication_id,
			   dose, route, administered_at, notes, verified, created_at
		FROM medication_administrations
		WHERE id = $1
	`

	admin := &types.MedicationAdministration{}
	err := r.db.QueryRow(query, id).Scan(
		&admin.ID, &admin.OrderID, &admin.PatientID, &admin.NurseID,
		&admin.MedicationID, &admin.Dose, &admin.Route, &admin.AdministeredAt,
		&admin.Notes, &admin.Verified, &admin.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("medication administration not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get medication administration: %w", err)
	}

	return admin, nil
}

// GetMedicationSchedule retrieves medication schedule for a patient
func (r *Repository) GetMedicationSchedule(patientID string) ([]*types.MedicationAdministration, error) {
	query := `
		SELECT id, order_id, patient_id, nurse_id, medication_id,
			   dose, route, administered_at, notes, verified, created_at
		FROM medication_administrations
		WHERE patient_id = $1
		ORDER BY administered_at DESC
	`

	rows, err := r.db.Query(query, patientID)
	if err != nil {
		return nil, fmt.Errorf("failed to query medication schedule: %w", err)
	}
	defer rows.Close()

	var schedule []*types.MedicationAdministration
	for rows.Next() {
		admin := &types.MedicationAdministration{}
		err := rows.Scan(
			&admin.ID, &admin.OrderID, &admin.PatientID, &admin.NurseID,
			&admin.MedicationID, &admin.Dose, &admin.Route, &admin.AdministeredAt,
			&admin.Notes, &admin.Verified, &admin.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan medication administration: %w", err)
		}
		schedule = append(schedule, admin)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating medication schedule: %w", err)
	}

	return schedule, nil
}

// UpdateMedicationAdmin updates a medication administration record
func (r *Repository) UpdateMedicationAdmin(id string, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return fmt.Errorf("no updates provided")
	}

	// Build dynamic update query
	setParts := make([]string, 0, len(updates))
	args := make([]interface{}, 0, len(updates)+1)
	argIndex := 1

	for field, value := range updates {
		setParts = append(setParts, fmt.Sprintf("%s = $%d", field, argIndex))
		args = append(args, value)
		argIndex++
	}

	query := fmt.Sprintf("UPDATE medication_administrations SET %s WHERE id = $%d", 
		strings.Join(setParts, ", "), argIndex)
	args = append(args, id)

	result, err := r.db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("failed to update medication administration: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("medication administration not found: %s", id)
	}

	return nil
}

// Lab Results Repository Methods

// CreateLabResult creates a new lab result
func (r *Repository) CreateLabResult(result *types.LabResult) error {
	query := `
		INSERT INTO lab_results (
			id, order_id, patient_id, technician_id, test_name,
			result, units, reference_range, status, resulted_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err := r.db.Exec(query,
		result.ID, result.OrderID, result.PatientID, result.TechnicianID,
		result.TestName, result.Result, result.Units, result.ReferenceRange,
		result.Status, result.ResultedAt, result.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create lab result: %w", err)
	}

	return nil
}

// GetLabResultByID retrieves a lab result by ID
func (r *Repository) GetLabResultByID(id string) (*types.LabResult, error) {
	query := `
		SELECT id, order_id, patient_id, technician_id, test_name,
			   result, units, reference_range, status, resulted_at, created_at
		FROM lab_results
		WHERE id = $1
	`

	result := &types.LabResult{}
	err := r.db.QueryRow(query, id).Scan(
		&result.ID, &result.OrderID, &result.PatientID, &result.TechnicianID,
		&result.TestName, &result.Result, &result.Units, &result.ReferenceRange,
		&result.Status, &result.ResultedAt, &result.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("lab result not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get lab result: %w", err)
	}

	return result, nil
}

// GetLabResults retrieves lab results for a patient with filters
func (r *Repository) GetLabResults(patientID string, filters map[string]interface{}) ([]*types.LabResult, error) {
	baseQuery := `
		SELECT id, order_id, patient_id, technician_id, test_name,
			   result, units, reference_range, status, resulted_at, created_at
		FROM lab_results
		WHERE patient_id = $1
	`

	args := []interface{}{patientID}
	argIndex := 2

	// Add filters
	whereClauses := []string{}
	for field, value := range filters {
		switch field {
		case "test_name", "status", "technician_id":
			whereClauses = append(whereClauses, fmt.Sprintf("%s = $%d", field, argIndex))
			args = append(args, value)
			argIndex++
		}
	}

	query := baseQuery
	if len(whereClauses) > 0 {
		query += " AND " + strings.Join(whereClauses, " AND ")
	}

	query += " ORDER BY resulted_at DESC"

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query lab results: %w", err)
	}
	defer rows.Close()

	var results []*types.LabResult
	for rows.Next() {
		result := &types.LabResult{}
		err := rows.Scan(
			&result.ID, &result.OrderID, &result.PatientID, &result.TechnicianID,
			&result.TestName, &result.Result, &result.Units, &result.ReferenceRange,
			&result.Status, &result.ResultedAt, &result.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan lab result: %w", err)
		}
		results = append(results, result)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating lab results: %w", err)
	}

	return results, nil
}

// UpdateLabResult updates a lab result
func (r *Repository) UpdateLabResult(id string, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return fmt.Errorf("no updates provided")
	}

	// Build dynamic update query
	setParts := make([]string, 0, len(updates))
	args := make([]interface{}, 0, len(updates)+1)
	argIndex := 1

	for field, value := range updates {
		setParts = append(setParts, fmt.Sprintf("%s = $%d", field, argIndex))
		args = append(args, value)
		argIndex++
	}

	query := fmt.Sprintf("UPDATE lab_results SET %s WHERE id = $%d", 
		strings.Join(setParts, ", "), argIndex)
	args = append(args, id)

	result, err := r.db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("failed to update lab result: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("lab result not found: %s", id)
	}

	return nil
}

// Offline Data Repository Methods

// StoreOfflineData stores offline synchronization data
func (r *Repository) StoreOfflineData(data *types.OfflineData) error {
	query := `
		INSERT INTO offline_sync_data (
			user_id, device_id, last_sync_at, data, synced_at
		) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id, device_id) 
		DO UPDATE SET 
			last_sync_at = EXCLUDED.last_sync_at,
			data = EXCLUDED.data,
			synced_at = EXCLUDED.synced_at
	`

	// Convert data to JSON for storage
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal offline data: %w", err)
	}

	_, err = r.db.Exec(query, data.UserID, data.DeviceID, data.LastSyncAt, dataJSON, data.SyncedAt)
	if err != nil {
		return fmt.Errorf("failed to store offline data: %w", err)
	}

	return nil
}

// GetOfflineData retrieves offline synchronization data
func (r *Repository) GetOfflineData(userID, deviceID string) (*types.OfflineData, error) {
	query := `
		SELECT user_id, device_id, last_sync_at, data, synced_at
		FROM offline_sync_data
		WHERE user_id = $1 AND device_id = $2
	`

	var dataJSON []byte
	data := &types.OfflineData{}

	err := r.db.QueryRow(query, userID, deviceID).Scan(
		&data.UserID, &data.DeviceID, &data.LastSyncAt, &dataJSON, &data.SyncedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("offline data not found for user %s, device %s", userID, deviceID)
		}
		return nil, fmt.Errorf("failed to get offline data: %w", err)
	}

	// Unmarshal JSON data
	if err := json.Unmarshal(dataJSON, data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal offline data: %w", err)
	}

	return data, nil
}

// UpdateSyncStatus updates the sync status for offline data
func (r *Repository) UpdateSyncStatus(userID, deviceID string, syncedAt string) error {
	syncTime, err := time.Parse(time.RFC3339, syncedAt)
	if err != nil {
		return fmt.Errorf("invalid sync time format: %w", err)
	}

	query := `
		UPDATE offline_sync_data 
		SET synced_at = $1
		WHERE user_id = $2 AND device_id = $3
	`

	result, err := r.db.Exec(query, syncTime, userID, deviceID)
	if err != nil {
		return fmt.Errorf("failed to update sync status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("offline data not found for user %s, device %s", userID, deviceID)
	}

	return nil
}

// DeleteOfflineData deletes offline synchronization data
func (r *Repository) DeleteOfflineData(userID, deviceID string) error {
	query := `
		DELETE FROM offline_sync_data
		WHERE user_id = $1 AND device_id = $2
	`

	result, err := r.db.Exec(query, userID, deviceID)
	if err != nil {
		return fmt.Errorf("failed to delete offline data: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("offline data not found for user %s, device %s", userID, deviceID)
	}

	return nil
}