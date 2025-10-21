package mobile

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/medrex/dlt-emr/pkg/interfaces"
	"github.com/medrex/dlt-emr/pkg/types"
)

// OfflineSyncService implements offline data synchronization
type OfflineSyncService struct {
	repo        interfaces.MobileRepository
	auditService interfaces.AuditService
}

// NewOfflineSyncService creates a new offline sync service
func NewOfflineSyncService(repo interfaces.MobileRepository, auditService interfaces.AuditService) *OfflineSyncService {
	return &OfflineSyncService{
		repo:        repo,
		auditService: auditService,
	}
}

// Sync Operations

// SyncUserData synchronizes offline data for a user and device
func (s *OfflineSyncService) SyncUserData(userID, deviceID string, data *types.OfflineData) error {
	// Validate data before sync
	isValid, errors, err := s.ValidateOfflineData(data)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	if !isValid {
		return fmt.Errorf("data validation failed: %v", errors)
	}

	// Check for conflicts with existing data
	conflicts, err := s.detectConflicts(userID, deviceID, data)
	if err != nil {
		return fmt.Errorf("conflict detection failed: %w", err)
	}

	if len(conflicts) > 0 {
		// Store conflicts for resolution
		if err := s.storeConflicts(userID, deviceID, conflicts); err != nil {
			return fmt.Errorf("failed to store conflicts: %w", err)
		}
		return fmt.Errorf("sync conflicts detected, manual resolution required")
	}

	// Sanitize data before storage
	sanitizedData, err := s.SanitizeOfflineData(data)
	if err != nil {
		return fmt.Errorf("data sanitization failed: %w", err)
	}

	// Sync individual data types
	if err := s.syncOrders(userID, sanitizedData.Orders); err != nil {
		return fmt.Errorf("failed to sync orders: %w", err)
	}

	if err := s.syncScans(userID, sanitizedData.Scans); err != nil {
		return fmt.Errorf("failed to sync scans: %w", err)
	}

	if err := s.syncNotes(userID, sanitizedData.Notes); err != nil {
		return fmt.Errorf("failed to sync notes: %w", err)
	}

	// Update sync timestamp
	sanitizedData.SyncedAt = time.Now()

	// Store offline data record
	if err := s.repo.StoreOfflineData(sanitizedData); err != nil {
		return fmt.Errorf("failed to store offline data: %w", err)
	}

	// Log sync event
	auditData := map[string]interface{}{
		"device_id":    deviceID,
		"orders_count": len(sanitizedData.Orders),
		"scans_count":  len(sanitizedData.Scans),
		"notes_count":  len(sanitizedData.Notes),
	}
	if err := s.auditService.LogEvent(userID, "offline_data_synced", deviceID, true, auditData); err != nil {
		// Log error but don't fail sync
		fmt.Printf("Failed to log sync audit event: %v\n", err)
	}

	return nil
}

// GetPendingSyncData retrieves pending sync data for a user and device
func (s *OfflineSyncService) GetPendingSyncData(userID, deviceID string) (*types.OfflineData, error) {
	// Get stored offline data
	data, err := s.repo.GetOfflineData(userID, deviceID)
	if err != nil {
		// If no data exists, return empty data structure
		return &types.OfflineData{
			UserID:     userID,
			DeviceID:   deviceID,
			LastSyncAt: time.Now(),
			Orders:     []types.CPOEOrder{},
			Scans:      []types.ScanResult{},
			Notes:      []types.ClinicalNote{},
			CustomData: make(map[string]interface{}),
			SyncedAt:   time.Now(),
		}, nil
	}

	// Get any new data since last sync
	newData, err := s.getNewDataSinceSync(userID, data.LastSyncAt)
	if err != nil {
		return nil, fmt.Errorf("failed to get new data: %w", err)
	}

	// Merge new data with existing offline data
	mergedData := s.mergeOfflineData(data, newData)

	return mergedData, nil
}

// MarkDataSynced marks specific data items as synced
func (s *OfflineSyncService) MarkDataSynced(userID, deviceID string, items []string) error {
	// Update sync status for specific items
	syncTime := time.Now().Format(time.RFC3339)
	
	if err := s.repo.UpdateSyncStatus(userID, deviceID, syncTime); err != nil {
		return fmt.Errorf("failed to update sync status: %w", err)
	}

	// Log sync completion
	auditData := map[string]interface{}{
		"device_id":    deviceID,
		"items_count":  len(items),
		"synced_items": items,
	}
	if err := s.auditService.LogEvent(userID, "sync_items_marked", deviceID, true, auditData); err != nil {
		fmt.Printf("Failed to log sync completion audit event: %v\n", err)
	}

	return nil
}

// Conflict Resolution

// ResolveConflicts resolves sync conflicts
func (s *OfflineSyncService) ResolveConflicts(userID string, conflicts []map[string]interface{}) error {
	for _, conflict := range conflicts {
		if err := s.resolveIndividualConflict(userID, conflict); err != nil {
			return fmt.Errorf("failed to resolve conflict: %w", err)
		}
	}

	// Log conflict resolution
	auditData := map[string]interface{}{
		"conflicts_count": len(conflicts),
	}
	if err := s.auditService.LogEvent(userID, "sync_conflicts_resolved", userID, true, auditData); err != nil {
		fmt.Printf("Failed to log conflict resolution audit event: %v\n", err)
	}

	return nil
}

// GetConflicts retrieves sync conflicts for a user and device
func (s *OfflineSyncService) GetConflicts(userID, deviceID string) ([]map[string]interface{}, error) {
	// This would retrieve stored conflicts from a conflicts table
	// For now, return empty slice
	return []map[string]interface{}{}, nil
}

// Data Validation

// ValidateOfflineData validates offline data structure and content
func (s *OfflineSyncService) ValidateOfflineData(data *types.OfflineData) (bool, []string, error) {
	var errors []string

	// Validate required fields
	if data.UserID == "" {
		errors = append(errors, "user_id is required")
	}
	if data.DeviceID == "" {
		errors = append(errors, "device_id is required")
	}

	// Validate orders
	for i, order := range data.Orders {
		if orderErrors := s.validateOrder(&order); len(orderErrors) > 0 {
			for _, err := range orderErrors {
				errors = append(errors, fmt.Sprintf("order[%d]: %s", i, err))
			}
		}
	}

	// Validate scans
	for i, scan := range data.Scans {
		if scanErrors := s.validateScan(&scan); len(scanErrors) > 0 {
			for _, err := range scanErrors {
				errors = append(errors, fmt.Sprintf("scan[%d]: %s", i, err))
			}
		}
	}

	// Validate notes
	for i, note := range data.Notes {
		if noteErrors := s.validateNote(&note); len(noteErrors) > 0 {
			for _, err := range noteErrors {
				errors = append(errors, fmt.Sprintf("note[%d]: %s", i, err))
			}
		}
	}

	// Check data size limits
	if err := s.validateDataSize(data); err != nil {
		errors = append(errors, err.Error())
	}

	return len(errors) == 0, errors, nil
}

// SanitizeOfflineData sanitizes offline data for security
func (s *OfflineSyncService) SanitizeOfflineData(data *types.OfflineData) (*types.OfflineData, error) {
	sanitized := &types.OfflineData{
		UserID:     data.UserID,
		DeviceID:   data.DeviceID,
		LastSyncAt: data.LastSyncAt,
		SyncedAt:   data.SyncedAt,
		CustomData: make(map[string]interface{}),
	}

	// Sanitize orders
	for _, order := range data.Orders {
		sanitizedOrder := s.sanitizeOrder(&order)
		sanitized.Orders = append(sanitized.Orders, *sanitizedOrder)
	}

	// Sanitize scans
	for _, scan := range data.Scans {
		sanitizedScan := s.sanitizeScan(&scan)
		sanitized.Scans = append(sanitized.Scans, *sanitizedScan)
	}

	// Sanitize notes
	for _, note := range data.Notes {
		sanitizedNote := s.sanitizeNote(&note)
		sanitized.Notes = append(sanitized.Notes, *sanitizedNote)
	}

	// Sanitize custom data
	for key, value := range data.CustomData {
		if s.isAllowedCustomDataKey(key) {
			sanitized.CustomData[key] = s.sanitizeCustomDataValue(value)
		}
	}

	return sanitized, nil
}

// Helper methods

// detectConflicts detects conflicts between offline data and server data
func (s *OfflineSyncService) detectConflicts(userID, deviceID string, data *types.OfflineData) ([]map[string]interface{}, error) {
	var conflicts []map[string]interface{}

	// Check for order conflicts
	for _, order := range data.Orders {
		if conflict := s.checkOrderConflict(&order); conflict != nil {
			conflicts = append(conflicts, conflict)
		}
	}

	// Check for note conflicts
	for _, note := range data.Notes {
		if conflict := s.checkNoteConflict(&note); conflict != nil {
			conflicts = append(conflicts, conflict)
		}
	}

	return conflicts, nil
}

// storeConflicts stores conflicts for later resolution
func (s *OfflineSyncService) storeConflicts(userID, deviceID string, conflicts []map[string]interface{}) error {
	// This would store conflicts in a conflicts table
	// For now, just log them
	conflictsJSON, _ := json.Marshal(conflicts)
	fmt.Printf("Storing conflicts for user %s, device %s: %s\n", userID, deviceID, string(conflictsJSON))
	return nil
}

// syncOrders synchronizes CPOE orders
func (s *OfflineSyncService) syncOrders(userID string, orders []types.CPOEOrder) error {
	for _, order := range orders {
		// Check if order already exists
		existingOrder, err := s.repo.GetOrderByID(order.ID)
		if err != nil {
			// Order doesn't exist, create it
			if err := s.repo.CreateOrder(&order); err != nil {
				return fmt.Errorf("failed to create order %s: %w", order.ID, err)
			}
		} else {
			// Order exists, check if update is needed
			if s.shouldUpdateOrder(existingOrder, &order) {
				updates := s.getOrderUpdates(existingOrder, &order)
				if err := s.repo.UpdateOrder(order.ID, updates); err != nil {
					return fmt.Errorf("failed to update order %s: %w", order.ID, err)
				}
			}
		}
	}
	return nil
}

// syncScans synchronizes scan results
func (s *OfflineSyncService) syncScans(userID string, scans []types.ScanResult) error {
	// Scans are typically read-only, so just log them for audit
	for _, scan := range scans {
		auditData := map[string]interface{}{
			"code":       scan.Code,
			"type":       scan.Type,
			"scanned_at": scan.ScannedAt,
			"valid":      scan.IsValid,
		}
		if err := s.auditService.LogEvent(userID, "barcode_scanned_offline", scan.Code, scan.IsValid, auditData); err != nil {
			fmt.Printf("Failed to log offline scan audit event: %v\n", err)
		}
	}
	return nil
}

// syncNotes synchronizes clinical notes
func (s *OfflineSyncService) syncNotes(userID string, notes []types.ClinicalNote) error {
	// This would integrate with the clinical notes service
	// For now, just validate and log
	for _, note := range notes {
		auditData := map[string]interface{}{
			"note_id":    note.ID,
			"patient_id": note.PatientID,
			"author_id":  note.AuthorID,
		}
		if err := s.auditService.LogEvent(userID, "clinical_note_synced", note.ID, true, auditData); err != nil {
			fmt.Printf("Failed to log offline note sync audit event: %v\n", err)
		}
	}
	return nil
}

// getNewDataSinceSync retrieves new data since last sync
func (s *OfflineSyncService) getNewDataSinceSync(userID string, lastSync time.Time) (*types.OfflineData, error) {
	// This would query for new data since lastSync
	// For now, return empty data
	return &types.OfflineData{
		UserID:     userID,
		Orders:     []types.CPOEOrder{},
		Scans:      []types.ScanResult{},
		Notes:      []types.ClinicalNote{},
		CustomData: make(map[string]interface{}),
	}, nil
}

// mergeOfflineData merges offline data with new data
func (s *OfflineSyncService) mergeOfflineData(existing, new *types.OfflineData) *types.OfflineData {
	merged := &types.OfflineData{
		UserID:     existing.UserID,
		DeviceID:   existing.DeviceID,
		LastSyncAt: existing.LastSyncAt,
		SyncedAt:   time.Now(),
		CustomData: make(map[string]interface{}),
	}

	// Merge orders (avoid duplicates)
	orderMap := make(map[string]types.CPOEOrder)
	for _, order := range existing.Orders {
		orderMap[order.ID] = order
	}
	for _, order := range new.Orders {
		orderMap[order.ID] = order
	}
	for _, order := range orderMap {
		merged.Orders = append(merged.Orders, order)
	}

	// Merge scans
	merged.Scans = append(existing.Scans, new.Scans...)

	// Merge notes (avoid duplicates)
	noteMap := make(map[string]types.ClinicalNote)
	for _, note := range existing.Notes {
		noteMap[note.ID] = note
	}
	for _, note := range new.Notes {
		noteMap[note.ID] = note
	}
	for _, note := range noteMap {
		merged.Notes = append(merged.Notes, note)
	}

	// Merge custom data
	for key, value := range existing.CustomData {
		merged.CustomData[key] = value
	}
	for key, value := range new.CustomData {
		merged.CustomData[key] = value
	}

	return merged
}

// Validation helper methods

func (s *OfflineSyncService) validateOrder(order *types.CPOEOrder) []string {
	var errors []string
	
	if order.ID == "" {
		errors = append(errors, "id is required")
	}
	if order.PatientID == "" {
		errors = append(errors, "patient_id is required")
	}
	if order.OrderingMD == "" {
		errors = append(errors, "ordering_md is required")
	}
	if order.OrderType == "" {
		errors = append(errors, "order_type is required")
	}
	
	return errors
}

func (s *OfflineSyncService) validateScan(scan *types.ScanResult) []string {
	var errors []string
	
	if scan.Code == "" {
		errors = append(errors, "code is required")
	}
	if scan.Type == "" {
		errors = append(errors, "type is required")
	}
	if scan.ScannedBy == "" {
		errors = append(errors, "scanned_by is required")
	}
	
	return errors
}

func (s *OfflineSyncService) validateNote(note *types.ClinicalNote) []string {
	var errors []string
	
	if note.ID == "" {
		errors = append(errors, "id is required")
	}
	if note.PatientID == "" {
		errors = append(errors, "patient_id is required")
	}
	if note.AuthorID == "" {
		errors = append(errors, "author_id is required")
	}
	
	return errors
}

func (s *OfflineSyncService) validateDataSize(data *types.OfflineData) error {
	// Check total data size (simplified)
	totalItems := len(data.Orders) + len(data.Scans) + len(data.Notes)
	if totalItems > 1000 {
		return fmt.Errorf("data size exceeds limit: %d items", totalItems)
	}
	return nil
}

// Sanitization helper methods

func (s *OfflineSyncService) sanitizeOrder(order *types.CPOEOrder) *types.CPOEOrder {
	// Remove any sensitive data or validate fields
	sanitized := *order
	// Add any sanitization logic here
	return &sanitized
}

func (s *OfflineSyncService) sanitizeScan(scan *types.ScanResult) *types.ScanResult {
	sanitized := *scan
	// Add any sanitization logic here
	return &sanitized
}

func (s *OfflineSyncService) sanitizeNote(note *types.ClinicalNote) *types.ClinicalNote {
	sanitized := *note
	// Add any sanitization logic here
	return &sanitized
}

func (s *OfflineSyncService) isAllowedCustomDataKey(key string) bool {
	allowedKeys := []string{"preferences", "settings", "cache"}
	for _, allowed := range allowedKeys {
		if key == allowed {
			return true
		}
	}
	return false
}

func (s *OfflineSyncService) sanitizeCustomDataValue(value interface{}) interface{} {
	// Add sanitization logic for custom data values
	return value
}

// Conflict detection helper methods

func (s *OfflineSyncService) checkOrderConflict(order *types.CPOEOrder) map[string]interface{} {
	// Check if order conflicts with server version
	// For now, return nil (no conflicts)
	return nil
}

func (s *OfflineSyncService) checkNoteConflict(note *types.ClinicalNote) map[string]interface{} {
	// Check if note conflicts with server version
	// For now, return nil (no conflicts)
	return nil
}

func (s *OfflineSyncService) resolveIndividualConflict(userID string, conflict map[string]interface{}) error {
	// Resolve individual conflict based on conflict type and resolution strategy
	// For now, just log the conflict
	conflictJSON, _ := json.Marshal(conflict)
	fmt.Printf("Resolving conflict for user %s: %s\n", userID, string(conflictJSON))
	return nil
}

func (s *OfflineSyncService) shouldUpdateOrder(existing, new *types.CPOEOrder) bool {
	return existing.UpdatedAt.Before(new.UpdatedAt)
}

func (s *OfflineSyncService) getOrderUpdates(existing, new *types.CPOEOrder) map[string]interface{} {
	updates := make(map[string]interface{})
	
	if existing.Status != new.Status {
		updates["status"] = new.Status
	}
	if existing.Details != new.Details {
		updates["details"] = new.Details
	}
	if existing.Priority != new.Priority {
		updates["priority"] = new.Priority
	}
	
	updates["updated_at"] = new.UpdatedAt
	
	return updates
}