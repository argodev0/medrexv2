package logger

import (
	"context"
	"os"

	"github.com/sirupsen/logrus"
)

// Logger wraps logrus.Logger with additional functionality
type Logger struct {
	*logrus.Logger
}

// New creates a new logger instance
func New(level string) *Logger {
	log := logrus.New()
	
	// Set log level
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	log.SetLevel(logLevel)

	// Set output format
	log.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "message",
		},
	})

	// Set output destination
	log.SetOutput(os.Stdout)

	return &Logger{Logger: log}
}

// WithFields creates a new logger entry with the specified fields
func (l *Logger) WithFields(fields map[string]interface{}) *logrus.Entry {
	return l.Logger.WithFields(fields)
}

// WithField creates a new logger entry with a single field
func (l *Logger) WithField(key string, value interface{}) *logrus.Entry {
	return l.Logger.WithField(key, value)
}

// WithError creates a new logger entry with an error field
func (l *Logger) WithError(err error) *logrus.Entry {
	return l.Logger.WithError(err)
}

// WithUserID creates a new logger entry with user ID field
func (l *Logger) WithUserID(userID string) *logrus.Entry {
	return l.Logger.WithField("user_id", userID)
}

// WithRequestID creates a new logger entry with request ID field
func (l *Logger) WithRequestID(requestID string) *logrus.Entry {
	return l.Logger.WithField("request_id", requestID)
}

// WithService creates a new logger entry with service name field
func (l *Logger) WithService(service string) *logrus.Entry {
	return l.Logger.WithField("service", service)
}

// WithComponent creates a new logger entry with component name field
func (l *Logger) WithComponent(component string) *logrus.Entry {
	return l.Logger.WithField("component", component)
}

// Audit logs audit events with structured format
func (l *Logger) Audit(userID, action, resource string, success bool, details map[string]interface{}) {
	entry := l.Logger.WithFields(logrus.Fields{
		"audit":     true,
		"user_id":   userID,
		"action":    action,
		"resource":  resource,
		"success":   success,
		"details":   details,
	})

	if success {
		entry.Info("Audit event")
	} else {
		entry.Warn("Audit event failed")
	}
}

// Security logs security-related events
func (l *Logger) Security(event string, userID string, details map[string]interface{}) {
	l.Logger.WithFields(logrus.Fields{
		"security": true,
		"event":    event,
		"user_id":  userID,
		"details":  details,
	}).Warn("Security event")
}

// Performance logs performance metrics
func (l *Logger) Performance(operation string, duration int64, details map[string]interface{}) {
	l.Logger.WithFields(logrus.Fields{
		"performance": true,
		"operation":   operation,
		"duration_ms": duration,
		"details":     details,
	}).Info("Performance metric")
}

// Compliance logs compliance-related events
func (l *Logger) Compliance(event string, userID string, details map[string]interface{}) {
	l.Logger.WithFields(logrus.Fields{
		"compliance": true,
		"event":      event,
		"user_id":    userID,
		"details":    details,
	}).Info("Compliance event")
}

// WithContext creates a logger with context-aware fields
func (l *Logger) WithContext(ctx context.Context) *logrus.Entry {
	entry := l.Logger.WithFields(logrus.Fields{})
	
	// Add trace ID if available
	if traceID := ctx.Value("trace_id"); traceID != nil {
		entry = entry.WithField("trace_id", traceID)
	}
	
	// Add span ID if available
	if spanID := ctx.Value("span_id"); spanID != nil {
		entry = entry.WithField("span_id", spanID)
	}
	
	// Add request ID if available
	if requestID := ctx.Value("request_id"); requestID != nil {
		entry = entry.WithField("request_id", requestID)
	}
	
	// Add user ID if available
	if userID := ctx.Value("user_id"); userID != nil {
		entry = entry.WithField("user_id", userID)
	}
	
	return entry
}

// StructuredLog logs with structured format and context
func (l *Logger) StructuredLog(ctx context.Context, level logrus.Level, message string, fields map[string]interface{}) {
	entry := l.WithContext(ctx)
	if fields != nil {
		entry = entry.WithFields(fields)
	}
	entry.Log(level, message)
}

// PHIAccess logs PHI access events with enhanced security context
func (l *Logger) PHIAccess(ctx context.Context, userID, patientID, action, resource string, success bool, details map[string]interface{}) {
	entry := l.WithContext(ctx).WithFields(logrus.Fields{
		"phi_access":  true,
		"user_id":     userID,
		"patient_id":  patientID,
		"action":      action,
		"resource":    resource,
		"success":     success,
		"details":     details,
		"sensitive":   true,
	})

	if success {
		entry.Info("PHI access granted")
	} else {
		entry.Warn("PHI access denied")
	}
}

// BlockchainTransaction logs blockchain transaction events
func (l *Logger) BlockchainTransaction(ctx context.Context, chaincode, function string, args []string, success bool, txID string, details map[string]interface{}) {
	entry := l.WithContext(ctx).WithFields(logrus.Fields{
		"blockchain":     true,
		"chaincode":      chaincode,
		"function":       function,
		"args":           args,
		"success":        success,
		"transaction_id": txID,
		"details":        details,
	})

	if success {
		entry.Info("Blockchain transaction completed")
	} else {
		entry.Error("Blockchain transaction failed")
	}
}

// HTTPRequest logs HTTP request events
func (l *Logger) HTTPRequest(ctx context.Context, method, path, userAgent, clientIP string, statusCode int, duration int64, details map[string]interface{}) {
	entry := l.WithContext(ctx).WithFields(logrus.Fields{
		"http_request": true,
		"method":       method,
		"path":         path,
		"user_agent":   userAgent,
		"client_ip":    clientIP,
		"status_code":  statusCode,
		"duration_ms":  duration,
		"details":      details,
	})

	if statusCode >= 400 {
		entry.Warn("HTTP request completed with error")
	} else {
		entry.Info("HTTP request completed")
	}
}

// DatabaseOperation logs database operation events
func (l *Logger) DatabaseOperation(ctx context.Context, operation, table string, duration int64, rowsAffected int64, success bool, details map[string]interface{}) {
	entry := l.WithContext(ctx).WithFields(logrus.Fields{
		"database":      true,
		"operation":     operation,
		"table":         table,
		"duration_ms":   duration,
		"rows_affected": rowsAffected,
		"success":       success,
		"details":       details,
	})

	if success {
		entry.Info("Database operation completed")
	} else {
		entry.Error("Database operation failed")
	}
}