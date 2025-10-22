package rbac

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// AlertManager manages real-time alerting for security events
type AlertManager struct {
	config           *Config
	logger           *logrus.Logger
	alertChannels    map[string]AlertChannel
	alertQueue       chan *SecurityAlert
	stopChan         chan struct{}
	wg               sync.WaitGroup
	metrics          *AlertManagerMetrics
	mutex            sync.RWMutex
}

// AlertChannel defines an interface for alert delivery channels
type AlertChannel interface {
	SendAlert(alert *SecurityAlert) error
	GetChannelType() string
	IsEnabled() bool
}

// AlertManagerMetrics tracks alert manager performance
type AlertManagerMetrics struct {
	AlertsSent         int64     `json:"alerts_sent"`
	AlertsFailed       int64     `json:"alerts_failed"`
	AlertsQueued       int64     `json:"alerts_queued"`
	ChannelMetrics     map[string]*ChannelMetrics `json:"channel_metrics"`
	LastAlertTime      time.Time `json:"last_alert_time"`
	AverageProcessTime time.Duration `json:"average_process_time"`
}

// ChannelMetrics tracks metrics for individual alert channels
type ChannelMetrics struct {
	ChannelType    string        `json:"channel_type"`
	AlertsSent     int64         `json:"alerts_sent"`
	AlertsFailed   int64         `json:"alerts_failed"`
	LastSentTime   time.Time     `json:"last_sent_time"`
	AverageLatency time.Duration `json:"average_latency"`
}

// WebhookChannel sends alerts via HTTP webhooks
type WebhookChannel struct {
	Name        string        `json:"name"`
	URL         string        `json:"url"`
	Method      string        `json:"method"`
	Headers     map[string]string `json:"headers"`
	Timeout     time.Duration `json:"timeout"`
	Enabled     bool          `json:"enabled"`
	RetryCount  int           `json:"retry_count"`
	RetryDelay  time.Duration `json:"retry_delay"`
	httpClient  *http.Client
}

// EmailChannel sends alerts via email (placeholder for future implementation)
type EmailChannel struct {
	Name         string   `json:"name"`
	SMTPServer   string   `json:"smtp_server"`
	SMTPPort     int      `json:"smtp_port"`
	Username     string   `json:"username"`
	Password     string   `json:"password"`
	FromAddress  string   `json:"from_address"`
	ToAddresses  []string `json:"to_addresses"`
	Enabled      bool     `json:"enabled"`
}

// SlackChannel sends alerts to Slack (placeholder for future implementation)
type SlackChannel struct {
	Name        string `json:"name"`
	WebhookURL  string `json:"webhook_url"`
	Channel     string `json:"channel"`
	Username    string `json:"username"`
	IconEmoji   string `json:"icon_emoji"`
	Enabled     bool   `json:"enabled"`
}

// LogChannel logs alerts to the application log
type LogChannel struct {
	Name    string `json:"name"`
	Level   string `json:"level"`
	Enabled bool   `json:"enabled"`
	logger  *logrus.Logger
}

// AlertPayload represents the payload sent to alert channels
type AlertPayload struct {
	Alert     *SecurityAlert         `json:"alert"`
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// NewAlertManager creates a new alert manager
func NewAlertManager(config *Config, logger *logrus.Logger) *AlertManager {
	am := &AlertManager{
		config:        config,
		logger:        logger,
		alertChannels: make(map[string]AlertChannel),
		alertQueue:    make(chan *SecurityAlert, config.AlertBufferSize),
		stopChan:      make(chan struct{}),
		metrics: &AlertManagerMetrics{
			ChannelMetrics: make(map[string]*ChannelMetrics),
		},
	}

	// Initialize alert channels based on configuration
	am.initializeAlertChannels()

	return am
}

// Start starts the alert manager
func (am *AlertManager) Start(ctx context.Context) error {
	am.logger.Info("Starting alert manager")

	// Start alert processor
	am.wg.Add(1)
	go am.processAlerts(ctx)

	am.logger.Info("Alert manager started successfully")
	return nil
}

// Stop stops the alert manager
func (am *AlertManager) Stop() error {
	am.logger.Info("Stopping alert manager")

	close(am.stopChan)
	am.wg.Wait()

	am.logger.Info("Alert manager stopped")
	return nil
}

// SendAlert sends an alert through all enabled channels
func (am *AlertManager) SendAlert(alert *SecurityAlert) error {
	// Queue the alert for processing
	select {
	case am.alertQueue <- alert:
		am.mutex.Lock()
		am.metrics.AlertsQueued++
		am.mutex.Unlock()
		return nil
	default:
		// Queue is full
		am.mutex.Lock()
		am.metrics.AlertsFailed++
		am.mutex.Unlock()
		return fmt.Errorf("alert queue is full")
	}
}

// AddChannel adds an alert channel
func (am *AlertManager) AddChannel(name string, channel AlertChannel) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	am.alertChannels[name] = channel
	am.metrics.ChannelMetrics[name] = &ChannelMetrics{
		ChannelType: channel.GetChannelType(),
	}

	am.logger.Info("Alert channel added",
		"name", name,
		"type", channel.GetChannelType(),
	)
}

// RemoveChannel removes an alert channel
func (am *AlertManager) RemoveChannel(name string) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	delete(am.alertChannels, name)
	delete(am.metrics.ChannelMetrics, name)

	am.logger.Info("Alert channel removed", "name", name)
}

// GetMetrics returns alert manager metrics
func (am *AlertManager) GetMetrics() *AlertManagerMetrics {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	// Create a copy to avoid race conditions
	metrics := *am.metrics
	metrics.ChannelMetrics = make(map[string]*ChannelMetrics)
	for name, channelMetrics := range am.metrics.ChannelMetrics {
		metricsCopy := *channelMetrics
		metrics.ChannelMetrics[name] = &metricsCopy
	}

	return &metrics
}

// Helper methods

func (am *AlertManager) initializeAlertChannels() {
	// Initialize webhook channels
	for _, webhookConfig := range am.config.AlertChannels.Webhooks {
		channel := &WebhookChannel{
			Name:       webhookConfig.Name,
			URL:        webhookConfig.URL,
			Method:     webhookConfig.Method,
			Headers:    webhookConfig.Headers,
			Timeout:    webhookConfig.Timeout,
			Enabled:    webhookConfig.Enabled,
			RetryCount: webhookConfig.RetryCount,
			RetryDelay: webhookConfig.RetryDelay,
			httpClient: &http.Client{
				Timeout: webhookConfig.Timeout,
			},
		}
		am.AddChannel(webhookConfig.Name, channel)
	}

	// Initialize log channel
	if am.config.AlertChannels.Log.Enabled {
		channel := &LogChannel{
			Name:    am.config.AlertChannels.Log.Name,
			Level:   am.config.AlertChannels.Log.Level,
			Enabled: am.config.AlertChannels.Log.Enabled,
			logger:  am.logger,
		}
		am.AddChannel(am.config.AlertChannels.Log.Name, channel)
	}

	// TODO: Initialize email and Slack channels when implemented
}

func (am *AlertManager) processAlerts(ctx context.Context) {
	defer am.wg.Done()

	for {
		select {
		case alert := <-am.alertQueue:
			start := time.Now()
			am.processAlertSync(alert)
			
			// Update metrics
			am.mutex.Lock()
			am.metrics.LastAlertTime = time.Now()
			processingTime := time.Since(start)
			if am.metrics.AlertsSent == 0 {
				am.metrics.AverageProcessTime = processingTime
			} else {
				// Calculate running average
				totalTime := am.metrics.AverageProcessTime * time.Duration(am.metrics.AlertsSent)
				am.metrics.AverageProcessTime = (totalTime + processingTime) / time.Duration(am.metrics.AlertsSent+1)
			}
			am.mutex.Unlock()

		case <-ctx.Done():
			am.logger.Info("Alert processor stopping")
			return
		case <-am.stopChan:
			am.logger.Info("Alert processor stopping")
			return
		}
	}
}

func (am *AlertManager) processAlertSync(alert *SecurityAlert) {
	am.mutex.RLock()
	channels := make(map[string]AlertChannel)
	for name, channel := range am.alertChannels {
		if channel.IsEnabled() {
			channels[name] = channel
		}
	}
	am.mutex.RUnlock()

	// Send alert to all enabled channels
	for name, channel := range channels {
		go am.sendToChannel(name, channel, alert)
	}
}

func (am *AlertManager) sendToChannel(channelName string, channel AlertChannel, alert *SecurityAlert) {
	start := time.Now()
	err := channel.SendAlert(alert)
	latency := time.Since(start)

	am.mutex.Lock()
	defer am.mutex.Unlock()

	channelMetrics := am.metrics.ChannelMetrics[channelName]
	if channelMetrics == nil {
		channelMetrics = &ChannelMetrics{
			ChannelType: channel.GetChannelType(),
		}
		am.metrics.ChannelMetrics[channelName] = channelMetrics
	}

	if err != nil {
		channelMetrics.AlertsFailed++
		am.metrics.AlertsFailed++
		am.logger.WithError(err).Error("Failed to send alert to channel",
			"channel", channelName,
			"alert_id", alert.ID,
		)
	} else {
		channelMetrics.AlertsSent++
		channelMetrics.LastSentTime = time.Now()
		am.metrics.AlertsSent++

		// Update average latency
		if channelMetrics.AlertsSent == 1 {
			channelMetrics.AverageLatency = latency
		} else {
			totalLatency := channelMetrics.AverageLatency * time.Duration(channelMetrics.AlertsSent-1)
			channelMetrics.AverageLatency = (totalLatency + latency) / time.Duration(channelMetrics.AlertsSent)
		}

		am.logger.Info("Alert sent successfully",
			"channel", channelName,
			"alert_id", alert.ID,
			"latency", latency,
		)
	}
}

// WebhookChannel implementation

func (wc *WebhookChannel) SendAlert(alert *SecurityAlert) error {
	if !wc.Enabled {
		return fmt.Errorf("webhook channel %s is disabled", wc.Name)
	}

	payload := &AlertPayload{
		Alert:     alert,
		Timestamp: time.Now(),
		Source:    "medrex-rbac-system",
		Metadata: map[string]interface{}{
			"channel": wc.Name,
			"version": "1.0",
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal alert payload: %w", err)
	}

	// Retry logic
	var lastErr error
	for attempt := 0; attempt <= wc.RetryCount; attempt++ {
		if attempt > 0 {
			time.Sleep(wc.RetryDelay)
		}

		req, err := http.NewRequest(wc.Method, wc.URL, bytes.NewBuffer(jsonData))
		if err != nil {
			lastErr = fmt.Errorf("failed to create request: %w", err)
			continue
		}

		// Set headers
		req.Header.Set("Content-Type", "application/json")
		for key, value := range wc.Headers {
			req.Header.Set(key, value)
		}

		resp, err := wc.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("failed to send request: %w", err)
			continue
		}

		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil // Success
		}

		lastErr = fmt.Errorf("webhook returned status code: %d", resp.StatusCode)
	}

	return fmt.Errorf("failed to send webhook after %d attempts: %w", wc.RetryCount+1, lastErr)
}

func (wc *WebhookChannel) GetChannelType() string {
	return "webhook"
}

func (wc *WebhookChannel) IsEnabled() bool {
	return wc.Enabled
}

// LogChannel implementation

func (lc *LogChannel) SendAlert(alert *SecurityAlert) error {
	if !lc.Enabled {
		return fmt.Errorf("log channel %s is disabled", lc.Name)
	}

	logEntry := lc.logger.WithFields(logrus.Fields{
		"alert_id":     alert.ID,
		"alert_type":   alert.AlertType,
		"severity":     alert.Severity,
		"user_id":      alert.UserID,
		"resource_id":  alert.ResourceID,
		"ip_address":   alert.IPAddress,
		"timestamp":    alert.Timestamp,
		"status":       alert.Status,
		"title":        alert.Title,
		"description":  alert.Description,
	})

	switch lc.Level {
	case "debug":
		logEntry.Debug("Security Alert")
	case "info":
		logEntry.Info("Security Alert")
	case "warn":
		logEntry.Warn("Security Alert")
	case "error":
		logEntry.Error("Security Alert")
	default:
		logEntry.Warn("Security Alert")
	}

	return nil
}

func (lc *LogChannel) GetChannelType() string {
	return "log"
}

func (lc *LogChannel) IsEnabled() bool {
	return lc.Enabled
}

// EmailChannel implementation (placeholder)

func (ec *EmailChannel) SendAlert(alert *SecurityAlert) error {
	if !ec.Enabled {
		return fmt.Errorf("email channel %s is disabled", ec.Name)
	}

	// TODO: Implement email sending logic
	// This would typically use an SMTP client to send emails
	return fmt.Errorf("email channel not implemented yet")
}

func (ec *EmailChannel) GetChannelType() string {
	return "email"
}

func (ec *EmailChannel) IsEnabled() bool {
	return ec.Enabled
}

// SlackChannel implementation (placeholder)

func (sc *SlackChannel) SendAlert(alert *SecurityAlert) error {
	if !sc.Enabled {
		return fmt.Errorf("slack channel %s is disabled", sc.Name)
	}

	// TODO: Implement Slack webhook sending logic
	// This would format the alert as a Slack message and send via webhook
	return fmt.Errorf("slack channel not implemented yet")
}

func (sc *SlackChannel) GetChannelType() string {
	return "slack"
}

func (sc *SlackChannel) IsEnabled() bool {
	return sc.Enabled
}