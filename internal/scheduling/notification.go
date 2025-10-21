package scheduling

import (
	"fmt"
	"time"

	"github.com/medrex/dlt-emr/pkg/interfaces"
	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
)

// NotificationService implements notification functionality for appointments
type NotificationService struct {
	logger *logger.Logger
}

// NewNotificationService creates a new notification service
func NewNotificationService(log *logger.Logger) interfaces.NotificationService {
	return &NotificationService{
		logger: log,
	}
}

// SendEmail sends an email notification
func (n *NotificationService) SendEmail(to, subject, body string) error {
	n.logger.Infof("Sending email to %s with subject: %s", to, subject)
	
	// TODO: Integrate with actual email service (SendGrid, AWS SES, etc.)
	// For now, just log the email
	n.logger.Infof("Email sent successfully to %s", to)
	return nil
}

// SendEmailTemplate sends an email using a template
func (n *NotificationService) SendEmailTemplate(to, template string, data map[string]interface{}) error {
	n.logger.Infof("Sending templated email to %s using template: %s", to, template)
	
	// TODO: Implement template rendering and email sending
	// For now, just log the template email
	n.logger.Infof("Templated email sent successfully to %s", to)
	return nil
}

// SendSMS sends an SMS notification
func (n *NotificationService) SendSMS(to, message string) error {
	n.logger.Infof("Sending SMS to %s: %s", to, message)
	
	// TODO: Integrate with SMS service (Twilio, AWS SNS, etc.)
	// For now, just log the SMS
	n.logger.Infof("SMS sent successfully to %s", to)
	return nil
}

// SendSMSTemplate sends an SMS using a template
func (n *NotificationService) SendSMSTemplate(to, template string, data map[string]interface{}) error {
	n.logger.Infof("Sending templated SMS to %s using template: %s", to, template)
	
	// TODO: Implement template rendering and SMS sending
	// For now, just log the template SMS
	n.logger.Infof("Templated SMS sent successfully to %s", to)
	return nil
}

// SendPushNotification sends a push notification
func (n *NotificationService) SendPushNotification(userID, title, message string) error {
	n.logger.Infof("Sending push notification to user %s: %s - %s", userID, title, message)
	
	// TODO: Integrate with push notification service (Firebase, AWS SNS, etc.)
	// For now, just log the push notification
	n.logger.Infof("Push notification sent successfully to user %s", userID)
	return nil
}

// GetUserPreferences retrieves user notification preferences
func (n *NotificationService) GetUserPreferences(userID string) (map[string]bool, error) {
	n.logger.Infof("Getting notification preferences for user %s", userID)
	
	// TODO: Implement database lookup for user preferences
	// For now, return default preferences
	preferences := map[string]bool{
		"email_reminders":    true,
		"sms_reminders":      false,
		"push_notifications": true,
		"email_confirmations": true,
		"sms_confirmations":   false,
	}
	
	return preferences, nil
}

// UpdateUserPreferences updates user notification preferences
func (n *NotificationService) UpdateUserPreferences(userID string, preferences map[string]bool) error {
	n.logger.Infof("Updating notification preferences for user %s", userID)
	
	// TODO: Implement database update for user preferences
	// For now, just log the update
	n.logger.Infof("Notification preferences updated successfully for user %s", userID)
	return nil
}

// AppointmentNotificationManager handles appointment-specific notifications
type AppointmentNotificationManager struct {
	notificationService interfaces.NotificationService
	schedulingRepo      interfaces.SchedulingRepository
	logger              *logger.Logger
}

// NewAppointmentNotificationManager creates a new appointment notification manager
func NewAppointmentNotificationManager(
	notificationService interfaces.NotificationService,
	schedulingRepo interfaces.SchedulingRepository,
	log *logger.Logger,
) *AppointmentNotificationManager {
	return &AppointmentNotificationManager{
		notificationService: notificationService,
		schedulingRepo:      schedulingRepo,
		logger:              log,
	}
}

// SendAppointmentReminder sends a reminder for an upcoming appointment
func (anm *AppointmentNotificationManager) SendAppointmentReminder(aptID string) error {
	anm.logger.Infof("Sending appointment reminder for %s", aptID)
	
	// Get appointment details
	apt, err := anm.schedulingRepo.GetAppointmentByID(aptID)
	if err != nil {
		return fmt.Errorf("failed to get appointment: %w", err)
	}
	
	// TODO: Get patient and provider details from their respective services
	// For now, use placeholder data
	
	// Calculate time until appointment
	timeUntil := time.Until(apt.StartTime)
	
	// Send reminder based on user preferences
	// TODO: Get actual user preferences and contact information
	
	// Email reminder
	subject := "Appointment Reminder"
	body := fmt.Sprintf(
		"This is a reminder for your appointment on %s at %s.\n\nAppointment Details:\n- Type: %s\n- Provider: %s\n- Location: %s",
		apt.StartTime.Format("January 2, 2006"),
		apt.StartTime.Format("3:04 PM"),
		apt.Type,
		apt.ProviderID, // TODO: Get provider name
		apt.Location,
	)
	
	// TODO: Get patient email from patient service
	patientEmail := "patient@example.com"
	
	if err := anm.notificationService.SendEmail(patientEmail, subject, body); err != nil {
		anm.logger.Errorf("Failed to send email reminder: %v", err)
	}
	
	// Push notification
	title := "Appointment Reminder"
	message := fmt.Sprintf("Your appointment is in %s", anm.formatDuration(timeUntil))
	
	if err := anm.notificationService.SendPushNotification(apt.PatientID, title, message); err != nil {
		anm.logger.Errorf("Failed to send push notification reminder: %v", err)
	}
	
	anm.logger.Infof("Appointment reminder sent successfully for %s", aptID)
	return nil
}

// SendAppointmentConfirmation sends a confirmation for a new or updated appointment
func (anm *AppointmentNotificationManager) SendAppointmentConfirmation(aptID string) error {
	anm.logger.Infof("Sending appointment confirmation for %s", aptID)
	
	// Get appointment details
	apt, err := anm.schedulingRepo.GetAppointmentByID(aptID)
	if err != nil {
		return fmt.Errorf("failed to get appointment: %w", err)
	}
	
	// Email confirmation
	subject := "Appointment Confirmation"
	body := fmt.Sprintf(
		"Your appointment has been confirmed.\n\nAppointment Details:\n- Date: %s\n- Time: %s\n- Type: %s\n- Provider: %s\n- Location: %s\n\nAppointment ID: %s",
		apt.StartTime.Format("January 2, 2006"),
		apt.StartTime.Format("3:04 PM"),
		apt.Type,
		apt.ProviderID, // TODO: Get provider name
		apt.Location,
		apt.ID,
	)
	
	// TODO: Get patient email from patient service
	patientEmail := "patient@example.com"
	
	if err := anm.notificationService.SendEmail(patientEmail, subject, body); err != nil {
		anm.logger.Errorf("Failed to send email confirmation: %v", err)
	}
	
	// Push notification
	title := "Appointment Confirmed"
	message := fmt.Sprintf("Your appointment on %s at %s has been confirmed", 
		apt.StartTime.Format("Jan 2"), 
		apt.StartTime.Format("3:04 PM"))
	
	if err := anm.notificationService.SendPushNotification(apt.PatientID, title, message); err != nil {
		anm.logger.Errorf("Failed to send push notification confirmation: %v", err)
	}
	
	anm.logger.Infof("Appointment confirmation sent successfully for %s", aptID)
	return nil
}

// SendAppointmentChangeNotification sends a notification about appointment changes
func (anm *AppointmentNotificationManager) SendAppointmentChangeNotification(aptID string, changeType string) error {
	anm.logger.Infof("Sending appointment change notification for %s (type: %s)", aptID, changeType)
	
	// Get appointment details
	apt, err := anm.schedulingRepo.GetAppointmentByID(aptID)
	if err != nil {
		return fmt.Errorf("failed to get appointment: %w", err)
	}
	
	var subject, body, pushTitle, pushMessage string
	
	switch changeType {
	case "cancelled":
		subject = "Appointment Cancelled"
		body = fmt.Sprintf(
			"Your appointment scheduled for %s at %s has been cancelled.\n\nCancelled Appointment Details:\n- Type: %s\n- Provider: %s\n- Location: %s\n\nPlease contact us to reschedule.",
			apt.StartTime.Format("January 2, 2006"),
			apt.StartTime.Format("3:04 PM"),
			apt.Type,
			apt.ProviderID,
			apt.Location,
		)
		pushTitle = "Appointment Cancelled"
		pushMessage = fmt.Sprintf("Your appointment on %s has been cancelled", apt.StartTime.Format("Jan 2"))
		
	case "rescheduled":
		subject = "Appointment Rescheduled"
		body = fmt.Sprintf(
			"Your appointment has been rescheduled.\n\nNew Appointment Details:\n- Date: %s\n- Time: %s\n- Type: %s\n- Provider: %s\n- Location: %s",
			apt.StartTime.Format("January 2, 2006"),
			apt.StartTime.Format("3:04 PM"),
			apt.Type,
			apt.ProviderID,
			apt.Location,
		)
		pushTitle = "Appointment Rescheduled"
		pushMessage = fmt.Sprintf("Your appointment has been moved to %s at %s", 
			apt.StartTime.Format("Jan 2"), 
			apt.StartTime.Format("3:04 PM"))
		
	default:
		subject = "Appointment Updated"
		body = fmt.Sprintf(
			"Your appointment has been updated.\n\nUpdated Appointment Details:\n- Date: %s\n- Time: %s\n- Type: %s\n- Provider: %s\n- Location: %s",
			apt.StartTime.Format("January 2, 2006"),
			apt.StartTime.Format("3:04 PM"),
			apt.Type,
			apt.ProviderID,
			apt.Location,
		)
		pushTitle = "Appointment Updated"
		pushMessage = "Your appointment details have been updated"
	}
	
	// TODO: Get patient email from patient service
	patientEmail := "patient@example.com"
	
	if err := anm.notificationService.SendEmail(patientEmail, subject, body); err != nil {
		anm.logger.Errorf("Failed to send email change notification: %v", err)
	}
	
	if err := anm.notificationService.SendPushNotification(apt.PatientID, pushTitle, pushMessage); err != nil {
		anm.logger.Errorf("Failed to send push notification change: %v", err)
	}
	
	anm.logger.Infof("Appointment change notification sent successfully for %s", aptID)
	return nil
}

// SendConflictAlert sends an alert about scheduling conflicts
func (anm *AppointmentNotificationManager) SendConflictAlert(providerID string, conflictingApts []*types.Appointment) error {
	anm.logger.Infof("Sending conflict alert for provider %s", providerID)
	
	if len(conflictingApts) == 0 {
		return nil
	}
	
	// TODO: Get provider email from IAM service
	providerEmail := "provider@example.com"
	
	subject := "Scheduling Conflict Alert"
	body := "The following appointments have scheduling conflicts:\n\n"
	
	for _, apt := range conflictingApts {
		body += fmt.Sprintf("- Appointment %s: %s at %s (Patient: %s)\n",
			apt.ID,
			apt.StartTime.Format("January 2, 2006"),
			apt.StartTime.Format("3:04 PM"),
			apt.PatientID,
		)
	}
	
	body += "\nPlease review and resolve these conflicts."
	
	if err := anm.notificationService.SendEmail(providerEmail, subject, body); err != nil {
		anm.logger.Errorf("Failed to send conflict alert email: %v", err)
		return err
	}
	
	// Send push notification to provider
	title := "Scheduling Conflict"
	message := fmt.Sprintf("You have %d conflicting appointments that need attention", len(conflictingApts))
	
	if err := anm.notificationService.SendPushNotification(providerID, title, message); err != nil {
		anm.logger.Errorf("Failed to send conflict alert push notification: %v", err)
	}
	
	anm.logger.Infof("Conflict alert sent successfully for provider %s", providerID)
	return nil
}

// ScheduleReminders schedules automatic reminders for upcoming appointments
func (anm *AppointmentNotificationManager) ScheduleReminders() error {
	anm.logger.Info("Scheduling automatic appointment reminders")
	
	// Get appointments for the next 24 hours that need reminders
	tomorrow := time.Now().Add(24 * time.Hour)
	filters := &types.AppointmentFilters{
		FromDate: time.Now(),
		ToDate:   tomorrow,
		Status:   types.StatusScheduled,
	}
	
	appointments, err := anm.schedulingRepo.GetAppointments(filters)
	if err != nil {
		return fmt.Errorf("failed to get appointments for reminders: %w", err)
	}
	
	for _, apt := range appointments {
		// Send reminder for appointments that are 24 hours away
		timeUntil := time.Until(apt.StartTime)
		if timeUntil > 23*time.Hour && timeUntil < 25*time.Hour {
			if err := anm.SendAppointmentReminder(apt.ID); err != nil {
				anm.logger.Errorf("Failed to send reminder for appointment %s: %v", apt.ID, err)
			}
		}
	}
	
	anm.logger.Infof("Processed reminders for %d appointments", len(appointments))
	return nil
}

// formatDuration formats a duration into a human-readable string
func (anm *AppointmentNotificationManager) formatDuration(d time.Duration) string {
	if d < time.Hour {
		minutes := int(d.Minutes())
		return fmt.Sprintf("%d minutes", minutes)
	} else if d < 24*time.Hour {
		hours := int(d.Hours())
		return fmt.Sprintf("%d hours", hours)
	} else {
		days := int(d.Hours() / 24)
		return fmt.Sprintf("%d days", days)
	}
}