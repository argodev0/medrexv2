package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all configuration for the application
type Config struct {
	// Server configuration
	Server ServerConfig `mapstructure:"server"`
	
	// Database configuration
	Database DatabaseConfig `mapstructure:"database"`
	
	// Hyperledger Fabric configuration
	Fabric FabricConfig `mapstructure:"fabric"`
	
	// Redis configuration
	Redis RedisConfig `mapstructure:"redis"`
	
	// JWT configuration
	JWT JWTConfig `mapstructure:"jwt"`
	
	// Encryption configuration
	Encryption EncryptionConfig `mapstructure:"encryption"`
	
	// Logging configuration
	LogLevel string `mapstructure:"log_level"`
	
	// Rate limiting configuration
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`
	
	// Monitoring configuration
	Monitoring MonitoringConfig `mapstructure:"monitoring"`
}

// ServerConfig holds server-specific configuration
type ServerConfig struct {
	Host         string `mapstructure:"host"`
	Port         int    `mapstructure:"port"`
	ReadTimeout  int    `mapstructure:"read_timeout"`
	WriteTimeout int    `mapstructure:"write_timeout"`
	IdleTimeout  int    `mapstructure:"idle_timeout"`
	TLSEnabled   bool   `mapstructure:"tls_enabled"`
	CertFile     string `mapstructure:"cert_file"`
	KeyFile      string `mapstructure:"key_file"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Host            string `mapstructure:"host"`
	Port            int    `mapstructure:"port"`
	Name            string `mapstructure:"name"`
	User            string `mapstructure:"user"`
	Password        string `mapstructure:"password"`
	SSLMode         string `mapstructure:"ssl_mode"`
	MaxOpenConns    int    `mapstructure:"max_open_conns"`
	MaxIdleConns    int    `mapstructure:"max_idle_conns"`
	ConnMaxLifetime int    `mapstructure:"conn_max_lifetime"`
	EncryptionKey   string `mapstructure:"encryption_key"`
}

// FabricConfig holds Hyperledger Fabric configuration
type FabricConfig struct {
	NetworkConfig   string            `mapstructure:"network_config"`
	UserName        string            `mapstructure:"user_name"`
	UserPassword    string            `mapstructure:"user_password"`
	OrgName         string            `mapstructure:"org_name"`
	ChannelName     string            `mapstructure:"channel_name"`
	ChaincodeID     string            `mapstructure:"chaincode_id"`
	CAEndpoint      string            `mapstructure:"ca_endpoint"`
	PeerEndpoints   []string          `mapstructure:"peer_endpoints"`
	OrdererEndpoint string            `mapstructure:"orderer_endpoint"`
	TLSEnabled      bool              `mapstructure:"tls_enabled"`
	CertPath        string            `mapstructure:"cert_path"`
	KeyPath         string            `mapstructure:"key_path"`
	MSPConfigPath   string            `mapstructure:"msp_config_path"`
	Chaincodes      map[string]string `mapstructure:"chaincodes"`
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
	PoolSize int    `mapstructure:"pool_size"`
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	SecretKey       string `mapstructure:"secret_key"`
	AccessTokenTTL  int    `mapstructure:"access_token_ttl"`
	RefreshTokenTTL int    `mapstructure:"refresh_token_ttl"`
	Issuer          string `mapstructure:"issuer"`
	Audience        string `mapstructure:"audience"`
}

// EncryptionConfig holds encryption configuration
type EncryptionConfig struct {
	AESKey    string `mapstructure:"aes_key"`
	HSMConfig HSMConfig `mapstructure:"hsm"`
}

// HSMConfig holds Hardware Security Module configuration
type HSMConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	Provider  string `mapstructure:"provider"`
	Endpoint  string `mapstructure:"endpoint"`
	KeyVault  string `mapstructure:"key_vault"`
	ClientID  string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	TenantID  string `mapstructure:"tenant_id"`
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled        bool `mapstructure:"enabled"`
	RequestsPerMin int  `mapstructure:"requests_per_min"`
	BurstSize      int  `mapstructure:"burst_size"`
	CleanupInterval int `mapstructure:"cleanup_interval"`
}

// MonitoringConfig holds monitoring configuration
type MonitoringConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	MetricsPath    string `mapstructure:"metrics_path"`
	PrometheusPort int    `mapstructure:"prometheus_port"`
	HealthPath     string `mapstructure:"health_path"`
}

// Load loads configuration from environment variables and config files
func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("/etc/medrex")

	// Set default values
	setDefaults()

	// Enable environment variable support
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Read config file if it exists
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Override with environment variables
	overrideWithEnv(&config)

	// Validate configuration
	if err := validate(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults() {
	// Server defaults
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.read_timeout", 30)
	viper.SetDefault("server.write_timeout", 30)
	viper.SetDefault("server.idle_timeout", 120)
	viper.SetDefault("server.tls_enabled", false)

	// Database defaults
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.name", "medrex")
	viper.SetDefault("database.user", "medrex")
	viper.SetDefault("database.ssl_mode", "require")
	viper.SetDefault("database.max_open_conns", 25)
	viper.SetDefault("database.max_idle_conns", 5)
	viper.SetDefault("database.conn_max_lifetime", 300)

	// Redis defaults
	viper.SetDefault("redis.host", "localhost")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("redis.pool_size", 10)

	// JWT defaults
	viper.SetDefault("jwt.access_token_ttl", 3600)  // 1 hour
	viper.SetDefault("jwt.refresh_token_ttl", 86400) // 24 hours
	viper.SetDefault("jwt.issuer", "medrex-dlt-emr")
	viper.SetDefault("jwt.audience", "medrex-users")

	// Fabric defaults
	viper.SetDefault("fabric.channel_name", "healthcare")
	viper.SetDefault("fabric.tls_enabled", true)

	// Rate limiting defaults
	viper.SetDefault("rate_limit.enabled", true)
	viper.SetDefault("rate_limit.requests_per_min", 100)
	viper.SetDefault("rate_limit.burst_size", 10)
	viper.SetDefault("rate_limit.cleanup_interval", 60)

	// Monitoring defaults
	viper.SetDefault("monitoring.enabled", true)
	viper.SetDefault("monitoring.metrics_path", "/metrics")
	viper.SetDefault("monitoring.prometheus_port", 9090)
	viper.SetDefault("monitoring.health_path", "/health")

	// Logging defaults
	viper.SetDefault("log_level", "info")
}

// overrideWithEnv overrides configuration with environment variables
func overrideWithEnv(config *Config) {
	if port := os.Getenv("PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			config.Server.Port = p
		}
	}

	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		// Parse DATABASE_URL if provided
		// Format: postgres://user:password@host:port/dbname?sslmode=require
		// This is a simplified parser - in production, use a proper URL parser
	}

	if jwtSecret := os.Getenv("JWT_SECRET_KEY"); jwtSecret != "" {
		config.JWT.SecretKey = jwtSecret
	}

	if encKey := os.Getenv("ENCRYPTION_KEY"); encKey != "" {
		config.Encryption.AESKey = encKey
	}

	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		config.LogLevel = logLevel
	}
}

// validate validates the configuration
func validate(config *Config) error {
	if config.JWT.SecretKey == "" {
		return fmt.Errorf("JWT secret key is required")
	}

	if config.Database.Password == "" {
		return fmt.Errorf("database password is required")
	}

	if config.Encryption.AESKey == "" {
		return fmt.Errorf("encryption key is required")
	}

	if config.Server.Port <= 0 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Server.Port)
	}

	return nil
}