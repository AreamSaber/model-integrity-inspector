package repository

import "time"

// Persistence models are not HTTP DTOs. Credential material is excluded from JSON.
type Organization struct {
	ID        int64
	Name      string
	Status    string
	Timezone  string
	QuotaJSON string `gorm:"column:quota_json" json:"-"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type User struct {
	ID                 int64
	Username           string
	UsernameNormalized string
	PasswordHash       string `json:"-"`
	Status             string
	IsSystemAdmin      bool
	FailedLoginCount   int
	LockedUntil        *time.Time
	PasswordChangedAt  time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type Membership struct {
	ID             int64
	OrganizationID int64
	UserID         int64
	Status         string
	CreatedAt      time.Time
}

func (Membership) TableName() string { return "organization_members" }

type Role struct {
	ID             int64
	OrganizationID int64
	Name           string
	Description    string
	IsBuiltin      bool
	CreatedAt      time.Time
}

type Session struct {
	ID            int64
	UserID        int64
	SessionHash   string `json:"-"`
	CSRFHash      string `json:"-"`
	DeviceSummary string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	RevokedAt     *time.Time
}

func (Session) TableName() string { return "user_sessions" }

type Provider struct {
	ID             int64
	OrganizationID int64
	Name           string
	Description    string
	Contact        string
	Status         string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      *time.Time
}

// ModelProfile lists use ModelProfileSummary so large capability/tokenizer JSON
// cannot accidentally enter a default pagination response.
type ModelProfile struct {
	ModelProfileSummary
	CapabilitiesJSON string `gorm:"column:capabilities_json"`
	TokenizerJSON    string `gorm:"column:tokenizer_json"`
	PublicLimitsJSON string `gorm:"column:public_limits_json"`
}

type ModelProfileSummary struct {
	ID                int64
	OrganizationID    int64
	ProviderID        int64
	Model             string
	DisplayName       string
	Protocol          string
	InputPriceMicros  *int64
	OutputPriceMicros *int64
	Status            string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	DeletedAt         *time.Time
}

func (ModelProfile) TableName() string { return "model_profiles" }

type Job struct {
	ID                int64
	OrganizationID    int64
	Type              string
	ObjectID          int64
	IdempotencyKey    string
	Status            string
	Priority          int
	AvailableAt       time.Time
	LeaseOwner        *string
	LeaseUntil        *time.Time
	AttemptCount      int
	MaxAttempts       int
	LastErrorCode     *string
	CancelRequestedAt *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
	CompletedAt       *time.Time
}

func (Job) TableName() string { return "integrity_jobs" }
