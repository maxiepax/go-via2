package models

import (
	"time"

	"gorm.io/datatypes"
)

type GroupForm struct {
	Name		string         `json:"name" gorm:"type:varchar(255)"`
	DNS			string         `json:"dns" gorm:"type:varchar(255)"`
	NTP			string         `json:"ntp" gorm:"type:varchar(255)"`
	Netmask		string         `json:"netmask" gorm:"type:varchar(255)"`
	Gateway		string         `json:"gateway" gorm:"type:varchar(255)"`
	Device		string         `json:"device" gorm:"type:varchar(255)"`
	Password	string         `json:"password" gorm:"type:varchar(255)"`
	ImageID		int            `json:"image_id" gorm:"type:INT"`
	Ks			string         `json:"ks" gorm:"type:text"`
	Syslog		string         `json:"syslog" gorm:"type:varchar(255)"`
	Vlan		string         `json:"vlan" gorm:"type:INT"`
	CallbackURL	string         `json:"callbackurl"`
	BootDisk	string         `json:"bootdisk" gorm:"type:varchar(255)"`
	Options		datatypes.JSON `json:"options" sql:"type:JSONB" swaggertype:"object,string"`
}

type NoPWGroupForm struct {
	Name        string         `json:"name" gorm:"type:varchar(255	)"`
	DNS         string         `json:"dns" gorm:"type:varchar(255)"`
	NTP         string         `json:"ntp" gorm:"type:varchar(255)"`
	Netmask		string         `json:"netmask" gorm:"type:varchar(255)"`
	Gateway		string         `json:"gateway" gorm:"type:varchar(255)"`
	Device		string         `json:"device" gorm:"type:varchar(255)"`
	ImageID     int            `json:"image_id" gorm:"type:INT"`
	Ks          string         `json:"ks" gorm:"type:text"`
	Syslog      string         `json:"syslog" gorm:"type:varchar(255)"`
	Vlan        string         `json:"vlan" gorm:"type:INT"`
	CallbackURL string         `json:"callbackurl"`
	BootDisk    string         `json:"bootdisk" gorm:"type:varchar(255)"`
	Options     datatypes.JSON `json:"options" sql:"type:JSONB" swaggertype:"object,string"`
}

type Group struct {
	ID int `json:"id" gorm:"primary_key"`

	GroupForm

	Host []Host `json:"host,omitempty" gorm:"foreignkey:GroupID"`

	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

type NoPWGroup struct {
	ID int `json:"id" gorm:"primary_key"`

	NoPWGroupForm

	Host []Host `json:"host,omitempty" gorm:"foreignkey:GroupID"`

	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

type GroupOptions struct {
	SSH                  bool `json:"ssh"`
	SuppressShellWarning bool `json:"suppressshellwarning"`
	EraseDisks           bool `json:"erasedisks"`
	AllowLegacyCPU       bool `json:"allowlegacycpu"`
	Certificate          bool `json:"certificate"`
	CreateVMFS           bool `json:"createvmfs"`
}

func (NoPWGroup) TableName() string {
	return "groups"
}