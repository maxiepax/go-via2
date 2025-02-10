package models

import (
	"time"
)

type HostForm struct {

	IP				string		`json:"ip" gorm:"type:varchar(15);not null;index:uniqIp,unique"`
	Hostname 		string		`json:"hostname" gorm:"type:varchar(255)"`
	Domain			string		`json:"domain" gorm:"type:varchar(255)"`
	Reimage			bool		`json:"reimage" gorm:"type:bool;index:uniqIp,unique"`
	GroupID			int			`json:"group_id" gorm:"type:INT" swaggertype:"integer"`
	Progress		int			`json:"progress" gorm:"type:INT"`
	Progresstext	string		`json:"progresstext" gorm:"type:varchar(255)"`
	Ks				string		`json:"ks" gorm:"type:text"`
}


type Host struct {

	ID				int			`json:"id" gorm:"primary_key"`
	Group			Group		`json:"group" gorm:"foreginkey:GroupID"`

	HostForm

	CreatedAt		time.Time	`json:"created_at"`
	UpdatedAt		time.Time	`json:"updated_at"`
	DeletedAt		*time.Time	`json:"deleted_at,omitempty"`
}