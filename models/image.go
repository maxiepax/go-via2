package models

import (
	"time"
)

type ImageForm struct {
	ISOImage		string		`json:"iso_image" gorm:"type:varchar(255)"`
	Hash			string		`json:"hash" gorm:"type:varchar(255)"`
	Description		string		`json:"description" gorm:"type:text"`
}

type Image struct {
	ID				int			`json:"id" gorm:"primary_key"`
	Size			int64		`json:"size" gorm:"type:BIGINT"`
	Path			string		`json:"path" gorm:"type:varchar(255)"`

	ImageForm

	CreatedAt		time.Time	`json:"created_at"`
	UpdatedAt		time.Time	`json:"updated_at"`
	DeletedAt		*time.Time	`json:"deleted_at,omitempty"`
}