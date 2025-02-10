package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode"

	"dario.cat/mergo"
	"github.com/gin-gonic/gin"
	"github.com/maxiepax/go-via2/db"
	"github.com/maxiepax/go-via2/models"
	"github.com/maxiepax/go-via2/secrets"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func GetGroups(c *gin.Context) {
	var items []models.NoPWGroup
	if res := db.DB.Find(&items); res.Error != nil {
		Error(c, http.StatusInternalServerError, res.Error) // 500
		return
	}
	c.JSON(http.StatusOK, items)
}

func GetGroup(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		Error(c, http.StatusBadRequest, err) // 400
		return
	}

	var item models.NoPWGroup
	if res := db.DB.First(&item, id); res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			Error(c, http.StatusNotFound, fmt.Errorf("not found")) // 404
		} else {
			Error(c, http.StatusInternalServerError, res.Error) // 500
		}
		return
	}

	c.JSON(http.StatusOK, item) // 200
}

func UpdateGroup(key string) func(c *gin.Context) {
	return func(c *gin.Context) {
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			Error(c, http.StatusBadRequest, err) // 400
			return
		}

		// Load the form data
		var form models.GroupForm
		if err := c.ShouldBind(&form); err != nil {
			Error(c, http.StatusBadRequest, err) // 400
			return
		}

		// Load the item
		var item models.Group
		if res := db.DB.First(&item, id); res.Error != nil {
			if errors.Is(res.Error, gorm.ErrRecordNotFound) {
				Error(c, http.StatusNotFound, fmt.Errorf("not found")) // 404
			} else {
				Error(c, http.StatusInternalServerError, res.Error) // 500
			}
			return
		}

		// Merge the item and the form data
		if err := mergo.Merge(&item, models.Group{GroupForm: form}, mergo.WithOverride); err != nil {
			Error(c, http.StatusInternalServerError, err) // 500
		}

		//remove whitespaces surrounding comma kickstart file breaks otherwise.
		item.DNS = strings.Join(strings.Fields(item.DNS), "")
		item.NTP = strings.Join(strings.Fields(item.NTP), "")
		item.Syslog = strings.Join(strings.Fields(item.Syslog), "")

		// to avoid re-hashing the password when no new password has been supplied, check if it was supplied
		//validate that password fullfills the password complexity requirements
		if form.Password != "" {
			if err := verifyPassword(form.Password); err != nil {
				Error(c, http.StatusBadRequest, err) // 400
				return
			}

			item.Password = secrets.Encrypt(item.Password, key)
		}

		//mergo wont overwrite values with empty space. To enable removal of ntp, dns, syslog, vlan, always overwrite.
		item.GroupForm.Vlan = form.Vlan
		item.GroupForm.DNS = form.DNS
		item.GroupForm.NTP = form.NTP
		item.GroupForm.Syslog = form.Syslog
		item.GroupForm.BootDisk = form.BootDisk

		// Save it
		if res := db.DB.Save(&item); res.Error != nil {
			Error(c, http.StatusInternalServerError, res.Error) // 500
			return
		}

		// Load a new version with relations
		if res := db.DB.First(&item); res.Error != nil {
			Error(c, http.StatusInternalServerError, res.Error) // 500
			return
		}

		c.JSON(http.StatusOK, item) // 200
	}
}

func CreateGroup(key string) func(c *gin.Context) {
	return func(c *gin.Context) {
		var form models.GroupForm

		if err := c.ShouldBind(&form); err != nil {
			Error(c, http.StatusBadRequest, err) // 400
			return
		}

		item := models.Group{GroupForm: form}

		//remove whitespaces surrounding comma kickstart file breaks otherwise
		item.DNS = strings.Join(strings.Fields(item.DNS), "")
		item.NTP = strings.Join(strings.Fields(item.NTP), "")
		item.Syslog = strings.Join(strings.Fields(item.Syslog), "")

		//validate that password fullfills the password complexity requirements
		if err := verifyPassword(form.Password); err != nil {
			Error(c, http.StatusBadRequest, err) // 400
			return
		}
		item.Password = secrets.Encrypt(item.Password, key)

		if res := db.DB.Create(&item); res.Error != nil {
			Error(c, http.StatusInternalServerError, res.Error) // 500
			return
		}

		// Load a new version with relations
		if res := db.DB.First(&item); res.Error != nil {
			Error(c, http.StatusInternalServerError, res.Error) // 500
			return
		}

		c.JSON(http.StatusOK, item) // 200

		logrus.WithFields(logrus.Fields{
			"Name":     item.Name,
			"DNS":      item.DNS,
			"NTP":      item.NTP,
			"Image ID": item.ImageID,
		}).Debug("group")
	}
}

func DeleteGroup(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		Error(c, http.StatusBadRequest, err) // 400
		return
	}

	var item models.Group
	if res := db.DB.First(&item, id); res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			Error(c, http.StatusNotFound, fmt.Errorf("not found")) // 404
		} else {
			Error(c, http.StatusInternalServerError, res.Error) // 500
		}
		return
	}

	if res := db.DB.Delete(&item); res.Error != nil {
		Error(c, http.StatusInternalServerError, res.Error) // 500
		return
	}

	c.JSON(http.StatusNoContent, gin.H{}) //204
}

func verifyPassword(s string) error {
	number := false
	upper := false
	special := false
	lower := false
	for _, c := range s {
		switch {
		case unicode.IsNumber(c):
			number = true
		case unicode.IsUpper(c):
			upper = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			special = true
		case unicode.IsLetter(c) || c == ' ':
			lower = true
		}
	}
	var b2i = map[bool]int8{false: 0, true: 1}
	classes := b2i[number] + b2i[upper] + b2i[special] + b2i[lower]

	if classes < 3 {
		return fmt.Errorf("you need to use at least 3 character classes (lowercase, uppercase, special and numbers)")
	}

	if len(s) < 7 {
		return fmt.Errorf("too short, should be at least 7 characters")
	}

	return nil
}