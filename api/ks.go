package api

import (
	"encoding/json"
	"net"
	"net/http"
	"text/template"

	"encoding/base64"

	"github.com/gin-gonic/gin"
	"github.com/maxiepax/go-via2/db"
	"github.com/maxiepax/go-via2/models"
	"github.com/maxiepax/go-via2/secrets"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm/clause"
)

var defaultks = `
# Accept the VMware End User License Agreement
vmaccepteula

# Set the root password for the DCUI and Tech Support Mode
rootpw {{ .password }}

{{ if .erasedisks }}
# Remove ALL partitions
clearpart --overwritevmfs --alldrives {{ end }}

{{ if .bootdisk }}
install --disk=/vmfs/devices/disks/{{.bootdisk}} --overwritevmfs --novmfsondisk
{{ else }}
# Install on the first local disk available on machine
install --overwritevmfs {{ if not .createvmfs }} --novmfsondisk {{ end }} --firstdisk="localesx,usb,ahci,vmw_ahci,VMware"
{{ end }}

# Set the network to static on the first network adapter
network --bootproto=static --ip={{ .ip }} --gateway={{ .gateway }} --netmask={{ .netmask }} --nameserver={{ .dns }} --hostname={{ .hostname }} --device={{ .mac }} {{if .vlan}} --vlanid={{.vlan}} {{end}}

reboot
`

//func Ks(c *gin.Context) {
func Ks(key string) func(c *gin.Context) {
	return func(c *gin.Context) {
		var item models.Host
		host, _, _ := net.SplitHostPort(c.Request.RemoteAddr)

		if res := db.DB.Preload(clause.Associations).Where("ip = ?", host).First(&item); res.Error != nil {
			Error(c, http.StatusInternalServerError, res.Error) // 500
			return
		}

		options := models.GroupOptions{}
		json.Unmarshal(item.Group.Options, &options)

		if reimage := db.DB.Model(&item).Where("ip = ?", host).Update("reimage", false); reimage.Error != nil {
			Error(c, http.StatusInternalServerError, reimage.Error) // 500
			return
		}

		laddrport, ok := c.Request.Context().Value(http.LocalAddrContextKey).(net.Addr)
		if !ok {
			logrus.WithFields(logrus.Fields{
				"interface": "could not determine the local interface used to apply to ks.cfgs postconfig callback",
			}).Debug("ks")
		}

		logrus.Info("Disabling re-imaging for host to avoid re-install looping")

		//decrypt the password
		decryptedPassword := secrets.Decrypt(item.Group.Password, key)

		//cleanup data to allow easier custom templating
		data := map[string]interface{}{
			"password":   decryptedPassword,
			"ip":         item.IP,
			"device":     item.Group.Device,
			"gateway":    item.Group.Gateway,
			"dns":        item.Group.DNS,
			"hostname":   item.Hostname,
			"netmask":    item.Group.Netmask,
			"via_server": laddrport,
			"erasedisks": options.EraseDisks,
			"bootdisk":   item.Group.BootDisk,
			"vlan":       item.Group.Vlan,
			"createvmfs": options.CreateVMFS,
		}

		ks := defaultks

		// check if default ks has been overridden.
		if item.Ks != "" {
			dec, _ := base64.StdEncoding.DecodeString(item.Ks)
			ks = string(dec)
			logrus.WithFields(logrus.Fields{
				"custom host ks": ks,
			}).Debug("ks")
		} else if item.Group.Ks != "" {
			dec, _ := base64.StdEncoding.DecodeString(item.Group.Ks)
			ks = string(dec)
			logrus.WithFields(logrus.Fields{
				"custom group ks": ks,
			}).Debug("ks")
		}

		t, err := template.New("").Parse(ks)
		if err != nil {
			logrus.Info(err)
			return
		}
		err = t.Execute(c.Writer, data)
		if err != nil {
			logrus.Info(err)
			return
		}

		logrus.Info("Served ks.cfg file")
		logrus.WithFields(logrus.Fields{
			"id":      item.ID,
			"ip":      item.IP,
			"host":    item.Hostname,
			"message": "served ks.cfg file",
		}).Info("ks")
		logrus.WithFields(logrus.Fields{
			"id":           item.ID,
			"percentage":   50,
			"progresstext": "kickstart",
		}).Info("progress")
		item.Progress = 50
		item.Progresstext = "kickstart"
		db.DB.Save(&item)

	}
}