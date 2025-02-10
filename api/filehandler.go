package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/gin-gonic/gin"
	"github.com/maxiepax/go-via2/db"
	"github.com/maxiepax/go-via2/models"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm/clause"
)

func FileHandler(configPort int) func(c *gin.Context) {
	return func(c *gin.Context) {
		requestor, _, _ := net.SplitHostPort(c.Request.RemoteAddr)

		var host models.Host
		if res := db.DB.Preload(clause.Associations).Where("ip = ?", requestor).First(&host); res.Error != nil {
			Error(c, http.StatusInternalServerError, res.Error) // 500
			return
		}

		var image models.Image
		if res := db.DB.Where("id = ?", host.Group.ImageID).Find(&image); res.Error != nil {
			Error(c, http.StatusInternalServerError, res.Error) // 500
			return
		}

		imagePath := image.Path
		file := strings.TrimPrefix(c.Request.RequestURI, "/esx")

		spew.Dump(file)

		switch file {
		case "/mboot.efi":
			filename, _ := mbootPath(imagePath)
			logrus.WithFields(logrus.Fields{
				requestor: "requesting mboot.efi",
				"file:": filename,
			}).Info("httpd")
			fileContent, err := os.ReadFile(filename)
			if err != nil {
				fmt.Println(err)
			}
			//defer fileContent.Close()
			c.Header("Content-Disposition", "attachment; filename="+file)
    		c.Data(http.StatusOK, "application/octet-stream", fileContent)
			//http.ServeContent(c.Writer, c.Request, "boot.cfg", time.Now(), fileContent)
		case "/crypto64.efi":
			logrus.WithFields(logrus.Fields{
				requestor: "requesting crypto64.efi",
			}).Info("httpd")
			filename, _ := crypto64Path(imagePath)
			fileContent, err := os.ReadFile(filename)
			if err != nil {
				fmt.Println(err)
			}
			c.Header("Content-Disposition", "attachment; filename="+file)
    		c.Data(http.StatusOK, "application/octet-stream", fileContent)
		case "/boot.cfg":
			logrus.WithFields(logrus.Fields{
				requestor: "requesting boot.cfg",
			}).Info("httpd")
			interfaceAndPort := c.Request.Host
			bootConfig, _ := bootCfg(host, image, requestor, interfaceAndPort)
			http.ServeContent(c.Writer, c.Request, "boot.cfg", time.Now(), strings.NewReader(bootConfig))
		default:
			logrus.WithFields(logrus.Fields{
				requestor: imagePath+file,
			}).Info("httpd")
			fileContent, err := os.ReadFile(imagePath+file)
			if err != nil {
				fmt.Println(err)
			}
			c.Header("Content-Disposition", "attachment; filename="+file)
    		c.Data(http.StatusOK, "application/octet-stream", fileContent)
		}
	}
}

func mbootPath(imagePath string) (string, error) {
	//check these paths if the file exists.
	paths := []string{"/EFI/BOOT/BOOTX64.EFI", "/EFI/BOOT/BOOTAA64.EFI", "/MBOOT.EFI", "/mboot.efi", "/efi/boot/bootx64.efi", "/efi/boot/bootaa64.efi"}

	for _, v := range paths {
		if _, err := os.Stat(imagePath + v); err == nil {
			return imagePath + v, nil
		}
	}
	//couldn't find the file
	return "", fmt.Errorf("could not locate a mboot.efi")

}

func crypto64Path(imagePath string) (string, error) {
	//check these paths if the file exists.
	paths := []string{"/EFI/BOOT/CRYPTO64.EFI", "/efi/boot/crypto64.efi"}

	for _, v := range paths {
		if _, err := os.Stat(imagePath + v); err == nil {
			return imagePath + v, nil
		}
	}
	//couldn't find the file
	return "", fmt.Errorf("could not locate a crypto64.efi")

}

func bootCfg(host models.Host, image models.Image, requestor string, interfaceAndPort string) (string, error) {
	//if the filename is boot.cfg, or /boot.cfg, we serve the boot cfg that belongs to that build. unfortunately, it seems boot.cfg or /boot.cfg varies in builds.

	logrus.WithFields(logrus.Fields{
		requestor: "requesting boot.cfg",
	}).Info("httpd")
	logrus.WithFields(logrus.Fields{
		"id":           host.ID,
		"percentage":   15,
		"progresstext": "installation",
	}).Info("progress")
	host.Progress = 15
	host.Progresstext = "installation"
	db.DB.Save(&host)

	bc, err := os.ReadFile(image.Path + "/BOOT.CFG")
	if err != nil {
		logrus.Warn(err)
		return "could not locate boot.cfg", err
	}

	// strip slashes from paths in file
	re := regexp.MustCompile("/")
	bc = re.ReplaceAllLiteral(bc, []byte(""))

	// add kickstart path to kernelopt
	re = regexp.MustCompile("kernelopt=.*")
	o := re.Find(bc)
	bc = re.ReplaceAllLiteral(bc, append(o, []byte(" ks=https://"+interfaceAndPort+"/ks.cfg")...))

	// append the mac address of the hardware interface to ensure ks.cfg request comes from the right interface, along with ip, netmask and gateway.
	re = regexp.MustCompile("kernelopt=.*")
	o = re.Find(bc)
	bc = re.ReplaceAllLiteral(bc, append(o, []byte(" netdevice="+host.Group.Device+" ip="+host.IP+" netmask="+host.Group.Netmask+" gateway="+host.Group.Gateway)...))

	// if vlan is configured for the group, append the vlan to kernelopts
	if host.Group.Vlan != "" {
		re = regexp.MustCompile("kernelopt=.*")
		o = re.Find(bc)
		bc = re.ReplaceAllLiteral(bc, append(o, []byte(" vlanid="+host.Group.Vlan)...))
	}

	// load options from the group
	options := models.GroupOptions{}
	json.Unmarshal(host.Group.Options, &options)

	// if autopart is configured for the group, append autopart to kernelopt - https://kb.vmware.com/s/article/77009

	// add allowLegacyCPU=true to kernelopt
	if options.AllowLegacyCPU {
		re = regexp.MustCompile("kernelopt=.*")
		o = re.Find(bc)
		bc = re.ReplaceAllLiteral(bc, append(o, []byte(" allowLegacyCPU=true")...))
	}

	// replace prefix with prefix=foldername
	//split := strings.Split(image.Path, "/")
	re = regexp.MustCompile("prefix=")
	o = re.Find(bc)
	bc = re.ReplaceAllLiteral(bc, append(o, []byte("https://"+interfaceAndPort+"/esx")...))

	ret := string(bc[:])
	return ret, fmt.Errorf("could not build boot.cfg")
}
