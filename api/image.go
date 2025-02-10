package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/gin-gonic/gin"
	"github.com/kdomanski/iso9660/util"
	"github.com/maxiepax/go-via2/db"
	"github.com/maxiepax/go-via2/models"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func GetImages(c *gin.Context) {
	var items []models.Image
	if res := db.DB.Find(&items); res.Error != nil {
		Error(c, http.StatusInternalServerError, res.Error) // 500
		return
	}
	c.JSON(http.StatusOK, items) // 200
}

func GetImage(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		Error(c, http.StatusBadRequest, err) // 400
		return
	}

	// Load the item
	var item models.Image
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

func CreateImage(c *gin.Context) {


	f, err := c.MultipartForm()
	if err != nil {
		Error(c, http.StatusInternalServerError, err) // 500
		return
	}
	spew.Dump(f)

	files := f.File["file[]"]

	spew.Dump(files)


	for _, file := range files {

		filename := file.Filename
		spew.Dump(filename)

		item := models.Image{}
		item.ISOImage = filepath.Base(file.Filename)
		item.Path = path.Join(".", "images", filename)
		item.Hash = c.PostForm("hash")
		item.Description = c.PostForm("description")

		os.MkdirAll(filepath.Dir(item.Path), os.ModePerm)

		_, err = SaveUploadedFile(file, item.Path)
		if err != nil {
			Error(c, http.StatusInternalServerError, err) // 500
			return
		}

		if item.Hash == "" {
			logrus.WithFields(logrus.Fields{
				"Hash": item.Hash,
			}).Warning("Image uploaded with no hash, please consider using a hash to avoid image corruption")
		} else {
			logrus.WithFields(logrus.Fields{
				"Hash": item.Hash,
			}).Warning("Image uploaded with hash, comparing hash!")

			f, err := os.Open(item.Path)
			if err != nil {
				logrus.Warning(err)
			}
			defer f.Close()

			h := sha256.New()
			if _, err := io.Copy(h, f); err != nil {
				log.Fatal(err)
			}

			if hex.EncodeToString(h.Sum(nil)) != item.Hash {
				err := fmt.Errorf("hash was invalid")
				Error(c, http.StatusBadRequest, err) // 400
				os.Remove(item.Path)
				return
			}

		}

		f, err := os.Open(item.Path)
		if err != nil {
			log.Fatalf("failed to open file: %s", err)
		}
		defer f.Close()

		//strip the filextension, eg. vmware.iso = vmware
		fn := strings.TrimSuffix(file.Filename, filepath.Ext(file.Filename))
		//merge into filepath
		fp := path.Join(".", "images", fn)

		if err = util.ExtractImageToDirectory(f, fp); err != nil {
			log.Fatalf("failed to extract image: %s", err)
		}

		//remove the file
		err = os.Remove(item.Path)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Debug("image")
		}

		//update item.Path
		item.Path = fp

		// get size of extracted dir

		size, err := dirSize(fp)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Debug("image")
		}

		item.Size = size

		if result := db.DB.Table("images").Create(&item); result.Error != nil {
			Error(c, http.StatusInternalServerError, result.Error) // 500
			return
		}
		logrus.WithFields(logrus.Fields{
			"id":          item.ID,
			"image":       item.ISOImage,
			"path":        item.Path,
			"size":        item.Size,
			"description": item.Description,
		}).Info("image")
		c.JSON(http.StatusOK, item) // 200
	}
}

func SaveUploadedFile(file *multipart.FileHeader, dst string) (int64, error) {
	src, err := file.Open()
	if err != nil {
		return -1, err
	}
	defer src.Close()

	out, err := os.Create(dst)
	if err != nil {
		return -1, err
	}
	defer out.Close()

	n, err := io.Copy(out, src)
	return n, err
}

func DeleteImage(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		Error(c, http.StatusBadRequest, err) // 400
		return
	}

	// Load the item
	var item models.Image
	if res := db.DB.First(&item, id); res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			Error(c, http.StatusNotFound, fmt.Errorf("not found")) // 404
		} else {
			Error(c, http.StatusInternalServerError, res.Error) // 500
		}
		return
	}

	//check if any group is using the image
	var group models.Group
	db.DB.First(&group, "image_id = ?", item.ID)

	if group.Name != "" {
		c.JSON(http.StatusConflict, "the image is being used by groups, please re-assign the groups to another image and then delete the image")
	} else {
		// Delete it
		//remove the entire directory and all files in it
		err = os.RemoveAll(item.Path)
		if err != nil {
			log.Fatal(err)
			Error(c, http.StatusInternalServerError, err) // 500
		}

		// remove record from database
		if res := db.DB.Delete(&item); res.Error != nil {
			Error(c, http.StatusInternalServerError, res.Error) // 500
			return
		}

		c.JSON(http.StatusNoContent, gin.H{}) //204
	}

}

/*
func WriteToFile(filename string, data string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.WriteString(file, data)
	if err != nil {
		return err
	}
	return file.Sync()
}

func GetInterfaceIpv4Addr(interfaceName string) (addr string, err error) {
	var (
		ief      *net.Interface
		addrs    []net.Addr
		ipv4Addr net.IP
	)
	if ief, err = net.InterfaceByName(interfaceName); err != nil { // get interface
		return
	}
	if addrs, err = ief.Addrs(); err != nil { // get addresses
		return
	}
	for _, addr := range addrs { // get ipv4 address
		if ipv4Addr = addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
			break
		}
	}
	if ipv4Addr == nil {
		return "", errors.New(fmt.Sprintf("interface %s don't have an ipv4 address\n", interfaceName))
	}
	return ipv4Addr.String(), nil
}
*/

func dirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return err
	})
	// convert byte to mb
	size = size / 1024 / 1024
	return size, err
}