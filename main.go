package main

import (
	"log"
	"net/http"
	"strconv"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/maxiepax/go-via2/api"
	"github.com/maxiepax/go-via2/config"
	ca "github.com/maxiepax/go-via2/crypto"
	"github.com/maxiepax/go-via2/db"
	"github.com/maxiepax/go-via2/dhcpd"
	"github.com/maxiepax/go-via2/models"
	"github.com/maxiepax/go-via2/secrets"
	"github.com/maxiepax/go-via2/websockets"
	"github.com/sirupsen/logrus"
	"github.com/davecgh/go-spew/spew"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type Config struct {
	Debug   bool
	Port    int `default:"8443"`
	Interfaces []string
}

func main() {

	logServer := websockets.NewLogServer()
	logrus.AddHook(logServer.Hook)
	logrus.WithFields(logrus.Fields{
		"version": version,
		"commit":  commit,
		"date":    date,
	}).Infof("Startup")

	db.Connect(true)

	//migrate models
	err := db.DB.AutoMigrate(&models.Host{}, models.Group{}, &models.Image{}, &models.User{})
	if err != nil {
		log.Fatal(err)
	}

	//create admin user if it doesn't exist
	var adm models.User
	hp := api.HashAndSalt([]byte("VMware1!"))
	if res := db.DB.Where(models.User{UserForm: models.UserForm{Username: "admin"}}).Attrs(models.User{UserForm: models.UserForm{Password: hp}}).FirstOrCreate(&adm); res.Error != nil {
		logrus.Warning(res.Error)
	}

	// load secrets key
	key := secrets.Init()

	// load config file
	conf := config.Load()

	// start dhcpd
	if !conf.DisableDhcp {
		for _, v := range conf.Network.Interfaces {
			go dhcpd.IPv4(v)
		}
	}

	// start gin setup
	router := gin.New()
	router.Use(cors.Default())

	// ks.cfg is served at top to not place it behind BasicAuth
	router.GET("ks.cfg", api.Ks(key))

	esx := router.Group("/")
		{
		esx.GET("/esx/*all", api.FileHandler(conf.Port))
		}

	// middleware to check if user is logged in
	router.Use(func(c *gin.Context) {
		username, password, hasAuth := c.Request.BasicAuth()
		if !hasAuth {
			logrus.WithFields(logrus.Fields{
				"login": "unauthorized request",
			}).Info("auth")
			c.Writer.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		//get the user that is trying to authenticate
		var user models.User
		if res := db.DB.Select("username", "password").Where("username = ?", username).First(&user); res.Error != nil {
			logrus.WithFields(logrus.Fields{
				"username": username,
				"status":   "supplied username does not exist",
			}).Info("auth")
			c.Writer.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		//check if passwords match
		if api.ComparePasswords(user.Password, []byte(password), username) {
			logrus.WithFields(logrus.Fields{
				"username": username,
				"status":   "successfully authenticated",
			}).Debug("auth")
		} else {
			logrus.WithFields(logrus.Fields{
				"username": username,
				"status":   "invalid password supplied",
			}).Info("auth")
			c.Writer.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	})

	a := router.Group("/api")
	{
		v1 := a.Group("/v1")
		{
			groups := v1.Group("/groups")
			{
				groups.GET("", api.GetGroups)
				groups.GET(":id", api.GetGroup)
				groups.POST("", api.CreateGroup(key))
				groups.PATCH(":id", api.UpdateGroup(key))
				groups.DELETE(":id", api.DeleteGroup)
			}

			hosts := v1.Group("/hosts")
			{
				hosts.GET("", api.GetHosts)
				hosts.GET(":id", api.GetHost)
				hosts.POST("", api.CreateHost)
				hosts.PATCH(":id", api.UpdateHost)
				hosts.DELETE(":id", api.DeleteHost)
			}

			images := v1.Group("/images")
			{
				images.GET("", api.GetImages)
				images.GET(":id", api.GetImage)
				images.POST("", api.CreateImage)
				images.DELETE(":id", api.DeleteImage)
			}

		v1.GET("log", logServer.Handle)
		v1.GET("version", api.Version(version, commit, date))
		}
	}

	// check if ./cert/server.crt exists, if not we will create the folder, and initiate a new CA and a self-signed certificate
	ca.Load()

	//enable HTTPS
	listen := ":" + strconv.Itoa(conf.Port)
	logrus.WithFields(logrus.Fields{
		"port": listen,
	}).Info("Webserver")
	err = router.RunTLS(listen, "./cert/server.crt", "./cert/server.key")

	logrus.WithFields(logrus.Fields{
		"error": err,
	}).Error("Webserver")

}