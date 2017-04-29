package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/couchbase/gocb.v1"
	"gopkg.in/gin-gonic/gin.v1"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

var (
	jwtSecret           = []byte("KHOzH8DJRHIPfC9Mq8yH")
	
)
const (
	redisServerAddr     = "apiator-3.csse.rose-hulman.edu:6379"
	redisServerPassword = "AK1lTOuHyUNT5sN4JHP7"
)

type Login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

type EndpointCRUD struct {
	ID    string      `json:"id" binding:"required"`
	Token string      `json:"token" binding:"required"`
	Doc   EndpointDoc `json:"document"`
}

type EndpointDoc struct {
	HTTPRequestTypes []string `json:"request_types"`
	Owner            string   `json:"owner"`
	Indexed          bool     `json:"indexed"`
	Index            string   `json:"index"`
	CreatedAt        string   `json:"created_at"`
}

type DataCRUD struct {
	ID    string      `json:"id" binding:"required"`
	Token string      `json:"token" binding:"required"`
	Doc   interface{} `json:"document"`
	DocID string      `json:"doc_id"`
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func createJwtToken(user string) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": user,
		"exp":  time.Now().Add(10 * time.Minute).Format(time.RFC3339),
	}).SignedString(jwtSecret)
}

func decodeAuthUserOrFail(authToken string) (bool, string) {
	token, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return jwtSecret, nil
	})
	if err != nil {
		return false, ""
	}

	authUser := token.Claims.(jwt.MapClaims)["user"].(string)
	expiry := token.Claims.(jwt.MapClaims)["exp"].(string)
	expTime, _ := time.Parse(time.RFC3339, expiry)
	currTime := time.Now()
	if authUser == "" || expTime.Before(currTime) {
		return false, ""
	}
	return true, authUser
}
func PingRedis() (string, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     redisServerAddr,
		Password: redisServerPassword,
		DB:       0, // use default DB
	})

	pong, err := client.Ping().Result()
	return pong, err
	// fmt.Println(pong, err)
	// Output: PONG <nil>
}

//retrieve all usernames that have tokens currently
func retrieveAllAuthedUsersRedis() ([]string, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     redisServerAddr,
		Password: redisServerPassword,
		DB:       0, // use default DB
	})

	val, err := client.SMembers("usernames").Result()
	return val, err
}

//Store a given jwt user token in redis
func storeUserTokenRedis(username, jwt string) error {
	client := redis.NewClient(&redis.Options{
		Addr:     redisServerAddr,
		Password: redisServerPassword,
		DB:       0, // use default DB
	})
	client.SAdd("usernames", username)
	// client.SAdd("jwts",jwt)
	err := client.Set(fmt.Sprintf("token_%s", username), jwt, 0).Err()
	return err
}
func resetUserTokenRedis(username string) error {
	client := redis.NewClient(&redis.Options{
		Addr:     redisServerAddr,
		Password: redisServerPassword,
		DB:       0, // use default DB
	})
	// sremerr := client.SRem("usernames", username).Err()
	client.SRem("usernames", username)
	err := storeUserTokenRedis(username,"")
	return err
}

//retrieve the jwt of a user in  a given jwt user token in redis
func retrieveUserTokenRedis(username string) (string, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     redisServerAddr,
		Password: redisServerPassword,
		DB:       0, // use default DB
	})

	val, err := client.Get(fmt.Sprintf("token_%s", username)).Result()
	return val, err
}

func main() {
	var cluster *gocb.Cluster
	var bucket *gocb.Bucket
	var bucketerror error
	var geterror error
	var connecterror error
	cluster, connecterror = gocb.Connect("137.112.104.106")
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	r.GET("/redis/ping", func(c *gin.Context) {
		var pong, err = PingRedis()

		c.JSON(200, gin.H{
			"redis-err":     err,
			"redis-message": pong,
		})
	})
	r.GET("/redis/set-user-token/:username", func(c *gin.Context) {
		var username = c.Param("username")
		var jwt, jwterr = createJwtToken(username)
		if jwterr != nil {
			c.JSON(400, gin.H{
				"jwt-create-err": jwterr,
				"jwt":            jwt})
		}

		var err = storeUserTokenRedis(username, jwt)
		c.JSON(200, gin.H{
			"redis-err": err,
			"user":      username,
			"jwt":       jwt,
		})
	})
	r.GET("/redis/reset-user-token/:username", func(c *gin.Context) {
		var username = c.Param("username")
		var err = resetUserTokenRedis(username)
		c.JSON(200, gin.H{
			"redis-err": err,
			// "redis-reset-err": reseterr,
			"user":      username,
			"jwt":       "reset: value nil",
		})
	})
	r.GET("/redis/get-user-token/:username", func(c *gin.Context) {
		var username = c.Param("username")
		fmt.Println("username")
		fmt.Println(username)
		var token, err = retrieveUserTokenRedis(username)
		if err != nil{
			c.JSON(200, gin.H{
			"redis-err":  "could not find token for username",
			"user-token": token,
		})
		}else {
			c.JSON(200, gin.H{
			"redis-err":  err,
			"user-token": token,
		})
		}
		
	})
	r.GET("/redis/get-all-authed-users", func(c *gin.Context) {
		var tokens, err = retrieveAllAuthedUsersRedis()
		c.JSON(200, gin.H{
			"redis-err":   err,
			"user-tokens": tokens,
		})
	})
	r.GET("/solr/ping", func(c *gin.Context) {
		resp, err := http.Get("http://apiator-2.csse.rose-hulman.edu:8983/solr/test/admin/ping")
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		fmt.Println("get:\n", string(body))

		c.JSON(200, gin.H{
			"solr-message": string(body),
		})
	})
	r.POST("/auth", func(c *gin.Context) {
		bucket, bucketerror = cluster.OpenBucket("users", "")
		if bucketerror != nil {
			c.JSON(402, gin.H{
				"message": "request failed, unable to open couchbase bucket",
			})
		} else {
			var cas gocb.Cas
			var form Login
			c.Bind(&form)
			username := form.Username
			password := form.Password
			var couchpass map[string]interface{}
			cas, geterror = bucket.Get(username, &couchpass)

			if cas == 0 {
				fmt.Println("bucket error: ", bucketerror)
				fmt.Println("get error: ", geterror)
				fmt.Println("connect error: ", connecterror)
			} else {
				match := CheckPasswordHash(password,
					couchpass["password"].(string))
				if match == true {
					token, _ := createJwtToken(username)
					c.JSON(200, gin.H{
						"token":   token,
						"expires": time.Now().Add(time.Minute),
					})
				} else {
					c.JSON(401, gin.H{
						"message": "request failed, authorization denied",
					})
				}

			}
		}
	})
	r.GET("/authed-ping", func(c *gin.Context) {
		authed, _ := decodeAuthUserOrFail("foo")
		if authed == true {
			c.JSON(200, gin.H{
				"message": "pong",
			})
		} else {
			c.JSON(401, gin.H{
				"message": "unauthorized user!",
			})
		}
	})
	r.POST("/create-endpoint", func(c *gin.Context) {
		var json EndpointCRUD
		var document EndpointDoc
		if c.BindJSON(&json) == nil {
			authed, user := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, _ = cluster.OpenBucket("endpoints", "")
				document = json.Doc
				document.Owner = user
				document.CreatedAt = time.Now().Format(time.RFC3339)
				_, _ = bucket.Insert(json.ID, document, 0)
				c.JSON(200, gin.H{
					"message": "document inserted",
				})
			} else {
				c.JSON(401, gin.H{
					"message": "unauthorized user!",
				})
			}
		}

	})
	r.POST("/get-endpoint", func(c *gin.Context) {
		var json EndpointCRUD
		var document EndpointDoc
		if c.BindJSON(&json) == nil {
			authed, _ := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, _ = cluster.OpenBucket("endpoints", "")
				_, _ = bucket.Get(json.ID, &document)
				c.JSON(200, document)
			} else {
				c.JSON(401, gin.H{
					"message": "unauthorized user!",
				})
			}
		}
	})
	r.POST("/delete-endpoint", func(c *gin.Context) {
		var json EndpointCRUD
		if c.BindJSON(&json) == nil {
			authed, _ := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, _ = cluster.OpenBucket("endpoints", "")
				_, _ = bucket.Remove(json.ID, 0)
				c.JSON(200, gin.H{
					"message": "document deleted",
				})
			} else {
				c.JSON(401, gin.H{
					"message": "unauthorized user!",
				})
			}
		}
	})
	r.POST("/update-endpoint", func(c *gin.Context) {
		var json EndpointCRUD
		var document EndpointDoc
		var db_document EndpointDoc
		if c.BindJSON(&json) == nil {
			authed, _ := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, _ = cluster.OpenBucket("endpoints", "")
				document = json.Doc
				_, _ = bucket.Get(json.ID, &db_document)
				document.CreatedAt = db_document.CreatedAt
				document.Owner = db_document.Owner
				_, _ = bucket.Replace(json.ID, document, 0, 0)
				c.JSON(200, gin.H{
					"message": "document updated",
				})
			} else {
				c.JSON(401, gin.H{
					"message": "unauthorized user!",
				})
			}
		}
	})
	r.POST("/insert", func(c *gin.Context) {
		var json DataCRUD
		var endpoint_doc EndpointDoc
		var err error
		var cluster_manager *gocb.ClusterManager
		if c.BindJSON(&json) == nil {
			authed, _ := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, _ = cluster.OpenBucket("endpoints", "")
				_, _ = bucket.Get(json.ID, &endpoint_doc)
				if endpoint_doc.Owner != "" {
					var endpoint_bucket_name string
					endpoint_bucket_name = strings.Replace(json.ID, "/", "-", -1)
					bucket, err = cluster.OpenBucket(endpoint_bucket_name, "")
					if err != nil {
						cluster_manager = cluster.Manager("Administrator", "password")
						err = cluster_manager.InsertBucket(&gocb.BucketSettings{
							FlushEnabled:  false,
							IndexReplicas: false,
							Name:          endpoint_bucket_name,
							Password:      "",
							Quota:         256,
							Replicas:      1,
							Type:          gocb.BucketType(0),
						})
						time.Sleep(8 * time.Second)
					}
					bucket, _ = cluster.OpenBucket(endpoint_bucket_name, "")
					_, _ = bucket.Insert(json.DocID, json.Doc, 0)
					c.JSON(200, gin.H{
						"message": "document inserted",
					})
				}
			} else {
				c.JSON(401, gin.H{
					"message": "unauthorized user!",
				})
			}
		} else {
			fmt.Printf("whoops!")
		}
	})
	r.POST("/update", func(c *gin.Context) {
		var json DataCRUD
		var endpoint_doc EndpointDoc
		if c.BindJSON(&json) == nil {
			authed, _ := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, _ = cluster.OpenBucket("endpoints", "")
				_, _ = bucket.Get(json.ID, &endpoint_doc)
				if endpoint_doc.Owner != "" {
					var endpoint_bucket_name string
					endpoint_bucket_name = strings.Replace(json.ID, "/", "-", -1)
					bucket, _ = cluster.OpenBucket(endpoint_bucket_name, "")
					_, _ = bucket.Replace(json.DocID, json.Doc, 0, 0)
					c.JSON(200, gin.H{
						"message": "document updated",
					})
				}
			} else {
				c.JSON(401, gin.H{
					"message": "unauthorized user!",
				})
			}
		} else {
			fmt.Printf("whoops!")
		}
	})
	r.POST("/delete", func(c *gin.Context) {
		var json DataCRUD
		var endpoint_doc EndpointDoc
		if c.BindJSON(&json) == nil {
			authed, _ := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, _ = cluster.OpenBucket("endpoints", "")
				_, _ = bucket.Get(json.ID, &endpoint_doc)
				if endpoint_doc.Owner != "" {
					var endpoint_bucket_name string
					endpoint_bucket_name = strings.Replace(json.ID, "/", "-", -1)
					bucket, _ = cluster.OpenBucket(endpoint_bucket_name, "")
					_, _ = bucket.Remove(json.DocID, 0)
					c.JSON(200, gin.H{
						"message": "document removed",
					})
				}
			} else {
				c.JSON(401, gin.H{
					"message": "unauthorized user!",
				})
			}
		} else {
			fmt.Printf("whoops!")
		}
	})
	r.POST("/get", func(c *gin.Context) {
		var json DataCRUD
		var endpoint_doc EndpointDoc
		var data_blob interface{}
		if c.BindJSON(&json) == nil {
			authed, _ := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, _ = cluster.OpenBucket("endpoints", "")
				_, _ = bucket.Get(json.ID, &endpoint_doc)
				if endpoint_doc.Owner != "" {
					var endpoint_bucket_name string
					endpoint_bucket_name = strings.Replace(json.ID, "/", "-", -1)
					bucket, _ = cluster.OpenBucket(endpoint_bucket_name, "")
					_, _ = bucket.Get(json.DocID, &data_blob)
					c.JSON(200, data_blob)
				}
			} else {
				c.JSON(401, gin.H{
					"message": "unauthorized user!",
				})
			}
		} else {
			fmt.Printf("whoops!")
		}
	})
	r.Run(":8000")
}
