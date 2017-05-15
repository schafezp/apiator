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
//investigate if these structs can be pulled into a constants.h type interface
//similar to C
var (
	jwtSecret           = []byte("KHOzH8DJRHIPfC9Mq8yH")
	cluster *gocb.Cluster
	bucket *gocb.Bucket
	err error
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
	DomainID string   `json:"domain_id" binding:"required"`
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
	DomainID string   `json:"domain_id" binding:"required"`
	Token string      `json:"token" binding:"required"`
	Doc   interface{} `json:"document"`
	DocID string      `json:"doc_id"`
}

type UserCRUD struct {
	ID string `json:"id" binding:"required"`
	Token string `json:"token" binding"required"`
	Doc UserDoc `json:"document"`
}

type UserDoc struct {
	Domains []DomainDoc `json:"domains" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type DomainDoc struct {
	DomainID string `json:"domain_id" binding:"required"`
	Owner bool `json:"owner" binding:"required"`
	Endpoints []DomainEndpointsDoc `json:"endpoints" binding:"required"`
}

type DomainEndpointsDoc struct {
	Name string `json:"name" binding:"required"`
	Permissions int `json:"permissions" binding"required"`
}

type DomainCRUD struct {
	Token string `json:"token" binding:"required"`
	DomainID string `json:"domain_id" binding:"required"`
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
		"exp":  time.Now().Add(10 * time.Hour).Format(time.RFC3339),
	}).SignedString(jwtSecret)
}

func decodeAuthUserOrFail(authToken string) (bool, string) {
	token, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v",
				token.Header["alg"])
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

	redisToken, _ := retrieveUserTokenRedis(authUser)
	if authToken != redisToken {
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

func checkReadPermission(username, domain, endpoint string) (bool, error) {
	var user_doc UserDoc
	bucket, err = cluster.OpenBucket("users", "")
	if err != nil {
		return false, err
	}
	_, err = bucket.Get(username, &user_doc)
	domains := user_doc.Domains
	if err != nil {
		return false, err
	}
	for _, domain_doc := range domains {
		if domain_doc.DomainID == domain {
			endpoints := domain_doc.Endpoints
			for _, endpoint_doc := range endpoints {
				if endpoint == endpoint_doc.Name {
					return endpoint_doc.Permissions & 1 > 0, nil
				}
			}
		}
	}
	return false, nil
}

func checkWritePermission(username, domain, endpoint string) (bool, error) {
	var user_doc UserDoc
	bucket, err = cluster.OpenBucket("users", "")
	if err != nil {
		return false, err
	}
	_, err = bucket.Get(username, &user_doc)
	domains := user_doc.Domains
	if err != nil {
		return false, err
	}
	for _, domain_doc := range domains {
		if domain_doc.DomainID == domain {
			endpoints := domain_doc.Endpoints
			for _, endpoint_doc := range endpoints {
				if endpoint == endpoint_doc.Name {
					return endpoint_doc.Permissions & 2 > 0, nil
				}
			}
		}
	}
	return false, nil
}

func checkOwner(username, domain string) (bool, error) {
	var user_doc UserDoc
	bucket, err = cluster.OpenBucket("users", "")
	if err != nil {
		return false, err
	}
	_, err = bucket.Get(username, &user_doc)
	if err != nil {
		return false, err
	}
	domains := user_doc.Domains
	for _, domain_doc := range domains {
		if domain_doc.DomainID == domain {
			return domain_doc.Owner, nil
		}
	}
	return false, nil
}


func createBucket(bucket_name string) (bool, error) {
	var cluster_manager *gocb.ClusterManager
	cluster_manager = cluster.Manager("Administrator", "password")
	err = cluster_manager.InsertBucket(&gocb.BucketSettings{
		FlushEnabled:  false,
		IndexReplicas: false,
		Name:          bucket_name,
		Password:      "",
		Quota:         256,
		Replicas:      1,
		Type:          gocb.BucketType(0),
	})
	if err == nil {
		return true, nil
	}
	return false, err
}

func updateUserEndpoints(username, domain, endpoint string) error {
	var user_doc UserDoc
	bucket, err = cluster.OpenBucket("users", "")
	if err != nil {
		return err
	}
	_, err = bucket.Get(username, &user_doc)
	domains := user_doc.Domains
	if err != nil {
		return err
	}
	for index, domain_doc := range domains {
		if domain_doc.DomainID == domain {
			endpoints := domain_doc.Endpoints
			domain_doc.Endpoints = append(endpoints,
				DomainEndpointsDoc{
					Name:endpoint,
					Permissions:3,
				})
			user_doc.Domains[index].Endpoints = domain_doc.Endpoints
			fmt.Println("Yo you made it here")
		}
	}
	_, err = bucket.Replace(username, &user_doc,
		0, 0)
	if err != nil {
		return err
	}
	return nil
}
func main() {
	//establish connection to main Couchbase server on bootup
	cluster, err = gocb.Connect("137.112.104.106")
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
		bucket, err = cluster.OpenBucket("users", "")
		if err != nil {
			c.JSON(402, gin.H{
				"message": "request failed, unable to"+
					"open couchbase bucket",
				"error": err.Error(),
			})
		}

		var form Login
		c.Bind(&form)
		username := form.Username
		password := form.Password
		var couchpass map[string]interface{}
		_, err = bucket.Get(username, &couchpass)
		if err != nil {
			c.JSON(402, gin.H{
				"message": "request failed, unable to"+
					"get item by id: " + username,
				"error": err.Error(),
			})
		}

		match := CheckPasswordHash(password,
			couchpass["password"].(string))
		if match == true {
			//functionally a reset call as well
			token, _ := createJwtToken(username)
			err = resetUserTokenRedis(username)
			if err != nil {
				c.JSON(403, gin.H{
					"message": "request failed, unable to"+
						"reset user token on Redis",
					"error": err.Error(),
				})
			}
			err = storeUserTokenRedis(username, token)
			if err != nil {
				c.JSON(403, gin.H{
					"message": "request failed, unable to"+
						"store user token on Redis",
					"error": err.Error(),
				})
			}

			c.JSON(200, gin.H{
				"token":   token,
			})
		} else {
			c.JSON(401, gin.H{
				"message": "authorization denied",
			})
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
		err = c.BindJSON(&json)
		if err == nil {
			authed, user := decodeAuthUserOrFail(json.Token)
			owner, _ := checkOwner(user, json.DomainID)
			if (authed == true) && (owner == true) {
				bucket, err = cluster.OpenBucket("endpoints",
					"")
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to connect"+
						" to endpoints bucket",
						"error": err.Error(),
					})
				}
				bucket_id := json.DomainID + json.ID
				_, err = bucket.Get(bucket_id, &document)
				if err == nil {
					c.JSON(403, gin.H{
						"message": "endpoint already"+
						"exists!",
					})
				}
				document = json.Doc
				document.Owner = user
				document.CreatedAt = time.Now().Format(time.RFC3339)
				_, err = bucket.Insert(bucket_id, document, 0)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "failed to insert"+
							"endpoint" + bucket_id,
						"error": err.Error(),
					})
				}
				err = updateUserEndpoints(user, json.DomainID, json.ID)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "failed to update"+
							"user endpoints",
						"error": err.Error(),
					})
				}
				c.JSON(200, gin.H{
					"message": "document inserted",
				})
			} else {
				c.JSON(401, gin.H{
					"message": "unauthorized user!",
				})
			}
		} else {
			c.JSON(400, gin.H{
				"message": "error binding JSON to variable",
				"error": err.Error(),
			})
		}

	})
	r.POST("/get-endpoint", func(c *gin.Context) {
		var json EndpointCRUD
		var document EndpointDoc
		err = c.BindJSON(&json)
		if err == nil {
			authed, authUser := decodeAuthUserOrFail(json.Token)
			owner, _ := checkOwner(authUser, json.DomainID)
			if (authed == true) && (owner == true) {
				bucket_id := json.DomainID + json.ID
				bucket, err = cluster.OpenBucket("endpoints", "")
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to connect"+
						" to endpoints bucket",
						"error": err.Error(),
					})
				}
				_, err = bucket.Get(bucket_id, &document)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "failed to retrieve"+
							"endpoint" + bucket_id,
						"error": err.Error(),
					})
				}
				c.JSON(200, document)
			} else {
				c.JSON(401, gin.H{
					"message": "unauthorized user!",
				})
			}
		} else {
			c.JSON(400, gin.H{
				"message": "error binding JSON to variable",
				"error": err.Error(),
			})
		}
	})
	r.POST("/delete-endpoint", func(c *gin.Context) {
		var json EndpointCRUD
		if c.BindJSON(&json) == nil {
			authed, authUser := decodeAuthUserOrFail(json.Token)
			owner, _ := checkOwner(authUser, json.DomainID)
			if (authed == true) && (owner == true) {
				bucket, err = cluster.OpenBucket("endpoints", "")
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to connect"+
						" to endpoints bucket",
						"error": err.Error(),
					})
				}
				bucket_id := json.DomainID + json.ID
				_, err = bucket.Remove(bucket_id, 0)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "failed to delete"+
							"endpoint" + bucket_id,
						"error": err.Error(),
					})
				}
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
			authed, authUser := decodeAuthUserOrFail(json.Token)
			owner, _ := checkOwner(authUser, json.DomainID)
			if (authed == true) && (owner == true) {
				bucket, err = cluster.OpenBucket("endpoints", "")
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to connect"+
						" to endpoints bucket",
						"error": err.Error(),
					})
				}
				document = json.Doc
				bucket_id := json.DomainID + json.ID
				_, err = bucket.Get(bucket_id, &db_document)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to connect"+
						" to endpoints bucket",
						"error": err.Error(),
					})
				}
				document.CreatedAt = db_document.CreatedAt
				document.Owner = db_document.Owner
				_, err = bucket.Replace(bucket_id, document, 0, 0)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "error updating"+
						"endpoint document:"+bucket_id,
						"error": err.Error(),
					})
				}
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
		var bucket_check bool
		if c.BindJSON(&json) == nil {
			authed, authUser := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, err = cluster.OpenBucket("endpoints", "")
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to open endpoints bucket!",
						"error": err.Error(),
					})
				}
				bucket_id := json.DomainID + json.ID
				_, err = bucket.Get(bucket_id, &endpoint_doc)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to fetch endpoint_doc!",
						"error": err.Error(),
					})
				}
				if valid, _ := checkWritePermission(authUser, json.DomainID, json.ID); valid {
					var endpoint_bucket_name string
					endpoint_bucket_name = strings.Replace(json.ID, "/", "-", -1)
					endpoint_bucket_name = json.DomainID + endpoint_bucket_name
					bucket, err = cluster.OpenBucket(endpoint_bucket_name, "")
					if err != nil {
						owner, _ := checkOwner(authUser, json.DomainID)
						if owner == true {
							bucket_check, err = createBucket(endpoint_bucket_name)
						} else {
							c.JSON(402, gin.H{
								"message": "unable to open bucket!",
								"error": err.Error(),
							})
						}
					}
					if bucket_check == true {
						bucket, err = cluster.OpenBucket(endpoint_bucket_name, "")
					}
					if err != nil {
						c.JSON(402, gin.H{
							"message": "unable to open bucket!",
							"error": err.Error(),
						})
					}
					_, err = bucket.Insert(json.DocID, json.Doc, 0)
					if err != nil {
						c.JSON(402, gin.H{
							"message": "unable to insert document!",
							"error": err.Error(),
						})
					}
					c.JSON(200, gin.H{
						"message": "document inserted",
					})
				} else {
					c.JSON(401, gin.H{
						"message": "unauthorized user!",
					})
				}
			} else {
				c.JSON(401, gin.H{
					"message": "unauthorized user!",
				})
			}
		} else {
			c.JSON(401, gin.H{
				"message": "unauthorized user!",
			})
		}
	})
	r.POST("/update", func(c *gin.Context) {
		var json DataCRUD
		var endpoint_doc EndpointDoc
		if c.BindJSON(&json) == nil {
			authed, authUser := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, err = cluster.OpenBucket("endpoints", "")
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to open endpoints bucket!",
						"error": err.Error(),
					})
				}
				bucket_id := json.DomainID + json.ID
				_, err = bucket.Get(bucket_id, &endpoint_doc)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to fetch endpoint_doc!",
						"error": err.Error(),
					})
				}
				has_write_permission, _ := checkWritePermission(authUser, json.DomainID, json.ID)
				has_read_permission, _ := checkReadPermission(authUser, json.DomainID, json.ID)
				if (has_write_permission == true) && (has_read_permission == true) {
					var endpoint_bucket_name string
					endpoint_bucket_name = strings.Replace(json.ID, "/", "-", -1)
					endpoint_bucket_name = json.DomainID + endpoint_bucket_name
					bucket, err = cluster.OpenBucket(endpoint_bucket_name, "")
					if err != nil {
						c.JSON(402, gin.H{
							"message": "unable to open bucket!",
							"error": err.Error(),
						})
					}
					_, err = bucket.Replace(json.DocID, json.Doc, 0, 0)
					if err != nil {
						c.JSON(402, gin.H{
							"message": "unable to update document!",
							"error": err.Error(),
						})
					}
					c.JSON(200, gin.H{
						"message": "document updated",
					})
				} else {
					c.JSON(401, gin.H{
						"message": "unauthorized user!",
					})
				}
			} else {
				c.JSON(401, gin.H{
					"message": "unauthorized user!",
				})
			}
		} else {
			c.JSON(401, gin.H{
				"message": "error binding JSON!",
			})
		}
	})
	r.POST("/delete", func(c *gin.Context) {
		var json DataCRUD
		var endpoint_doc EndpointDoc
		if c.BindJSON(&json) == nil {
			authed, authUser := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, err = cluster.OpenBucket("endpoints", "")
				bucket_id := json.DomainID + json.ID
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to open endpoints bucket!",
						"error": err.Error(),
					})
				}
				_, err = bucket.Get(bucket_id, &endpoint_doc)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to fetch endpoint_doc!",
						"error": err.Error(),
					})
				}
				has_write_permission, _ := checkWritePermission(authUser, json.DomainID, json.ID)
				if has_write_permission == true {
					var endpoint_bucket_name string
					endpoint_bucket_name = strings.Replace(json.ID, "/", "-", -1)
					endpoint_bucket_name = json.DomainID + endpoint_bucket_name
					bucket, err = cluster.OpenBucket(endpoint_bucket_name, "")
					if err != nil {
						c.JSON(402, gin.H{
							"message": "unable to open bucket!",
							"error": err.Error(),
						})
					}
					_, err = bucket.Remove(json.DocID, 0)
					if err != nil {
						c.JSON(402, gin.H{
							"message": "unable to remove document!",
							"error": err.Error(),
						})
					}
					c.JSON(200, gin.H{
						"message": "document updated",
					})
				} else{
					c.JSON(401, gin.H{
					"message": "unauthorized user!",
					})
				}
			} else {
				c.JSON(401, gin.H{
					"message": "unauthorized user!",
				})
			}
		} else {
			c.JSON(401, gin.H{
				"message": "error binding JSON!",
			})
		}
	})
	r.POST("/get", func(c *gin.Context) {
		var json DataCRUD
		var endpoint_doc EndpointDoc
		var data_blob interface{}
		if c.BindJSON(&json) == nil {
			authed, authUser := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, err = cluster.OpenBucket("endpoints", "")
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to open endpoints bucket!",
						"error": err.Error(),
					})
				}
				bucket_id := json.DomainID + json.ID
				_, err = bucket.Get(bucket_id, &endpoint_doc)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to fetch endpoint_doc!",
						"error": err.Error(),
					})
				}
				if valid, _ := checkReadPermission(authUser, json.DomainID, json.ID); valid {
					var endpoint_bucket_name string
					endpoint_bucket_name = strings.Replace(json.ID, "/", "-", -1)
					endpoint_bucket_name = json.DomainID + endpoint_bucket_name
					bucket, err = cluster.OpenBucket(endpoint_bucket_name, "")
					if err != nil {
						c.JSON(402, gin.H{
							"message": "unable to open bucket!",
							"error": err.Error(),
						})
					}
					bucket, err = cluster.OpenBucket(endpoint_bucket_name, "")
					if err != nil {
						c.JSON(402, gin.H{
							"message": "unable to open bucket!",
							"error": err.Error(),
						})
					}
					_, err = bucket.Get(json.DocID, &data_blob)
					if err != nil {
						c.JSON(402, gin.H{
							"message": "unable to get document!",
							"error": err.Error(),
						})
					}
					c.JSON(200, data_blob)
				} else {
					c.JSON(401, gin.H{
						"message": "unauthorized user!",
					})
				}
			} else {
				c.JSON(401, gin.H{
					"message": "unauthorized user!",
				})
			}
		} else {
			c.JSON(401, gin.H{
				"message": "error binding JSON!",
			})
		}
	})
	r.POST("/create-domain", func(c *gin.Context) {
		var json DomainCRUD
		var user_doc UserDoc
		err = c.BindJSON(&json)
		if err == nil {
			authed, authUser := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, err = cluster.OpenBucket("users", "")
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to connect"+
						" to users bucket",
						"error": err.Error(),
					})
				}
				_, err = bucket.Get(authUser, &user_doc)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to retrieve"+
						"user: "+authUser,
						"error": err.Error(),
					})
				}
				user_doc.Domains = append(user_doc.Domains,
					DomainDoc{
						DomainID: json.DomainID,
						Owner: true,
						Endpoints: []DomainEndpointsDoc{},
					})
				_, err = bucket.Replace(authUser, &user_doc,
					0, 0)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to update"+
						"user: "+authUser,
						"error": err.Error(),
					})
				}
				c.JSON(200, user_doc)
			}
		} else {
			c.JSON(401, gin.H{
				"message": "Error binding JSON!",
			})
		}
	})
	r.Run(":8000")
}
