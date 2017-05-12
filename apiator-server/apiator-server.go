package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/couchbase/gocb.v1"
	"github.com/rtt/Go-Solr"
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
	couchbaseServerAddr = "137.112.104.106"
	solrServerAddr = "http://apiator-2.csse.rose-hulman.edu:8983"
	redisServerAddr     = "apiator-3.csse.rose-hulman.edu:6379"
	redisServerPassword = "AK1lTOuHyUNT5sN4JHP7"
	solrServerHost = "localhost"
	solrServerPort = 8983
	solrCoreName = "gettingstarted"
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


func bucketInsert(bucket *gocb.Bucket,document interface{},id string)(error){
	_,err := bucket.Insert(id,document,0)
	return err
}

func solrRetrieveAllUsers()(interface{},error){
	s, err := solr.Init(solrServerHost, solrServerPort,solrCoreName)

	if err != nil{return nil,err}

	q := solr.Query{
		Params: solr.URLParamMap{
			"q":           []string{"*:*"},
		},
	}
	// perform the query, checking for errors
	res, err := s.Select(&q)

	if err != nil { return nil,err}
	results := res.Results

	for i := 0; i < results.Len(); i++ {
		fmt.Println("Username:", results.Get(i).Field("username"))
		fmt.Println("Password:", results.Get(i).Field("password"))

		fmt.Println("")
	}
	return results,nil
}
func solrRetrieveUsers(username string)(interface{},error){
	s, err := solr.Init(solrServerHost, solrServerPort,solrCoreName)

	if err != nil{return nil,err}

	qstring := fmt.Sprintf("username:*%s*",username)
	
	q := solr.Query{
		Params: solr.URLParamMap{
			"q":           []string{qstring},
		},
	}
	// perform the query, checking for errors
	res, err := s.Select(&q)

	if err != nil { return nil,err}
	results := res.Results

	for i := 0; i < results.Len(); i++ {
		fmt.Println("Username:", results.Get(i).Field("username"))
		fmt.Println("Password:", results.Get(i).Field("password"))

		fmt.Println("")
	}
	return results,nil
}

func solrInsertUser(user *Login)(bool,error){
	var resp *solr.UpdateResponse
	var err error;
	s, err := solr.Init(solrServerHost, solrServerPort, solrCoreName)

	if err != nil{return false,err}

	fmt.Println("User to insert:")
	fmt.Println(user)
	f := map[string]interface{}{
		"add": []interface{}{
			map[string]interface{}{"username": user.Username, "password": user.Password},
		},
	}
		
	resp, err = s.Update(f, true)

	if err != nil {
		return false,err
	} else {
		return resp.Success,err
}
}
// func solrInsertEndpoint(endpoint *EndpointDoc)(bool,error){
// 	var resp *solr.UpdateResponse
// 	var err error;
// 	s, err := solr.Init("localhost", 8983, "users")

// 	if err != nil{return false,err}

// 	fmt.Println("User to insert:")
// 	fmt.Println(endpoint)
// 	//TODO: put apporopriate fields
// 	// https://github.com/rtt/Go-Solr
// 	f := map[string]interface{}{
// 		"add": []interface{}{
// 			map[string]interface{}{"username": user.Username, "password": user.Password},
// 		},
// 	}
		
// 	resp, err = s.Update(f, true)

// 	if err != nil {
// 		return false,err
// 	} else {
// 		return resp.Success,err
// }
// }

func main() {
	var cluster *gocb.Cluster
	var bucket *gocb.Bucket
	var bucketerror error
	var geterror error
	var connecterror error
	cluster, connecterror = gocb.Connect(couchbaseServerAddr)
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
		resp, err := http.Get(solrServerAddr + "/solr/admin/ping")
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
	r.GET("/solr/getall", func(c *gin.Context) {
		results,err := solrRetrieveAllUsers()

		if err != nil{
			c.JSON(400, gin.H{
				"error retrieve users": results,
			})
		}else{
			c.JSON(200, gin.H{
			"users": results,
		})
		}
	})
	r.GET("/solr/getuser/:username", func(c *gin.Context) {
		var username = c.Param("username")
		results,err := solrRetrieveUsers(username)

		if err != nil{
			c.JSON(400, gin.H{
				"error retrieve users": results,
			})
		}else{
			c.JSON(200, gin.H{
			"users": results,
		})
		}
	})
	r.POST("/solr/insertuser", func(c *gin.Context) {

		var form Login
		c.Bind(&form)
		result,err := solrInsertUser(&form)
		if err != nil{
			c.JSON(400, gin.H{
				"error insert user": result,
			})
		}else{
			c.JSON(200, gin.H{
			"success: result": result,
		})
		}
	})
	r.POST("/create-user" , func(c *gin.Context) {
		bucket, bucketerror = cluster.OpenBucket("users", "")
		if bucketerror != nil {
			c.JSON(402, gin.H{
				"message": "request failed, unable to open couchbase bucket",
			})
		} else {
			var form Login
			c.Bind(&form)
			username := form.Username
			hashed,err := HashPassword(form.Password)
			if err != nil{
				c.JSON(402, gin.H{
				"message": "request failed, unable to hash password",
				})}
			
			form.Password = hashed
			err = bucketInsert(bucket,form,username)
			if err != nil{
				c.JSON(402, gin.H{
					"message": "request failed, unable to insert to couchbase bucket",
					"err": err,
				})} else {

				c.JSON(200, gin.H{
					"message": "insert successful",
					"err": err,
				})
			}
			

		}
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
					//TODO: Handle the case where REDIS is down when we try to do this
					//append the failed value to a list rather than just fail
					_ = storeUserTokenRedis(username, token)

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
				err := bucketInsert(bucket,document,json.ID)
				if err != nil{
					c.JSON(200, gin.H{
					"message": "document inserted",
					})
				}else{
					c.JSON(400, gin.H{
					"message": "document insert failed",
					})
				}
				
				// _, _ = bucket.Insert(json.ID, document, 0)
				
				
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
		var endpointDoc EndpointDoc
		var err error
		var clusterManager *gocb.ClusterManager
		if c.BindJSON(&json) == nil {
			authed, _ := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, _ = cluster.OpenBucket("endpoints", "")
				_, _ = bucket.Get(json.ID, &endpointDoc)
				if endpointDoc.Owner != "" {
					var endpointBucketName string
					endpointBucketName = strings.Replace(json.ID, "/", "-", -1)
					bucket, err = cluster.OpenBucket(endpointBucketName, "")
					if err != nil {
						clusterManager = cluster.Manager("Administrator", "password")
						err = clusterManager.InsertBucket(&gocb.BucketSettings{
							FlushEnabled:  false,
							IndexReplicas: false,
							Name:          endpointBucketName,
							Password:      "",
							Quota:         256,
							Replicas:      1,
							Type:          gocb.BucketType(0),
						})
						time.Sleep(8 * time.Second)
					}
					bucket, _ = cluster.OpenBucket(endpointBucketName, "")
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
		var endpointDoc EndpointDoc
		if c.BindJSON(&json) == nil {
			authed, _ := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, _ = cluster.OpenBucket("endpoints", "")
				_, _ = bucket.Get(json.ID, &endpointDoc)
				if endpointDoc.Owner != "" {
					var endpointBucketName string
					endpointBucketName = strings.Replace(json.ID, "/", "-", -1)
					bucket, _ = cluster.OpenBucket(endpointBucketName, "")
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
		var endpointDoc EndpointDoc
		if c.BindJSON(&json) == nil {
			authed, _ := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, _ = cluster.OpenBucket("endpoints", "")
				_, _ = bucket.Get(json.ID, &endpointDoc)
				if endpointDoc.Owner != "" {
					var endpointBucketName string
					endpointBucketName = strings.Replace(json.ID, "/", "-", -1)
					bucket, _ = cluster.OpenBucket(endpointBucketName, "")
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
		var endpointDoc EndpointDoc
		var data_blob interface{}
		if c.BindJSON(&json) == nil {
			authed, _ := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, _ = cluster.OpenBucket("endpoints", "")
				_, _ = bucket.Get(json.ID, &endpointDoc)
				if endpointDoc.Owner != "" {
					var endpointBucketName string
					endpointBucketName = strings.Replace(json.ID, "/", "-", -1)
					bucket, _ = cluster.OpenBucket(endpointBucketName, "")
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
