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

//local user defined packages
import "./dbsolr"
import "./config"
import "./endpoint"
// func handleCouchbaseError()
var (
	jwtSecret           = []byte("KHOzH8DJRHIPfC9Mq8yH")
	conf = config.GetConfig()
	operationsToApply = make(chan QueuedOperation)
	syncRedis = make(chan int)
	syncSolr = make(chan int)
	quitSync = make(chan int)
	
)

func redisOperationFail(operation string){
	fmt.Printf("Redis operation failed: %s \n",operation)
	operationsToApply <- QueuedOperation{DbType:1,Operation:operation}
	// fmt.Printf("Redis operation failed: %s \n",operation)
}
func issueRedisSync(){
	syncRedis <- 1
}

//calling this function with go routine will sync the dbs
// func syncdbs(syncRedis,syncSolr, quit chan int){
func syncdbs(){
	for {
		select {
		case _ = <-quitSync:
			fmt.Println("Stop waiting to sync")
			return
			
		case _ = <-syncRedis:
			fmt.Println("Redis Sync Issued")
		client := redis.NewClient(&redis.Options{
		Addr:     conf.RedisServerAddr,
		Password: conf.RedisServerPassword,
			DB:       0, // use default DB
		})
			for op := range operationsToApply{
				switch  op.DbType {
				case 0://couchbase
					fmt.Println("Don't handle couchbase queued ops'")
					operationsToApply <- op

				case 1://redis
					fmt.Println("Run failed redis command: %s",op.Operation)
					fmt.Println(op.Operation)
					err := client.Eval(op.Operation,[]string{})
					//TODO: putting back here is dangerous if too many "bad" redis commands stack up
					if err != nil{//put it back
						operationsToApply <- op
					}
					
				case 2://solr
					fmt.Println("Don't handle solr queued ops'")
					operationsToApply<- op
				default:
				}
			}
			
		}
	}

}

//QueuedRedisOperation represents a redis operation to be performed
type QueuedRedisOperation struct {
	
}
//When SOLR or Redis is down and we receive a request we should store it rather than ignoring it
//to store it we will use a channel of Queued Operations

//QueuedOperation represents a queued instruction to preform 
type QueuedOperation struct {
		//TODO: make Databasetype be an enum type rather than int
	//currently 0 -> couchbase
	//          1 -> redis
	//          2 -> solr
	DbType int `form:"dbtype" json:"dbtype" binding:"required"`
	Operation string `form:"operation" json:"operation" binding:"required"`
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
		Addr:     conf.RedisServerAddr,
		Password: conf.RedisServerPassword,
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
		Addr:     conf.RedisServerAddr,
		Password: conf.RedisServerPassword,
		DB:       0, // use default DB
	})

	val, err := client.SMembers("usernames").Result()
	return val, err
}

//Store a given jwt user token in redis
func storeUserTokenRedis(username, jwt string) error {
	client := redis.NewClient(&redis.Options{
		Addr:     conf.RedisServerAddr,
		Password: conf.RedisServerPassword,
		DB:       0, // use default DB
	})
	err := client.SAdd("usernames", username).Err()
	if err  != nil{
		q1 := fmt.Sprintf("sadd usernames %s",username)
		go redisOperationFail(q1)
	}
	// client.SAdd("jwts",jwt)
	err = client.Set(fmt.Sprintf("token_%s", username), jwt, 0).Err()
	if err != nil{
		q2 := fmt.Sprintf("set token_%s %s", username,jwt)
		go redisOperationFail(q2)
	}
	
	
	return err
}
func resetUserTokenRedis(username string) error {
	client := redis.NewClient(&redis.Options{
		Addr:     conf.RedisServerAddr,
		Password: conf.RedisServerPassword,
		DB:       0, // use default DB
	})
	// sremerr := client.SRem("usernames", username).Err()
	client.SRem("usernames", username)
	err := storeUserTokenRedis(username,"")

	if err != nil{
		q1 := fmt.Sprintf("usernames %s",username)
		q2 := fmt.Sprintf("token_%s", username)
		go redisOperationFail(q1)
		go redisOperationFail(q2)
	}
	
	
	return err
}

//retrieve the jwt of a user in  a given jwt user token in redis
func retrieveUserTokenRedis(username string) (string, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     conf.RedisServerAddr,
		Password: conf.RedisServerPassword,
		DB:       0, // use default DB
	})

	val, err := client.Get(fmt.Sprintf("token_%s", username)).Result()
	return val, err
}


func bucketInsert(bucket *gocb.Bucket,document interface{},id string)(error){
	_,err := bucket.Insert(id,document,0)
	return err
}

// Use document.Username as key always
func userBucketInsert(bucket *gocb.Bucket,document endpoint.Login)(error){
	_,err := bucket.Insert(document.Username,document,0)
	return err
}



//This function 
func storeFailedOperation(){

}



func main() {
	var cluster *gocb.Cluster
	var bucket *gocb.Bucket
	var bucketerror error
	var geterror error
	var connecterror error
	//start sync dbs asap
	go syncdbs()
	cluster, connecterror = gocb.Connect(conf.CouchbaseServerAddr)
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
		if err != nil {
			c.JSON(400, gin.H{
			"redis-err": err,
			// "redis-reset-err": reseterr,
			"user":      username,
		})
		}else{
			c.JSON(200, gin.H{
			"redis-err": err,
			// "redis-reset-err": reseterr,
			"user":      username,
			"jwt":       "reset: value nil",
		})
		}
		
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
	//issues attempt to sync redis
	r.GET("/redis/sync", func(c *gin.Context) {
		go issueRedisSync()
		c.JSON(200, gin.H{
			"solr-message": "Start attempt to sync manually",
		})
	})
	//TODO: not tested w solrserverhost
	r.GET("/solr/ping", func(c *gin.Context) {
		resp, err := http.Get(conf.SolrServerHost + "/solr/admin/ping")
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
		results,err := dbsolr.SolrRetrieveAllUsers()

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
		results,err := dbsolr.SolrRetrieveUsers(username)

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

		var form endpoint.Login
		c.Bind(&form)
		result,err := dbsolr.SolrInsertUser(&form)
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
		}
		var form endpoint.Login
		c.Bind(&form)
		// username := form.Username
		hashed,err := HashPassword(form.Password)
		if err != nil{
			c.JSON(402, gin.H{
				"message": "request failed, unable to hash password",
			})}
		
		form.Password = hashed
		err = userBucketInsert(bucket,form)
		if err != nil{
			c.JSON(402, gin.H{
				"message": "request failed, unable to insert to couchbase bucket",
				"err": err,
			})}
		_,err = dbsolr.SolrInsertUser(&form)
		if err != nil{
			c.JSON(402, gin.H{
				"message": "request failed, unable to insert to couchbase bucket",
				"err": err,
			})
		}
		
		c.JSON(200, gin.H{
			"message": "insert successful",
			"err": err,
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
			var form endpoint.Login
			c.Bind(&form)
			fmt.Println("Auth login received")
			fmt.Println(form)
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
					// if err != nil{
						
					// }

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
		var json endpoint.EndpointCRUD
		var document endpoint.EndpointDoc
		if c.BindJSON(&json) == nil {
			authed, user := decodeAuthUserOrFail(json.Token)
			fmt.Println("Authed")
			fmt.Println(json)
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
		var json endpoint.EndpointCRUD
		var document endpoint.EndpointDoc
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
		var json endpoint.EndpointCRUD
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
		var json endpoint.EndpointCRUD
		var document endpoint.EndpointDoc
		var db_document endpoint.EndpointDoc
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
		var endpointDoc endpoint.EndpointDoc
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
		var endpointDoc endpoint.EndpointDoc
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
		var endpointDoc endpoint.EndpointDoc
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
		var endpointDoc endpoint.EndpointDoc
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
