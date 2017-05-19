package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/couchbase/gocb.v1"
	"gopkg.in/gin-gonic/gin.v1"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

//local user defined packages
import "./dbsolr"
import "./config"
import "./structs"
import "./sync"
import "./stats"

// func handleCouchbaseError()
var (
	jwtSecret = []byte("KHOzH8DJRHIPfC9Mq8yH")
	conf      = config.GetConfig()
	//reasonable initial length? currently set to 5
	operationsToApply        = make([]sync.QueuedOperation, 5)
	cluster, connectionerror = gocb.Connect(conf.CouchbaseServerAddr)
)

func solrOperationFail(operation structs.DataCRUD) {
	fmt.Printf("Solr operation failed: %s \n", operation)
	operationsToApply = append(operationsToApply, sync.QueuedOperation{DbType: 2, Operation: operation})
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
	if err != nil {
		// q1 := fmt.Sprintf("sadd usernames %s", username)
		return err
	}
	// client.SAdd("jwts",jwt)
	err = client.Set(fmt.Sprintf("token_%s", username), jwt, 0).Err()
	if err != nil {
		// q2 := fmt.Sprintf("set token_%s %s", username, jwt)
		return err
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
	err := storeUserTokenRedis(username, "")

	if err != nil {
		return err
		// q1 := fmt.Sprintf("usernames %s", username)
		// q2 := fmt.Sprintf("token_%s", username)
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

func checkEndpointPermission(username string, domain string, endpointArg string, permission int) (bool, error) {
	var userDoc structs.UserDoc
	var err error
	bucket, err := cluster.OpenBucket("users", "")
	if err != nil {
		return false, err
	}
	_, err = bucket.Get(username, &userDoc)
	domains := userDoc.Domains
	if err != nil {
		return false, err
	}
	for _, domain_doc := range domains {
		if domain_doc.DomainID == domain {
			endpoints := domain_doc.Endpoints
			for _, endpoint_doc := range endpoints {
				if endpointArg == endpoint_doc.Name {
					return endpoint_doc.Permissions&permission > 0, nil
				}
			}
		}
	}
	return false, nil
}

func checkOwner(username, domain string) (bool, error) {
	var userDoc structs.UserDoc
	var err error
	bucket, err := cluster.OpenBucket("users", "")
	if err != nil {
		return false, err
	}
	_, err = bucket.Get(username, &userDoc)
	if err != nil {
		return false, err
	}
	domains := userDoc.Domains
	for _, domain_doc := range domains {
		if domain_doc.DomainID == domain {
			return domain_doc.Owner, nil
		}
	}
	return false, nil
}

func createBucket(bucket_name string) (bool, error) {
	var cluster_manager *gocb.ClusterManager
	var err error
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
	if err != nil {
		return false, err
	}
	verified := false
	for !verified {
		_, err := cluster.OpenBucket(bucket_name, "")
		if err == nil {
			verified = true
		}
	}
	return verified, nil
}

func createUserEndpoints(username, domain, endpointArg string) error {
	var userDoc structs.UserDoc
	var err error
	bucket, err := cluster.OpenBucket("users", "")
	if err != nil {
		return err
	}
	_, err = bucket.Get(username, &userDoc)
	if err != nil {
		return err
	}
	domains := userDoc.Domains
	for index, domain_doc := range domains {
		if domain_doc.DomainID == domain {
			endpoints := domain_doc.Endpoints
			domain_doc.Endpoints = append(endpoints,
				structs.DomainEndpointsDoc{
					Name:        endpointArg,
					Permissions: 7,
				})
			userDoc.Domains[index].Endpoints = domain_doc.Endpoints
			_, err = bucket.Replace(username, &userDoc,
				0, 0)
			if err != nil {
				return err
			}
			err = stats.AddUserStatistic(username, domain, endpointArg, 7)
			if err != nil {
				return err
			}
			return nil
		}
	}
	err = stats.AddUserStatistic(username, domain, endpointArg, 7)
	if err != nil {
		return err
	}
	return nil
}

func updateUserEndpoints(username string, domain string, endpointArg string, permissions int) error {
	var userDoc structs.UserDoc
	var err error
	bucket, err := cluster.OpenBucket("users", "")
	if err != nil {
		return err
	}
	_, err = bucket.Get(username, &userDoc)
	if err != nil {
		return err
	}
	domains := userDoc.Domains
	for index, domain_doc := range domains {
		if domain_doc.DomainID == domain {
			endpoints := domain_doc.Endpoints
			for endpoint_index, endpoints_doc := range endpoints {
				if endpoints_doc.Name == endpointArg {
					endpoints[endpoint_index] = structs.DomainEndpointsDoc{
						Name:        endpointArg,
						Permissions: permissions,
					}
					domain_doc.Endpoints = endpoints
					userDoc.Domains[index].Endpoints = domain_doc.Endpoints
					_, err = bucket.Replace(username, &userDoc,
						0, 0)
					if err != nil {
						return err
					}
					err = stats.DeleteUserStatistic(username, domain, endpointArg)
					if err != nil {
						return err
					}
					err = stats.AddUserStatistic(username, domain, endpointArg, permissions)
					if err != nil {
						return err
					}
					return nil
				}
			}
			endpoints = append(endpoints, structs.DomainEndpointsDoc{
				Name:        endpointArg,
				Permissions: permissions,
			})
			domain_doc.Endpoints = endpoints
			userDoc.Domains[index].Endpoints = domain_doc.Endpoints
			_, err = bucket.Replace(username, &userDoc,
				0, 0)
			if err != nil {
				return err
			}
			err = stats.DeleteUserStatistic(username, domain, endpointArg)
			if err != nil {
				return err
			}
			err = stats.AddUserStatistic(username, domain, endpointArg, permissions)
			if err != nil {
				return err
			}
			return nil
		}
	}
	domains = append(domains, structs.DomainDoc{
		DomainID: domain,
		Owner:    false,
		Endpoints: []structs.DomainEndpointsDoc{
			structs.DomainEndpointsDoc{
				Name:        endpointArg,
				Permissions: permissions,
			},
		},
	})
	userDoc.Domains = domains
	_, err = bucket.Replace(username, &userDoc,
		0, 0)
	if err != nil {
		return err
	}
	err = stats.DeleteUserStatistic(username, domain, endpointArg)
	if err != nil {
		return err
	}
	err = stats.AddUserStatistic(username, domain, endpointArg, permissions)
	if err != nil {
		return err
	}
	return nil
}

func deleteUserEndpoints(username string, domain string, endpointArg string) error {
	var userDoc structs.UserDoc
	var err error
	bucket, err := cluster.OpenBucket("users", "")
	if err != nil {
		return err
	}
	_, err = bucket.Get(username, &userDoc)
	if err != nil {
		return err
	}
	domains := userDoc.Domains
	for index, domain_doc := range domains {
		if domain_doc.DomainID == domain {
			endpoints := domain_doc.Endpoints
			for endpoint_index, endpoints_doc := range endpoints {
				if endpoints_doc.Name == endpointArg {
					domain_doc.Endpoints = append(endpoints[:endpoint_index], endpoints[endpoint_index+1:]...)
					userDoc.Domains[index].Endpoints = domain_doc.Endpoints
					_, err = bucket.Replace(username, &userDoc,
						0, 0)
					if err != nil {
						return err
					}
					err = stats.DeleteUserStatistic(username, domain, endpointArg)
					if err != nil {
						return err
					}
					return nil
				}
			}
		}
	}
	return nil
}

func bucketInsert(bucket *gocb.Bucket, document interface{}, id string) error {
	_, err := bucket.Insert(id, document, 0)
	return err
}

// Use document.Username as key always
func userBucketInsert(bucket *gocb.Bucket, document structs.Login) error {
	var json structs.UserDoc
	json.Password = document.Password
	json.Domains = make([]structs.DomainDoc, 0)
	_, err := bucket.Insert(document.Username, json, 0)
	return err
}

//This function
func storeFailedOperation() {

}

func main() {
	cluster, err := gocb.Connect(conf.CouchbaseServerAddr)
	if err != nil {
		log.Panic(err)
	}

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

	r.POST("/redis/set-user-token/:username", func(c *gin.Context) {
		var username = c.Param("username")
		var jwt, jwterr = createJwtToken(username)
		if jwterr != nil {
			c.JSON(500, gin.H{
				"jwt-create-err": jwterr,
				"jwt":            jwt})
		}

		var err = storeUserTokenRedis(username, jwt)
		//TODO: figure out why returning 400/500 here causes postman to Syntax error
		// if err != nil {
		// 	c.JSON(500, gin.H{
		// 		"store-error": err,})
		// }
		c.JSON(200, gin.H{
			"redis-err": err,
			"user":      username,
			"jwt":       jwt,
		})
	})
	r.GET("log-stored-ops", func(c *gin.Context) {
		sync.LogStoredOps(operationsToApply)

	})
	r.GET("/redis/reset-user-token/:username", func(c *gin.Context) {
		var username = c.Param("username")
		var err = resetUserTokenRedis(username)
		if err != nil {
			c.JSON(400, gin.H{
				"redis-err": err,
				// "redis-reset-err": reseterr,
				"user": username,
			})
		} else {
			c.JSON(200, gin.H{
				"redis-err": err,
				// "redis-reset-err": reseterr,
				"user": username,
				"jwt":  "reset: value nil",
			})
		}

	})
	r.GET("/redis/get-user-token/:username", func(c *gin.Context) {
		var username = c.Param("username")
		fmt.Println("username")
		fmt.Println(username)
		var token, err = retrieveUserTokenRedis(username)
		if err != nil {
			c.JSON(200, gin.H{
				"redis-err":  "could not find token for username",
				"user-token": token,
			})
		} else {

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
		sync.Syncdbs(operationsToApply, conf)
		c.JSON(200, gin.H{
			"solr-message": "Start attempt to sync manually",
		})
	})
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
		results, err := dbsolr.SolrRetrieveAllUsers()

		if err != nil {
			c.JSON(400, gin.H{
				"error retrieve users": err,
			})
		} else {
			c.JSON(200, gin.H{
				"users": results,
			})
		}
	})
	r.GET("/solr/getuser/:username", func(c *gin.Context) {
		var username = c.Param("username")
		results, err := dbsolr.SolrRetrieveUsers(username)

		if err != nil {
			c.JSON(400, gin.H{
				"error retrieve users": results,
			})
		} else {
			c.JSON(200, gin.H{
				"users": results,
			})
		}
	})
	r.POST("/solr/insertuser", func(c *gin.Context) {

		var form structs.Login
		c.Bind(&form)
		result, err := dbsolr.SolrInsertUser(&form)
		if err != nil {
			c.JSON(400, gin.H{
				"error insert user": result,
			})
		} else {
			c.JSON(200, gin.H{
				"success: result": result,
			})
		}
	})
	r.POST("/create-user", func(c *gin.Context) {
		bucket, bucketerror := cluster.OpenBucket("users", "")
		if bucketerror != nil {
			c.JSON(402, gin.H{
				"message": "request failed, unable to open couchbase bucket",
				"error":   bucketerror.Error(),
			})
			return
		}
		var form structs.Login
		c.Bind(&form)
		hashed, err := HashPassword(form.Password)
		if err != nil {
			c.JSON(402, gin.H{
				"message": "request failed, unable to hash password",
			})
			return
		}

		form.Password = hashed
		err = userBucketInsert(bucket, form)
		if err != nil {
			c.JSON(402, gin.H{
				"message": "request failed, unable to insert to couchbase bucket",
				"err":     err,
			})
			return
		}
		_, err = dbsolr.SolrInsertUser(&form)
		if err != nil {
			c.JSON(402, gin.H{
				"message": "request failed, unable to insert user to solr",
				"err":     err,
			})
			return
		}

		c.JSON(200, gin.H{
			"message": "insert successful",
			"err":     err,
		})
	})
	r.POST("/delete-user", func(c *gin.Context) {
		var err error
		bucket, bucketerror := cluster.OpenBucket("users", "")
		if bucketerror != nil {
			c.JSON(402, gin.H{
				"message": "request failed, unable to open couchbase bucket",
				"error":   bucketerror.Error(),
			})
			return
		}
		var form structs.TokenDoc
		c.Bind(&form)
		authed, user := decodeAuthUserOrFail(form.Token)
		if authed == false {
			c.JSON(402, gin.H{
				"message": "request failed, unable to open couchbase bucket",
				"error":   bucketerror.Error(),
			})
			return
		}
		_, err = bucket.Remove(user, 0)
		if err != nil {
			c.JSON(402, gin.H{
				"message": "request failed, unable to remove user in couchbase",
				"error":   err.Error(),
			})
			return
		}
		err = resetUserTokenRedis(user)
		if err != nil {
			c.JSON(402, gin.H{
				"message": "request failed, unable to remove user in redis",
				"error":   err.Error(),
			})
			return
		}
		c.JSON(200, gin.H{
			"message": "insert successful",
			"err":     err,
		})
		// } else {
		// 	var cas gocb.Cas
		// 	var form structs.Login
		// 	c.Bind(&form)
		// 	fmt.Println("Auth login received")
		// 	fmt.Println(form)
		// 	username := form.Username
		// 	password := form.Password
		// 	var couchpass map[string]interface{}
		// 	cas, geterror = bucket.Get(username, &couchpass)

		// 	if cas == 0 {
		// 		fmt.Println("bucket error: ", bucketerror)
		// 		fmt.Println("get error: ", geterror)
		// 		fmt.Println("connect error: ", connecterror)
		// 	} else {
		// 		match := CheckPasswordHash(password,
		// 			couchpass["password"].(string))
		// 		if match == true {
		// 			token, _ := createJwtToken(username)
		// 			//TODO: Handle the case where REDIS is down when we try to do this
		// 			//append the failed value to a list rather than just fail
		// 			_ = storeUserTokenRedis(username, token)
		// 			// if err != nil{

		// 			// }

	})
	r.POST("/auth", func(c *gin.Context) {
		var err error
		bucket, err := cluster.OpenBucket("users", "")
		if err != nil {
			c.JSON(402, gin.H{
				"message": "request failed, unable to" +
					"open couchbase bucket",
				"error": err.Error(),
			})
			return
		}
		var form structs.Login
		c.Bind(&form)
		username := form.Username
		password := form.Password
		var couchpass map[string]interface{}
		_, err = bucket.Get(username, &couchpass)
		if err != nil {
			c.JSON(402, gin.H{
				"message": "request failed, unable to" +
					"get item by id: " + username,
				"error": err.Error(),
			})
			return
		}

		match := CheckPasswordHash(password,
			couchpass["password"].(string))
		if match == false {
			c.JSON(401, gin.H{
				"message": "authorization denied",
			})
			return
		}
		//functionally a reset call as well
		token, _ := createJwtToken(username)
		err = resetUserTokenRedis(username)
		if err != nil {
			c.JSON(403, gin.H{
				"message": "request failed, unable to" +
					"reset user token on Redis",
				"error": err.Error(),
			})
			return
		}
		err = storeUserTokenRedis(username, token)
		if err != nil {
			c.JSON(403, gin.H{
				"message": "request failed, unable to" +
					"store user token on Redis",
				"error": err.Error(),
			})
			return
		}

		c.JSON(200, gin.H{
			"token": token,
		})
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
		var err error
		var json structs.EndpointCRUD
		var document structs.EndpointDoc
		err = c.BindJSON(&json)
		if err != nil {
			c.JSON(400, gin.H{
				"message": "error binding JSON to variable",
				"error":   err.Error(),
			})
			return
		}
		authed, user := decodeAuthUserOrFail(json.Token)
		owner, _ := checkOwner(user, json.DomainID)
		if (authed == false) || (owner == false) {
			c.JSON(401, gin.H{
				"message": "unauthorized user!",
			})
			return
		}
		bucket, err := cluster.OpenBucket("endpoints", "")
		if err != nil {
			c.JSON(402, gin.H{
				"message": "unable to connect" +
					" to endpoints bucket",
				"error": err.Error(),
			})
			return
		}
		bucket_id := json.DomainID + json.ID
		_, err = bucket.Get(bucket_id, &document)
		if err == nil {
			c.JSON(403, gin.H{
				"message": "endpoint already" +
					"exists!",
			})
			return
		}
		document = json.Doc
		document.Owner = user
		document.CreatedAt = time.Now().Format(time.RFC3339)
		err = bucketInsert(bucket, document, bucket_id)
		if err != nil {
			c.JSON(402, gin.H{
				"message": "failed to insert" +
					"endpoint" + bucket_id,
				"error": err.Error(),
			})
			return
		}
		err = createUserEndpoints(user, json.DomainID, json.ID)
		if err != nil {
			c.JSON(402, gin.H{
				"message": "failed to update" +
					"user endpoints",
				"error": err.Error(),
			})
			return
		}

	})
	r.POST("/get-endpoint", func(c *gin.Context) {
		var json structs.EndpointCRUD
		var document structs.EndpointDoc
		var err error
		err = c.BindJSON(&json)
		if err == nil {
			authed, authUser := decodeAuthUserOrFail(json.Token)
			owner, _ := checkOwner(authUser, json.DomainID)
			if (authed == true) && (owner == true) {
				bucket_id := json.DomainID + json.ID
				bucket, err := cluster.OpenBucket("endpoints", "")
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to connect" +
							" to endpoints bucket",
						"error": err.Error(),
					})
					return
				}
				_, err = bucket.Get(bucket_id, &document)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "failed to retrieve" +
							"endpoint" + bucket_id,
						"error": err.Error(),
					})
					return
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
				"error":   err.Error(),
			})
		}
	})
	r.POST("/delete-endpoint", func(c *gin.Context) {
		var json structs.EndpointCRUD
		var cluster_manager *gocb.ClusterManager
		cluster_manager = cluster.Manager("Administrator", "password")
		if c.BindJSON(&json) == nil {
			authed, authUser := decodeAuthUserOrFail(json.Token)
			owner, _ := checkOwner(authUser, json.DomainID)
			if (authed == true) && (owner == true) {
				bucket, err := cluster.OpenBucket("endpoints", "")
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to connect" +
							" to endpoints bucket",
						"error": err.Error(),
					})
					return
				}
				bucket_id := json.DomainID + json.ID
				_, err = bucket.Remove(bucket_id, 0)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "failed to delete" +
							"endpoint" + bucket_id,
						"error": err.Error(),
					})
					return
				}
				err = cluster_manager.RemoveBucket(bucket_id)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "failed to delete associated bucket for " +
							"endpoint" + bucket_id,
						"error": err.Error(),
					})
					return
				}
				bucket, err = cluster.OpenBucket("statistics", "")
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to connect" +
							" to statistics bucket",
						"error": err.Error(),
					})
					return
				}
				err = removeEndpointFromStatistics(bucket, bucket_id)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to remove" +
							" endpoint from statistics bucket",
						"error": err.Error(),
					})
					return
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
		var json structs.EndpointCRUD
		var document structs.EndpointDoc
		var db_document structs.EndpointDoc
		if c.BindJSON(&json) == nil {
			authed, authUser := decodeAuthUserOrFail(json.Token)
			owner, _ := checkOwner(authUser, json.DomainID)
			if (authed == true) && (owner == true) {
				bucket, err := cluster.OpenBucket("endpoints", "")
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to connect" +
							" to endpoints bucket",
						"error": err.Error(),
					})
					return
				}
				document = json.Doc
				bucket_id := json.DomainID + json.ID
				_, err = bucket.Get(bucket_id, &db_document)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to connect" +
							" to endpoints bucket",
						"error": err.Error(),
					})
					return
				}
				document.CreatedAt = db_document.CreatedAt
				document.Owner = db_document.Owner
				_, err = bucket.Replace(bucket_id, document, 0, 0)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "error updating" +
							"endpoint document:" + bucket_id,
						"error": err.Error(),
					})
					return
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
		var json structs.DataCRUD
		var endpoint_doc structs.EndpointDoc
		var bucket_check bool
		if c.BindJSON(&json) == nil {
			authed, authUser := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, err := cluster.OpenBucket("endpoints", "")
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to open endpoints bucket!",
						"error":   err.Error(),
					})
					AddMissCount(json.DomainID, json.ID)
					UpdateTimeStatistic(json.DomainID, json.ID)
					return
				}
				bucket_id := json.DomainID + json.ID
				_, err = bucket.Get(bucket_id, &endpoint_doc)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to fetch endpoint_doc!",
						"error":   err.Error(),
					})
					AddMissCount(json.DomainID, json.ID)
					UpdateTimeStatistic(json.DomainID, json.ID)
					return
				}
				if valid, _ := checkEndpointPermission(authUser, json.DomainID, json.ID, 2); valid {
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
								"error":   err.Error(),
							})
							AddMissCount(json.DomainID, json.ID)
							UpdateTimeStatistic(json.DomainID, json.ID)
							return
						}
					}
					if bucket_check == true {
						bucket, err = cluster.OpenBucket(endpoint_bucket_name, "")
					}
					if err != nil {
						c.JSON(402, gin.H{
							"message": "unable to open bucket!",
							"error":   err.Error(),
						})
						AddMissCount(json.DomainID, json.ID)
						UpdateTimeStatistic(json.DomainID, json.ID)
						return
					}
					_, err = bucket.Insert(json.DocID, json.Doc, 0)
					if err != nil {
						c.JSON(402, gin.H{
							"message": "unable to insert document!",
							"error":   err.Error(),
						})
						AddMissCount(json.DomainID, json.ID)
						UpdateTimeStatistic(json.DomainID, json.ID)
						return
					}
					AddHitCount(json.DomainID, json.ID)
					UpdateTimeStatistic(json.DomainID, json.ID)
					_, err = dbsolr.SolrInsertEndpoint(json)

					//in this case, store as queued operation
					if err != nil {
						//make sure this mutates operationsToApply
						solrOperationFail(json)
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
		var json structs.DataCRUD
		var endpoint_doc structs.EndpointDoc
		if c.BindJSON(&json) == nil {
			authed, authUser := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, err := cluster.OpenBucket("endpoints", "")
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to open endpoints bucket!",
						"error":   err.Error(),
					})
					AddMissCount(json.DomainID, json.ID)
					UpdateTimeStatistic(json.DomainID, json.ID)
					return
				}
				bucket_id := json.DomainID + json.ID
				_, err = bucket.Get(bucket_id, &endpoint_doc)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to fetch endpoint_doc!",
						"error":   err.Error(),
					})
					AddMissCount(json.DomainID, json.ID)
					UpdateTimeStatistic(json.DomainID, json.ID)
					return
				}
				has_write_permission, _ := checkEndpointPermission(authUser, json.DomainID, json.ID, 2)
				has_read_permission, _ := checkEndpointPermission(authUser, json.DomainID, json.ID, 1)
				if (has_write_permission == true) && (has_read_permission == true) {
					var endpoint_bucket_name string
					endpoint_bucket_name = strings.Replace(json.ID, "/", "-", -1)
					endpoint_bucket_name = json.DomainID + endpoint_bucket_name
					bucket, err = cluster.OpenBucket(endpoint_bucket_name, "")
					if err != nil {
						c.JSON(402, gin.H{
							"message": "unable to open bucket!",
							"error":   err.Error(),
						})
						AddMissCount(json.DomainID, json.ID)
						UpdateTimeStatistic(json.DomainID, json.ID)
						return
					}
					_, err = bucket.Replace(json.DocID, json.Doc, 0, 0)
					if err != nil {
						c.JSON(402, gin.H{
							"message": "unable to update document!",
							"error":   err.Error(),
						})
						AddMissCount(json.DomainID, json.ID)
						UpdateTimeStatistic(json.DomainID, json.ID)
						return
					}
					AddHitCount(json.DomainID, json.ID)
					UpdateTimeStatistic(json.DomainID, json.ID)
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
		var json structs.DataCRUD
		var endpoint_doc structs.EndpointDoc
		if c.BindJSON(&json) == nil {
			authed, authUser := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, err := cluster.OpenBucket("endpoints", "")
				bucket_id := json.DomainID + json.ID
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to open endpoints bucket!",
						"error":   err.Error(),
					})
					AddMissCount(json.DomainID, json.ID)
					UpdateTimeStatistic(json.DomainID, json.ID)
					return
				}
				_, err = bucket.Get(bucket_id, &endpoint_doc)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to fetch endpoint_doc!",
						"error":   err.Error(),
					})
					AddMissCount(json.DomainID, json.ID)
					UpdateTimeStatistic(json.DomainID, json.ID)
					return
				}
				has_del_permission, _ := checkEndpointPermission(authUser, json.DomainID, json.ID, 4)
				if has_del_permission == true {
					var endpoint_bucket_name string
					endpoint_bucket_name = strings.Replace(json.ID, "/", "-", -1)
					endpoint_bucket_name = json.DomainID + endpoint_bucket_name
					bucket, err = cluster.OpenBucket(endpoint_bucket_name, "")
					if err != nil {
						c.JSON(402, gin.H{
							"message": "unable to open bucket!",
							"error":   err.Error(),
						})
						AddMissCount(json.DomainID, json.ID)
						UpdateTimeStatistic(json.DomainID, json.ID)
						return
					}
					_, err = bucket.Remove(json.DocID, 0)
					if err != nil {
						c.JSON(402, gin.H{
							"message": "unable to remove document!",
							"error":   err.Error(),
						})
						AddMissCount(json.DomainID, json.ID)
						UpdateTimeStatistic(json.DomainID, json.ID)
						return
					}
					AddHitCount(json.DomainID, json.ID)
					UpdateTimeStatistic(json.DomainID, json.ID)
					c.JSON(200, gin.H{
						"message": "delete successful",
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
	r.POST("/get", func(c *gin.Context) {
		var json structs.DataCRUD
		var endpoint_doc structs.EndpointDoc
		var data_blob interface{}
		if c.BindJSON(&json) == nil {
			authed, authUser := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, err := cluster.OpenBucket("endpoints", "")
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to open endpoints bucket!",
						"error":   err.Error(),
					})
					AddMissCount(json.DomainID, json.ID)
					UpdateTimeStatistic(json.DomainID, json.ID)
					return
				}
				bucket_id := json.DomainID + json.ID
				_, err = bucket.Get(bucket_id, &endpoint_doc)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to fetch endpoint_doc!",
						"error":   err.Error(),
					})
					AddMissCount(json.DomainID, json.ID)
					UpdateTimeStatistic(json.DomainID, json.ID)
					return
				}
				if valid, _ := checkEndpointPermission(authUser, json.DomainID, json.ID, 1); valid {
					var endpoint_bucket_name string
					endpoint_bucket_name = strings.Replace(json.ID, "/", "-", -1)
					endpoint_bucket_name = json.DomainID + endpoint_bucket_name
					bucket, err = cluster.OpenBucket(endpoint_bucket_name, "")
					if err != nil {
						c.JSON(402, gin.H{
							"message": "unable to open bucket!",
							"error":   err.Error(),
						})
						AddMissCount(json.DomainID, json.ID)
						UpdateTimeStatistic(json.DomainID, json.ID)
						return
					}
					bucket, err = cluster.OpenBucket(endpoint_bucket_name, "")
					if err != nil {
						c.JSON(402, gin.H{
							"message": "unable to open bucket!",
							"error":   err.Error(),
						})
						AddMissCount(json.DomainID, json.ID)
						UpdateTimeStatistic(json.DomainID, json.ID)
						return
					}
					_, err = bucket.Get(json.DocID, &data_blob)
					if err != nil {
						c.JSON(402, gin.H{
							"message": "unable to get document!",
							"error":   err.Error(),
						})
						AddMissCount(json.DomainID, json.ID)
						UpdateTimeStatistic(json.DomainID, json.ID)
						return
					}
					AddHitCount(json.DomainID, json.ID)
					UpdateTimeStatistic(json.DomainID, json.ID)
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
		var json structs.DomainCRUD
		var userDoc structs.UserDoc
		var err error
		err = c.BindJSON(&json)
		if err == nil {
			authed, authUser := decodeAuthUserOrFail(json.Token)
			if authed == true {
				bucket, err := cluster.OpenBucket("users", "")
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to connect" +
							" to users bucket",
						"error": err.Error(),
					})
					return
				}
				_, err = bucket.Get(authUser, &userDoc)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to retrieve" +
							"user: " + authUser,
						"error": err.Error(),
					})
					return
				}
				userDoc.Domains = append(userDoc.Domains,
					structs.DomainDoc{
						DomainID:  json.DomainID,
						Owner:     true,
						Endpoints: []structs.DomainEndpointsDoc{},
					})
				_, err = bucket.Replace(authUser, &userDoc,
					0, 0)
				if err != nil {
					c.JSON(402, gin.H{
						"message": "unable to update" +
							"user: " + authUser,
						"error": err.Error(),
					})
					return
				}
				c.JSON(200, userDoc)
			}
		} else {
			c.JSON(401, gin.H{
				"message": "Error binding JSON!",
			})
		}
	})
	r.POST("/update-user-permissions", func(c *gin.Context) {
		var json structs.UserPermissionsDoc
		var err error
		err = c.BindJSON(&json)
		if err != nil {
			c.JSON(401, gin.H{
				"message": "Error binding JSON!",
			})
			return
		}
		authed, authUser := decodeAuthUserOrFail(json.Token)
		owner, _ := checkOwner(authUser, json.DomainID)
		if (authed == false) || (owner == false) {
			c.JSON(401, gin.H{
				"message": "unauthorized user!",
			})
			return
		}
		err = updateUserEndpoints(json.Username, json.DomainID, json.ID, json.Permissions)
		if err != nil {
			c.JSON(402, gin.H{
				"message": "failed to update" +
					"user endpoints",
				"error": err.Error(),
			})
			return
		}
		c.JSON(200, gin.H{
			"message": "User permissions updated.",
		})
	})
	r.POST("/delete-user-permissions", func(c *gin.Context) {
		var json structs.UserPermissionsDoc
		var err error
		err = c.BindJSON(&json)
		if err != nil {
			c.JSON(401, gin.H{
				"message": "Error binding JSON!",
			})
			return
		}
		authed, authUser := decodeAuthUserOrFail(json.Token)
		owner, _ := checkOwner(authUser, json.DomainID)
		if (authed == false) || (owner == false) {
			c.JSON(401, gin.H{
				"message": "unauthorized user!",
			})
			return
		}
		err = deleteUserEndpoints(json.Username, json.DomainID, json.ID)
		if err != nil {
			c.JSON(402, gin.H{
				"message": "failed to delete" +
					"user endpoints",
				"error": err.Error(),
			})
			return
		}
		c.JSON(200, gin.H{
			"message": "User permissions deleted.",
		})
	})
	r.POST("/get-statistics", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Woohoo!",
		})
	})
	r.POST("/get-endpoints", func(c *gin.Context) {
		var login_form structs.TokenDoc
		var userDoc structs.UserDoc
		var err error
		err = c.BindJSON(&login_form)
		if err != nil {
			c.JSON(400, gin.H{
				"message": "error binding JSON to variable",
				"error":   err.Error(),
			})
			return
		}
		authed, user := decodeAuthUserOrFail(login_form.Token)
		if authed == false {
			c.JSON(401, gin.H{
				"message": "unauthorized user!",
			})
			return
		}
		bucket, err := cluster.OpenBucket("users", "")
		if err != nil {
			c.JSON(402, gin.H{
				"message": "request failed, unable to" +
					"open couchbase bucket",
				"error": err.Error(),
			})
			return
		}

		_, err = bucket.Get(user, &userDoc)
		if err != nil {
			c.JSON(402, gin.H{
				"message": "request failed, unable to" +
					"retrieve user info",
				"error": err.Error(),
			})
			return
		}
		c.JSON(200, userDoc.Domains)
	})
	r.Run(":8000")
}
