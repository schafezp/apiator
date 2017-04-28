package main

import (
	"fmt"
	"gopkg.in/gin-gonic/gin.v1"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/couchbase/gocb.v1"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis"
	"time"
	"net/http"
	"strings"
	"io/ioutil"
)

var (
	jwtSecret  = []byte("KHOzH8DJRHIPfC9Mq8yH")
	redisServerAddr = "apiator-3.csse.rose-hulman.edu:6379"
	redisServerPassword = "AK1lTOuHyUNT5sN4JHP7"
)

type Login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
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
		"exp": time.Now().Add(time.Minute).Format(time.RFC3339),
	}).SignedString(jwtSecret)
}

func decodeAuthUserOrFail(req *http.Request) bool {
	authHeader := req.Header.Get("Authorization")
	authHeaderParts := strings.SplitN(authHeader, " ", 2)
	if authHeaderParts[0] != "Bearer" {
		return false
	}

	authToken := authHeaderParts[1]
	token, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return jwtSecret, nil
	})
	if err != nil {
		return false
	}

	authUser := token.Claims.(jwt.MapClaims)["user"].(string)
	expiry := token.Claims.(jwt.MapClaims)["exp"].(string)
	expTime, _ := time.Parse(time.RFC3339, expiry)
	currTime := time.Now()
	if authUser == "" || expTime.Before(currTime){
		return false
	}

	return true
}
func PingRedis() (string,error){
	client := redis.NewClient(&redis.Options{
		Addr:     redisServerAddr,
		Password: redisServerPassword, 
		DB:       0,  // use default DB
	})

	pong, err := client.Ping().Result()
	return pong, err
	// fmt.Println(pong, err)
	// Output: PONG <nil>
}

//retrieve all usernames that have tokens currently
func retrieveAllAuthedUsersRedis() ([]string,error){
	client := redis.NewClient(&redis.Options{
		Addr:     redisServerAddr,
		Password: redisServerPassword, 
		DB:       0,  // use default DB
	})

	val,err := client.SMembers("usernames").Result()
	return val,err
}
//Store a given jwt user token in redis
func storeUserTokenRedis(username,jwt  string) (error){
	client := redis.NewClient(&redis.Options{
		Addr:     redisServerAddr,
		Password: redisServerPassword, 
		DB:       0,  // use default DB
	})
	client.SAdd("usernames",username)
	// client.SAdd("jwts",jwt)
	err := client.Set(fmt.Sprintf("token_%s",username), jwt,0).Err()
	return err
}
//retrieve the jwt of a user in  a given jwt user token in redis
func retrieveUserTokenRedis(username string) (string,error){
	client := redis.NewClient(&redis.Options{
		Addr:     redisServerAddr,
		Password: redisServerPassword, 
		DB:       0,  // use default DB
	})
	
	val,err := client.Get(fmt.Sprintf("token_%s",username)).Result()
	return val,err
}




func main() {
	var cluster *gocb.Cluster
	var bucket *gocb.Bucket
	var bucketerror error
	var geterror error
	var connecterror error
	cluster, connecterror = gocb.Connect("127.0.0.1")
	bucket, bucketerror = cluster.OpenBucket("default","")
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	r.GET("/redis/ping", func(c *gin.Context) {
		var pong,err = PingRedis()
		
		c.JSON(200, gin.H{
			"redis-err": err,
			"redis-message": pong,
		})
	})
	r.GET("/redis/set-user-token/:username", func(c *gin.Context) {
		var username = c.Param("username")
		var jwt,jwterr = createJwtToken(username)
		if jwterr != nil {
			c.JSON(400, gin.H{
				"jwt-create-err": jwterr,
				"jwt": jwt,})}
		
		var err = storeUserTokenRedis(username,jwt)
		c.JSON(200, gin.H{
			"redis-err": err,
			"user": username,
			"jwt": jwt,
		})
	})
	r.GET("/redis/get-user-token/:username", func(c *gin.Context) {
		var username = c.Param("username")
		fmt.Println("username")
		fmt.Println(username)
		var token,err = retrieveUserTokenRedis(username)
		c.JSON(200, gin.H{
			"redis-err": err,
			"user-token": token,
		})
	})
	r.GET("/redis/get-all-authed-users", func(c *gin.Context) {
		var tokens,err = retrieveAllAuthedUsersRedis()
		c.JSON(200, gin.H{
			"redis-err": err,
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
		}else{
			match := CheckPasswordHash(password,
				couchpass["password"].(string))
			if (match == true) {
				token,_ := createJwtToken(username)
				c.JSON(200, gin.H{
					"token": token,
					"expires": time.Now().Add(time.Minute),
				})
			} else {
				c.JSON(401, gin.H{
					"message": "request failed, authorization denied",
				})
			}

		}
        })
	r.GET("/authed-ping", func(c *gin.Context) {
		authed := decodeAuthUserOrFail(c.Request)
		if (authed == true) {
			c.JSON(200, gin.H{
				"message": "pong",
			})
		} else {
			c.JSON(401, gin.H{
				"message": "unauthorized user!",
			})
		}
	})
	r.Run(":8000")
}
