package main

import (
	"fmt"
	"gopkg.in/gin-gonic/gin.v1"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/couchbase/gocb.v1"
	"github.com/go-redis/redis"
	"net/http"
	"io/ioutil"
	
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
func PingRedis() (string,error){
	client := redis.NewClient(&redis.Options{
		Addr:     "apiator-3.csse.rose-hulman.edu:6379",
		Password: "AK1lTOuHyUNT5sN4JHP7", 
		DB:       0,  // use default DB
	})

	pong, err := client.Ping().Result()
	return pong, err
	// fmt.Println(pong, err)
	// Output: PONG <nil>
}

func main() {
	var cluster *gocb.Cluster
	var bucket *gocb.Bucket
	var bucketerror error
	var geterror error
	var connecterror error
	cluster, connecterror = gocb.Connect("127.0.0.1")
	bucket, bucketerror = cluster.OpenBucket("users","")
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	r.GET("/redisping", func(c *gin.Context) {
		var pong,err = PingRedis()
		c.JSON(200, gin.H{
			"redis-err": err,
			"redis-message": pong,
		})
	})
	r.GET("/solrping", func(c *gin.Context) {
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
                hashedpass, _ := HashPassword(password)
		var couchpass map[string]interface{}

		cas, geterror = bucket.Get("zach", &couchpass)
		name_check := bucket.Name()
		fmt.Println("bucket name: ", name_check)

		if cas == 0 {
			fmt.Println("Error with get call")
			fmt.Println("Username: ", username)
			fmt.Println("form: ", form)
			fmt.Println("bucket error: ", bucketerror)
			fmt.Println("get error: ", geterror)
			fmt.Println("connect error: ", connecterror)
			fmt.Println(couchpass)
		}else{
			match := CheckPasswordHash(hashedpass, couchpass["password"].(string))
			c.JSON(200, gin.H{
				"matching_pass_check": match,
			})
		}
        })
	r.Run(":8000") // listen and serve on 0.0.0.0:8000
}
