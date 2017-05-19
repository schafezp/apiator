package sync

import (
	"fmt"
	"github.com/go-redis/redis"
)

import ".././config"

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

//calling this function with go routine will sync the dbs
// func syncdbs(syncRedis,syncSolr, quit chan int){
func Syncdbs(operationsToApply []QueuedOperation,  conf config.Config){
	for _, op := range operationsToApply{
		switch  op.DbType {
		case 0://couchbase
			fmt.Println("Don't handle couchbase queued ops'")
			// switch op.functtype:
			//do stuff depending on functtype passing in necessary args

		case 1://redis
			client := redis.NewClient(&redis.Options{
				Addr:     conf.RedisServerAddr,
				Password: conf.RedisServerPassword,
				DB:       0, // use default DB
			})
			fmt.Println("Run failed redis command: %s",op.Operation)
			fmt.Println(op.Operation)
			err := client.Eval(op.Operation,[]string{})
			//TODO: putting back here is dangerous if too many "bad" redis commands stack up
			if err == nil{//if successful then remove that slice part
				operationsToApply = append(operationsToApply[:0], operationsToApply[1:]...)
			}
			
		case 2://solr
			fmt.Println("Don't handle solr queued ops'")
			
		default:
		}
	}
}

func LogStoredOps(operationsToApply []QueuedOperation){
	for _,op := range operationsToApply{
		switch  op.DbType {
		case 0://couchbase
			fmt.Println("Don't handle couchbase queued ops'")
		case 1://redis
			fmt.Println("Run failed redis command: %s",op.Operation)
		case 2://solr
			fmt.Println("Don't handle solr queued ops'")
		default:
		}
	}
}
