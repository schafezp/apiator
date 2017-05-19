package sync

import (
	"fmt"
)
import ".././dbsolr"
import ".././config"
import ".././structs"

//If SOLR goes down we want to store the 


//QueuedOperation represents a queued instruction to preform 
type QueuedOperation struct {
	//TODO: make Databasetype be an enum type rather than int
	//currently 0 -> couchbase
	//          1 -> redis
	//          2 -> solr
	DbType int `form:"dbtype" json:"dbtype" binding:"required"`
	Operation structs.DataCRUD `form:"operation" json:"operation" binding:"required"`
}

//calling this function with go routine will sync the dbs
// func syncdbs(syncRedis,syncSolr, quit chan int){
func Syncdbs(operationsToApply []QueuedOperation,  conf config.Config){
	for _, op := range operationsToApply{
		switch  op.DbType {
		case 0://couchbase
			fmt.Println("Don't handle couchbase queued ops'")
		case 1://redis
			fmt.Println("Don't handle redis queued ops'")
		case 2://solr
			fmt.Println("Don't handle solr queued ops'")
			_,err := dbsolr.SolrInsertEndpoint(op.Operation)

			if err == nil{//if successful then remove that slice part
				operationsToApply = append(operationsToApply[:0], operationsToApply[1:]...)
			}
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
