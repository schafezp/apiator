package config

const (
	couchbaseServerAddr = "localhost:8091"
	solrServerAddr = "127.0.0.1:8983"
	redisServerAddr     = "localhost:6379"
	redisServerPassword = ""
	solrServerHost = "localhost"
	solrServerPort = 8983
	solrCoreName = "gettingstarted"
)

type Config struct {
	CouchbaseServerAddr string
	RedisServerAddr     string
	RedisServerPassword string
	SolrServerHost string
	SolrServerPort int
	SolrCoreName string
}


func GetConfig()(Config){
	return Config{
		CouchbaseServerAddr:couchbaseServerAddr,
		SolrServerHost:solrServerHost,
		SolrServerPort:solrServerPort,
		SolrCoreName:  solrCoreName,
		RedisServerAddr:redisServerAddr,
		RedisServerPassword:redisServerPassword,
		}
}

