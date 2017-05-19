package config

const (
	couchbaseServerAddr = "http://apiator-2.csse.rose-hulman.edu:8091"
	redisServerAddr     = "apiator-3.csse.rose-hulman.edu:6379"
	redisServerPassword = "AK1lTOuHyUNT5sN4JHP7"
	solrServerHost = "apiator-2.csse.rose-hulman.edu"
	solrServerPort = 8983
	solrCoreName = "gettingstarted"
)

const (
	localCouchbaseServerAddr = "localhost:8091"
	localSolrServerAddr = "127.0.0.1:8983"
	localRedisServerAddr     = "localhost:6379"
	localRedisServerPassword = ""
	localSolrServerHost = "localhost"
	localSolrServerPort = 8983
	localSolrCoreName = "gettingstarted"
)

const (
	isProduction = true
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
	if (isProduction){
		return Config{
			CouchbaseServerAddr:couchbaseServerAddr,
			SolrServerHost:solrServerHost,
			SolrServerPort:solrServerPort,
			SolrCoreName:  solrCoreName,
			RedisServerAddr:redisServerAddr,
			RedisServerPassword:redisServerPassword,
		}
	}else{ return Config{
		CouchbaseServerAddr:localCouchbaseServerAddr,
		SolrServerHost:localSolrServerHost,
		SolrServerPort:localSolrServerPort,
		SolrCoreName:  localSolrCoreName,
		RedisServerAddr:localRedisServerAddr,
		RedisServerPassword:localRedisServerPassword,}
	}
	
}

