package dbsolr


import ("github.com/rtt/Go-Solr"
	"fmt"
	
)
//this file is named export.go by convention
import (
	"../config"
	//TODO: don't import apiator-server for EndpointDoc: instead make separate package
	"../structs"

)

var (
	conf = config.GetConfig()

)

func SolrRetrieveAllUsers()(interface{},error){
	s, err := solr.Init(conf.SolrServerHost, conf.SolrServerPort,conf.SolrCoreName)

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
func SolrRetrieveUsers(username string)(interface{},error){
	s, err := solr.Init(conf.SolrServerHost, conf.SolrServerPort, conf.SolrCoreName)

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
func SolrInsertUser(user *structs.Login)(bool,error){
	var resp *solr.UpdateResponse
	var err error;
	s, err := solr.Init(conf.SolrServerHost, conf.SolrServerPort, conf.SolrCoreName)

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
func SolrInsertEndpoint(endpoint *structs.EndpointDoc)(bool,error){
	var resp *solr.UpdateResponse
	var err error;
	s, err := solr.Init(conf.SolrServerHost, conf.SolrServerPort, conf.SolrCoreName)

	if err != nil{return false,err}

	fmt.Println("User to insert:")
	fmt.Println(endpoint)
	//TODO: put apporopriate fields
	// https://github.com/rtt/Go-Solr
	f := map[string]interface{}{
		"add": []interface{}{
			map[string]interface{}{"owner": endpoint.Owner, "index": endpoint.Index,"indexed": endpoint.Indexed},
		},
	}
		
	resp, err = s.Update(f, true)

	if err != nil {
		return false,err
	}
	return resp.Success,err
	
}
