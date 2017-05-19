package dbsolr


import ("github.com/rtt/Go-Solr"
	"fmt"
	"strings"
	
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

//insert data at a given endpoint
func SolrInsertEndpoint(datacrud structs.DataCRUD)(bool,error){
	var resp *solr.UpdateResponse
	var err error;
	s, err := solr.Init(conf.SolrServerHost, conf.SolrServerPort, conf.SolrCoreName)

	if err != nil{return false,err}

	endpointBucketName := strings.Replace(datacrud.ID, "/", "-", -1)
	endpointBucketName = datacrud.DomainID + endpointBucketName
	
	fmt.Println("EndpointBucketName:")
	fmt.Println(endpointBucketName)
	//TODO: put apporopriate fields
	// https://github.com/rtt/Go-Solr
	f := map[string]interface{}{
		"add": []interface{}{
			map[string]interface{}{"ID": datacrud.ID, "DomainID": datacrud.DomainID,"Doc": datacrud.DomainID, "endpointBucketName": endpointBucketName},
		},
	}
		
	resp, err = s.Update(f, true)

	if err != nil {
		return false,err
	}
	return resp.Success,err
	
}

func SolrSearchEndpoint(id, domainId string)(interface{},error){
	s, err := solr.Init(conf.SolrServerHost, conf.SolrServerPort, conf.SolrCoreName)

	if err != nil{return nil,err}

	endpointBucketName := strings.Replace(id, "/", "-", -1)
	endpointBucketName = domainId + endpointBucketName
	
	qstring := fmt.Sprintf("endpointBucketName:*%s*",endpointBucketName)
	
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
		fmt.Println("ID:", results.Get(i).Field("ID"))
		fmt.Println("Doc:", results.Get(i).Field("Doc"))

		fmt.Println("")
	}
	return results,nil
}
