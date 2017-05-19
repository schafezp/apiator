package stats

import (
	"gopkg.in/couchbase/gocb.v1"
	"time"
)

import "../structs"
import "../config"

var (
	conf       = config.GetConfig()
	cluster, _ = gocb.Connect(conf.CouchbaseServerAddr)
)

func AddMissCount(domain, endpoint string) error {
	var json structs.EndpointDoc
	bucket, err := cluster.OpenBucket("endpoints", "")
	if err != nil {
		return err
	}
	bucketID := domain + endpoint
	_, err = bucket.Get(bucketID, &json)
	if err != nil {
		return err
	}
	json.Statistics.MissCount++
	json.Statistics.HitRate = float32(json.Statistics.HitCount) / float32(json.Statistics.HitCount+json.Statistics.MissCount)
	_, err = bucket.Replace(bucketID, &json, 0, 0)
	return err
}

func AddHitCount(domain, endpoint string) error {
	var json structs.EndpointDoc
	bucket, err := cluster.OpenBucket("endpoints", "")
	if err != nil {
		return err
	}
	bucketID := domain + endpoint
	_, err = bucket.Get(bucketID, &json)
	if err != nil {
		return err
	}
	json.Statistics.HitCount++
	json.Statistics.HitRate = float32(json.Statistics.HitCount) / float32(json.Statistics.HitCount+json.Statistics.MissCount)
	_, err = bucket.Replace(bucketID, &json, 0, 0)
	return err
}

func AddUserStatistic(username string, domain string, endpointArg string, permissions int) error {
	var json structs.EndpointDoc
	bucket, err := cluster.OpenBucket("endpoints", "")
	if err != nil {
		return err
	}
	bucketID := domain + endpointArg
	_, err = bucket.Get(bucketID, &json)
	if err != nil {
		return err
	}
	exists := false
	if permissions&1 > 0 {
		readList := json.Statistics.Permissions.Read
		for _, readName := range readList {
			if readName == username {
				exists = true
				break
			}
		}
		if exists == false {
			json.Statistics.Permissions.Read = append(readList, username)
		}
	}
	exists = false
	if permissions&2 > 0 {
		writeList := json.Statistics.Permissions.Write
		for _, writeName := range writeList {
			if writeName == username {
				exists = true
				break
			}
		}
		if exists == false {
			json.Statistics.Permissions.Write = append(writeList, username)
		}
	}
	exists = false
	if permissions&4 > 0 {
		deleteList := json.Statistics.Permissions.Delete
		for _, deleteName := range deleteList {
			if deleteName == username {
				exists = true
				break
			}
		}
		if exists == false {
			json.Statistics.Permissions.Delete = append(deleteList, username)
		}
	}
	_, err = bucket.Replace(bucketID, &json, 0, 0)
	if err != nil {
		return err
	}
	return nil
}

func DeleteUserStatistic(username string, domain string, endpointArg string) error {
	var json structs.EndpointDoc
	bucket, err := cluster.OpenBucket("endpoints", "")
	if err != nil {
		return err
	}
	bucketID := domain + endpointArg
	_, err = bucket.Get(bucketID, &json)
	if err != nil {
		return err
	}

	readList := json.Statistics.Permissions.Read
	for readIndex, readName := range readList {
		if readName == username {
			json.Statistics.Permissions.Read = append(readList[:readIndex], readList[readIndex+1:]...)
			break
		}
	}

	writeList := json.Statistics.Permissions.Write
	for writeIndex, writeName := range writeList {
		if writeName == username {
			json.Statistics.Permissions.Write = append(writeList[:writeIndex], writeList[writeIndex+1:]...)
			break
		}
	}

	deleteList := json.Statistics.Permissions.Delete
	for deleteIndex, deleteName := range deleteList {
		if deleteName == username {
			json.Statistics.Permissions.Delete = append(deleteList[:deleteIndex], deleteList[deleteIndex+1:]...)
			break
		}
	}

	_, err = bucket.Replace(bucketID, &json, 0, 0)
	if err != nil {
		return err
	}
	return nil
}

func UpdateTimeStatistic(domain, endpointArg string) error {
	var json structs.EndpointDoc
	bucket, err := cluster.OpenBucket("endpoints", "")
	if err != nil {
		return err
	}
	bucketID := domain + endpointArg
	_, err = bucket.Get(bucketID, &json)
	if err != nil {
		return err
	}
	json.Statistics.LastCommandReceived = time.Now().Format(time.RFC3339)
	_, err = bucket.Replace(bucketID, &json, 0, 0)
	return err
}
