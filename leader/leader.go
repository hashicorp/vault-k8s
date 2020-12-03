package leader

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
)

type leaderResponse struct {
	Name string `json:"name"`
}

// IsLeader returns whether this host is the leader
func IsLeader() (bool, error) {
	resp, err := http.Get("http://localhost:4040/")
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	leaderResp := &leaderResponse{}
	err = json.Unmarshal(body, leaderResp)
	if err != nil {
		return false, err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return false, err
	}
	if leaderResp.Name == hostname {
		// log.Printf("[DEBUG] I'm the leader! %s", hostname)
		return true, nil
	}
	// log.Printf("[DEBUG] I'm not the leader: %s, %s", leaderResp.Name, hostname)
	return false, nil
}
