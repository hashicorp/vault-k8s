package leader

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
)

const defaultURL = "http://localhost:4040/"

type LeaderElector struct {
	URL string
}

type LeaderResponse struct {
	Name string `json:"name"`
}

// New returns a LeaderElector with the default service endpoint
func New() *LeaderElector {
	return &LeaderElector{
		URL: defaultURL,
	}
}

// NewWithURL returns a LeaderElector with a custom service endpoint URL
func NewWithURL(URL string) *LeaderElector {
	return &LeaderElector{
		URL: URL,
	}
}

// IsLeader returns whether this host is the leader
func (le *LeaderElector) IsLeader() (bool, error) {
	resp, err := http.Get(le.URL)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	leaderResp := &LeaderResponse{}
	err = json.Unmarshal(body, leaderResp)
	if err != nil {
		return false, err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return false, err
	}
	if leaderResp.Name == hostname {
		return true, nil
	}

	return false, nil
}
