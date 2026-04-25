package mobile

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const controlPlaneAddr = "http://127.0.0.1:58175/api/v1"

var httpClient = &http.Client{Timeout: 5 * time.Second}

// GetStatus returns JSON of the node status.
// Queries the ControlPlane API running inside the extension process.
func (n *NylonMobile) GetStatus() string {
	return fetchAPI("/status")
}

// GetNodes returns JSON of all known mesh nodes.
func (n *NylonMobile) GetNodes() string {
	return fetchAPI("/nodes")
}

// GetNeighbours returns JSON of neighbours with endpoint metrics.
func (n *NylonMobile) GetNeighbours() string {
	return fetchAPI("/neighbours")
}

// GetRoutes returns JSON of the routing table.
func (n *NylonMobile) GetRoutes() string {
	return fetchAPI("/routes")
}

// GetTopology returns JSON of the full mesh topology (nodes + edges).
func (n *NylonMobile) GetTopology() string {
	return fetchAPI("/topology")
}

// fetchAPI queries the ControlPlane REST API and returns the raw JSON response.
func fetchAPI(path string) string {
	resp, err := httpClient.Get(controlPlaneAddr + path)
	if err != nil {
		data, _ := json.Marshal(map[string]string{"error": err.Error()})
		return string(data)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		data, _ := json.Marshal(map[string]string{"error": fmt.Sprintf("read error: %v", err)})
		return string(data)
	}
	return string(body)
}
