package ws

import (
	"encoding/json"
	"sync"

	"github.com/gofiber/contrib/websocket"
)

// ScanProgress represents real-time scan progress data sent to clients
type ScanProgress struct {
	JobID      uint    `json:"job_id"`
	Status     string  `json:"status"` // running, completed, failed
	Total      int     `json:"total"`
	Completed  int     `json:"completed"`
	Percent    float64 `json:"percent"`
	CurrentURL string  `json:"current_url"`
	Message    string  `json:"message"`
}

// Hub manages WebSocket client connections and broadcasts
type Hub struct {
	clients map[*websocket.Conn]bool
	mu      sync.RWMutex
}

// DefaultHub is the global WebSocket hub instance
var DefaultHub = &Hub{
	clients: make(map[*websocket.Conn]bool),
}

// Register adds a new WebSocket client to the hub
func (h *Hub) Register(c *websocket.Conn) {
	h.mu.Lock()
	h.clients[c] = true
	h.mu.Unlock()
}

// Unregister removes a WebSocket client from the hub
func (h *Hub) Unregister(c *websocket.Conn) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}

// Broadcast sends a ScanProgress message to all connected clients
func (h *Hub) Broadcast(progress ScanProgress) {
	data, err := json.Marshal(progress)
	if err != nil {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for client := range h.clients {
		client.WriteMessage(websocket.TextMessage, data)
	}
}

// HandleWebSocket handles incoming WebSocket connections
func HandleWebSocket(c *websocket.Conn) {
	DefaultHub.Register(c)
	defer DefaultHub.Unregister(c)
	defer c.Close()

	for {
		_, _, err := c.ReadMessage()
		if err != nil {
			break
		}
	}
}
