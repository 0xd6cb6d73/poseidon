// Package payloadsync adds the payload crypto declaration missing from the
// pinned MythicContainer SDK. Remove this adapter when PayloadType exposes
// supported_crypto_schemes; application messages and handlers remain SDK-owned.
package payloadsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/rabbitmq"
	"github.com/MythicMeta/MythicContainer/utils/sharedStructs"
)

// The wire version of the pinned MythicContainer v1.7.0-rc4 dependency.
const containerVersion = "v1.5.0"

type syncSender func(context.Context, []byte) ([]byte, error)

type payloadDefinition struct {
	agentstructs.PayloadType
	SupportedCryptoSchemes []string `json:"supported_crypto_schemes"`
}

type syncMessage struct {
	PayloadType      payloadDefinition      `json:"payload_type"`
	CommandList      []agentstructs.Command `json:"commands"`
	ContainerVersion string                 `json:"container_version"`
	ForcedResync     bool                   `json:"forced_resync"`
}

func marshalSync(name string, schemes []string, forced bool) ([]byte, error) {
	data := agentstructs.AllPayloadData.Get(name)
	return json.Marshal(syncMessage{
		PayloadType: payloadDefinition{PayloadType: data.GetPayloadDefinition(), SupportedCryptoSchemes: append([]string{}, schemes...)},
		CommandList: data.GetCommands(), ContainerVersion: containerVersion, ForcedResync: forced,
	})
}

func syncDefinition(ctx context.Context, name string, schemes []string, forced bool, send syncSender, retryDelay time.Duration) error {
	for {
		body, err := marshalSync(name, schemes, forced)
		if err == nil {
			var reply []byte
			reply, err = send(ctx, body)
			if err == nil {
				var response agentstructs.PayloadTypeSyncMessageResponse
				if err = json.Unmarshal(reply, &response); err == nil && !response.Success {
					err = errors.New(response.Error)
				}
			}
		}
		if err == nil {
			logging.LogInfo("Successfully synced payload type!", "name", name)
			return nil
		}
		logging.LogError(err, "Failed to sync payload definition; retrying", "name", name)
		timer := time.NewTimer(retryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func listeners(name string, schemes []string, send syncSender, retryDelay time.Duration) ([]sharedStructs.RabbitmqRPCMethod, []sharedStructs.RabbitmqDirectMethod) {
	data := agentstructs.AllPayloadData.Get(name)
	defaults := agentstructs.AllPayloadData.Get("")
	rpc := append([]sharedStructs.RabbitmqRPCMethod{}, data.GetRPCMethods()...)
	rpc = append(rpc, defaults.GetRPCMethods()...)
	for i := range rpc {
		if rpc[i].RabbitmqRoutingKey == rabbitmq.PT_RPC_RESYNC_ROUTING_KEY {
			rpc[i].RabbitmqProcessingFunction = func(ctx context.Context, body []byte) interface{} {
				var input agentstructs.PTRPCReSyncMessage
				if err := json.Unmarshal(body, &input); err != nil || input.Name != name {
					return agentstructs.PTRPCReSyncMessageResponse{Error: "invalid payload resync request"}
				}
				if err := syncDefinition(ctx, name, schemes, true, send, retryDelay); err != nil {
					return agentstructs.PTRPCReSyncMessageResponse{Error: err.Error()}
				}
				return agentstructs.PTRPCReSyncMessageResponse{Success: true}
			}
		}
	}
	direct := append([]sharedStructs.RabbitmqDirectMethod{}, data.GetDirectMethods()...)
	direct = append(direct, defaults.GetDirectMethods()...)
	// The SDK normally appends its build handler during StartServices(payload).
	direct = append(direct, sharedStructs.RabbitmqDirectMethod{
		RabbitmqRoutingKey: rabbitmq.PAYLOAD_BUILD_ROUTING_KEY, RabbitmqProcessingFunction: rabbitmq.WrapPayloadBuild,
	})
	return rpc, direct
}

// StartAndRunForever preserves the SDK's startup sequence and all registered
// handlers, replacing only payload definition serialization and forced resync.
// ReceiveFrom* keeps its normal nonexclusive payload queues and acknowledgments.
func StartAndRunForever(name string, schemes []string) error {
	data := agentstructs.AllPayloadData.Get(name)
	if name == "" || data.GetPayloadName() != name {
		return fmt.Errorf("payload type %q is not initialized", name)
	}
	schemes = append([]string{}, schemes...)
	data.AddContainerVersion(containerVersion)
	send := func(ctx context.Context, body []byte) ([]byte, error) {
		return rabbitmq.RabbitMQConnection.SendRPCMessageWithContext(ctx, rabbitmq.MYTHIC_EXCHANGE, rabbitmq.PT_SYNC_ROUTING_KEY, body, true)
	}
	rpc, direct := listeners(name, schemes, send, rabbitmq.RETRY_CONNECT_DELAY)
	rabbitmq.Initialize()
	// Start any custom SDK listeners before its ordinary payload listeners.
	rabbitmq.StartServices(nil)
	var ready sync.WaitGroup
	for _, method := range rpc {
		route := data.GetRoutingKey(method.RabbitmqRoutingKey)
		ready.Add(1)
		go rabbitmq.RabbitMQConnection.ReceiveFromRPCQueue(rabbitmq.MYTHIC_EXCHANGE, route, route, method.RabbitmqProcessingFunction, false, &ready)
	}
	for _, method := range direct {
		route := data.GetRoutingKey(method.RabbitmqRoutingKey)
		ready.Add(1)
		go rabbitmq.RabbitMQConnection.ReceiveFromMythicDirectExchange(rabbitmq.MYTHIC_EXCHANGE, route, route, method.RabbitmqProcessingFunction, false, &ready)
	}
	ready.Wait()
	if err := syncDefinition(context.Background(), name, schemes, false, send, rabbitmq.RETRY_CONNECT_DELAY); err != nil {
		return err
	}
	select {}
}
