package payloadsync

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	poseidonfunctions "MyContainer/poseidon/agentfunctions"
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/rabbitmq"
	"github.com/MythicMeta/MythicContainer/utils/sharedStructs"
)

func TestMain(m *testing.M) {
	poseidonfunctions.Initialize()
	os.Exit(m.Run())
}

func TestSyncPreservesSDKDefinitionAndCommands(t *testing.T) {
	for _, forced := range []bool{false, true} {
		body, err := marshalSync("poseidon", poseidonfunctions.SupportedCryptoSchemes(), forced)
		if err != nil {
			t.Fatal(err)
		}
		var message map[string]json.RawMessage
		if err := json.Unmarshal(body, &message); err != nil {
			t.Fatal(err)
		}
		var definition map[string]json.RawMessage
		if err := json.Unmarshal(message["payload_type"], &definition); err != nil {
			t.Fatal(err)
		}
		var schemes []string
		if err := json.Unmarshal(definition["supported_crypto_schemes"], &schemes); err != nil || !reflect.DeepEqual(schemes, []string{"Native", "WASM"}) {
			t.Fatalf("crypto declaration = %v, %v", schemes, err)
		}
		delete(definition, "supported_crypto_schemes")
		sdkDefinition, err := json.Marshal(agentstructs.AllPayloadData.Get("poseidon").GetPayloadDefinition())
		if err != nil {
			t.Fatal(err)
		}
		var expected map[string]json.RawMessage
		if err := json.Unmarshal(sdkDefinition, &expected); err != nil || !reflect.DeepEqual(definition, expected) {
			t.Fatal("extended sync changed the SDK payload definition")
		}
		var decoded struct {
			ContainerVersion string            `json:"container_version"`
			ForcedResync     bool              `json:"forced_resync"`
			CommandList      []json.RawMessage `json:"commands"`
		}
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.ContainerVersion != "v1.5.0" || decoded.ForcedResync != forced {
			t.Fatalf("sync lost SDK version or forced-resync flag: %s", body)
		}
		commands, err := json.Marshal(agentstructs.AllPayloadData.Get("poseidon").GetCommands())
		if err != nil || string(message["commands"]) != string(commands) || len(decoded.CommandList) == 0 {
			t.Fatal("extended sync changed or omitted SDK commands")
		}
	}
}

func TestListenersPreserveSDKHandlersAndResyncDeclaration(t *testing.T) {
	var sent []byte
	sender := func(_ context.Context, body []byte) ([]byte, error) {
		sent = append([]byte{}, body...)
		return []byte(`{"success":true}`), nil
	}
	rpc, direct := listeners("poseidon", poseidonfunctions.SupportedCryptoSchemes(), sender, 0)
	data := agentstructs.AllPayloadData.Get("poseidon")
	defaults := agentstructs.AllPayloadData.Get("")
	expectedRPC := append([]sharedStructs.RabbitmqRPCMethod{}, data.GetRPCMethods()...)
	expectedRPC = append(expectedRPC, defaults.GetRPCMethods()...)
	if len(rpc) != len(expectedRPC) {
		t.Fatal("payload RPC handler was omitted")
	}
	resyncCount := 0
	for i, original := range expectedRPC {
		actual := rpc[i]
		if actual.RabbitmqRoutingKey != original.RabbitmqRoutingKey {
			t.Fatal("payload RPC route order changed")
		}
		if original.RabbitmqRoutingKey != rabbitmq.PT_RPC_RESYNC_ROUTING_KEY {
			if reflect.ValueOf(actual.RabbitmqProcessingFunction).Pointer() != reflect.ValueOf(original.RabbitmqProcessingFunction).Pointer() {
				t.Fatalf("SDK handler was replaced for %s", actual.RabbitmqRoutingKey)
			}
			continue
		}
		resyncCount++
		response := actual.RabbitmqProcessingFunction(context.Background(), []byte(`{"payload_type":"poseidon"}`)).(agentstructs.PTRPCReSyncMessageResponse)
		if !response.Success {
			t.Fatalf("resync failed: %+v", response)
		}
		expected, err := marshalSync("poseidon", poseidonfunctions.SupportedCryptoSchemes(), true)
		if err != nil || string(sent) != string(expected) {
			t.Fatal("forced resync omitted the full declaration")
		}
		sent = nil
		for _, invalid := range []string{`{`, `{"payload_type":"another"}`} {
			response := actual.RabbitmqProcessingFunction(context.Background(), []byte(invalid)).(agentstructs.PTRPCReSyncMessageResponse)
			if response.Success || len(sent) != 0 {
				t.Fatal("invalid resync reached the sync sender")
			}
		}
	}
	if resyncCount != 1 {
		t.Fatalf("expected one resync listener, got %d", resyncCount)
	}
	expectedDirect := append([]sharedStructs.RabbitmqDirectMethod{}, data.GetDirectMethods()...)
	expectedDirect = append(expectedDirect, defaults.GetDirectMethods()...)
	expectedDirect = append(expectedDirect, sharedStructs.RabbitmqDirectMethod{RabbitmqRoutingKey: rabbitmq.PAYLOAD_BUILD_ROUTING_KEY, RabbitmqProcessingFunction: rabbitmq.WrapPayloadBuild})
	if len(direct) != len(expectedDirect) {
		t.Fatal("payload direct handler was omitted")
	}
	onStart := false
	for i, original := range expectedDirect {
		actual := direct[i]
		if actual.RabbitmqRoutingKey != original.RabbitmqRoutingKey || reflect.ValueOf(actual.RabbitmqProcessingFunction).Pointer() != reflect.ValueOf(original.RabbitmqProcessingFunction).Pointer() {
			t.Fatalf("SDK direct handler changed for %s", original.RabbitmqRoutingKey)
		}
		onStart = onStart || actual.RabbitmqRoutingKey == rabbitmq.CONTAINER_ON_START
	}
	if !onStart {
		t.Fatal("SDK container-on-start authorization handler missing")
	}
}

func TestSyncRetriesTransportMalformedAndRejectedReplies(t *testing.T) {
	calls := 0
	sender := func(_ context.Context, body []byte) ([]byte, error) {
		calls++
		expected, err := marshalSync("poseidon", poseidonfunctions.SupportedCryptoSchemes(), false)
		if err != nil || string(body) != string(expected) {
			t.Fatal("retry changed the full registration")
		}
		switch calls {
		case 1:
			return nil, errors.New("temporary transport error")
		case 2:
			return []byte("invalid JSON"), nil
		case 3:
			return []byte(`{"success":false,"error":"not ready"}`), nil
		default:
			return []byte(`{"success":true}`), nil
		}
	}
	if err := syncDefinition(context.Background(), "poseidon", poseidonfunctions.SupportedCryptoSchemes(), false, sender, 0); err != nil || calls != 4 {
		t.Fatalf("sync retry result: calls=%d err=%v", calls, err)
	}
}
