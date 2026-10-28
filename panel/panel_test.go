package panel_test

import (
	"testing"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/features/routing"

	"github.com/XrayR-project/XrayR/app/mydispatcher"
	"github.com/XrayR-project/XrayR/panel"
)

// Exercise core feature registration and startup without an external panel API.
func TestCoreStartup(t *testing.T) {
	p := panel.New(&panel.Config{})
	p.Start()
	t.Cleanup(p.Close)

	if !p.Running {
		t.Fatal("panel did not start")
	}
	if _, ok := p.Server.GetFeature(routing.DispatcherType()).(*dispatcher.DefaultDispatcher); !ok {
		t.Fatal("official dispatcher is missing or has been replaced")
	}
	custom, ok := p.Server.GetFeature(mydispatcher.Type()).(*mydispatcher.DefaultDispatcher)
	if !ok {
		t.Fatal("custom dispatcher is missing")
	}
	if custom.Limiter == nil || custom.RuleManager == nil {
		t.Fatal("custom dispatcher features were not initialized")
	}
}
