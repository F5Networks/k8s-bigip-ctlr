package f5teem

var envList = []string{"production", "staging"}
var envVar = map[string]interface{}{
	"published": envList,
	"env_var":   "TEEM_API_ENVIRONMENT",
}
var prodEnd = map[string]string{
	"endpoint": "product.apis.f5.com",
	"api_key":  "mmhJU2sCd63BznXAXDh4kxLIyfIMm3Ar",
}
var stagEnd = map[string]string{
	"endpoint": "product-tst.apis.f5networks.net",
	"api_key":  "",
}
var k = map[string]interface{}{
	"production": prodEnd,
	"staging":    stagEnd,
}
var endPoints = map[string]interface{}{
	"anonymous": k,
}

const (
	productName    string = "Automation Toolchain"
	productVersion string = "1.0.2"
	userAgent             = "f5-teem/${version}"
)

type TeemObject struct {
	//EndpointInfo interface{}
	ClientInfo           AssetInfo
	ApiKey               string
	TelemetryType        string
	TelemetryTypeVersion string
	ServiceHost          string
}
type clientConfig struct {
	ClientInfo string
	ApiKey     string
}

type AssetInfo struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Id      string `json:"id,omitempty"`
}
