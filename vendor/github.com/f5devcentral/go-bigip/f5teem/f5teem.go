/**
 * Copyright 2020 F5 Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package f5teem

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"fmt"
	uuid "github.com/google/uuid"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

func AnonymousClient(assetInfo AssetInfo, apiKey string) *TeemObject {
	envTeem, teemServer := getEndpointInfo()
	if envTeem != "staging" {
		apiKey = teemServer.(map[string]string)["api_key"]
	}
	serviceHost := teemServer.(map[string]string)["endpoint"]
	//log.Printf("[INFO]TeemServer:%+v\n", serviceHost)
	teemClient := TeemObject{
		assetInfo,
		apiKey,
		"",
		"",
		serviceHost,
	}
	//log.Printf("teemClient:%v\n", teemClient)
	return &teemClient
}

func getEndpointInfo() (string, interface{}) {
	environment := envVar["published"].([]string)[0]
	if len(os.Getenv(envVar["env_var"].(string))) > 0 {
		environment = os.Getenv(envVar["env_var"].(string))
	}
	return environment, endPoints["anonymous"].(map[string]interface{})[environment]
}

func inDocker() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	return false
}

func genUUID() string {
	id := uuid.New()
	return id.String()
}

var osHostname = os.Hostname

func uniqueUUID() string {
	hostname, err := osHostname()
	hash := md5.New()
	if err != nil {
		return genUUID()
	}
	_, _ = io.WriteString(hash, hostname)
	seed := hash.Sum(nil)
	uid, err := uuid.FromBytes(seed[0:16])
	if err != nil {
		return genUUID()
	}
	result := uid.String()
	return result
}

func (b *TeemObject) Report(telemetry map[string]interface{}, telemetryType, telemetryTypeVersion string) error {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}
	url := fmt.Sprintf("https://%s/ee/v1/telemetry", b.ServiceHost)

	uniqueID := uniqueUUID()
	//log.Printf("[DEBUG] digitalAssetId:%+v", uniqueID)
	telemetry["RunningInDocker"] = inDocker()
	b.TelemetryType = telemetryType
	b.TelemetryTypeVersion = telemetryTypeVersion
	//telemetryData, _ := json.Marshal(telemetry)
	//telemetryDatalist := []string{string(telemetryData[:])}
	//log.Printf("[DEBUG] telemetryDatalist:%+v", telemetryDatalist)
	//
	//log.Printf("[DEBUG] ControllerAsDocker:#{docker}")

	telemetrynew := []map[string]interface{}{}
	telemetrynew = append(telemetrynew, telemetry)

	bodyData := map[string]interface{}{
		"documentType":         b.TelemetryType,
		"documentVersion":      b.TelemetryTypeVersion,
		"digitalAssetId":       uniqueID,
		"digitalAssetName":     b.ClientInfo.Name,
		"digitalAssetVersion":  b.ClientInfo.Version,
		"observationStartTime": time.Now().UTC().Format(time.RFC3339Nano),
		"observationEndTime":   time.Now().UTC().Format(time.RFC3339Nano),
		"epochTime":            time.Now().Unix(),
		"telemetryRecords":     telemetrynew,
	}
	bodyInfo, _ := json.Marshal(bodyData)
	body := bytes.NewReader([]byte(bodyInfo))
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		fmt.Printf("Error found:%v", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("F5-ApiKey", b.ApiKey)
	req.Header.Set("F5-DigitalAssetId", uniqueID)
	req.Header.Set("F5-TraceId", genUUID())

	//fmt.Printf("Req is :%+v\n", req)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("telemetry request to teem server failed with :%v", err)
	}
	//log.Printf("Resp Code:%+v \t Status:%+v\n", resp.StatusCode, resp.Status)
	defer resp.Body.Close()
	data, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 204 {
		return fmt.Errorf("telemetry request to teem server failed with:%v", string(data[:]))
	}
	//log.Printf("Resp Body:%v", string(data[:]))
	return nil
}
