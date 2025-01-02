package platoboost

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type BoostStruct struct {
	client     *http.Client
	callback   func(string)
	hostname   string
	identifier string
	cachedLink string
	cachedTime time.Time
	service    int
	secret     string
	useNonce   bool
}

func Boost(service int, secret string, useNonce bool, callback func(string)) *BoostStruct {
	b := &BoostStruct{
		client:   &http.Client{},
		callback: callback,
		hostname: "https://api.platoboost.com",
		service:  service,
		secret:   secret,
		useNonce: useNonce,
	}

	if !b.checkConnectivity() {
		b.hostname = "https://api.platoboost.net"
	}

	b.identifier = b.getHWID()
	b.cacheLink()
	return b
}

func (b *BoostStruct) checkConnectivity() bool {
	resp, err := b.client.Get(b.hostname + "/public/connectivity")
	if err != nil || resp.StatusCode != 200 {
		return false
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			// ignore
		}
	}(resp.Body)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return false
	}

	return result["success"] == true
}

func (b *BoostStruct) getHWID() string {
	var uuid string
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("wmic", "csproduct", "get", "uuid")
		out, _ := cmd.Output()
		uuid = strings.TrimSpace(strings.Split(string(out), "\n")[1])
	case "linux":
		out, _ := os.ReadFile("/etc/machine-id")
		uuid = strings.TrimSpace(string(out))
	case "darwin":
		cmd := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
		out, _ := cmd.Output()
		uuid = strings.TrimSpace(strings.Split(string(out), "IOPlatformSerialNumber")[1])
	default:
		panic("unsupported OS")
	}
	hash := sha256.Sum256([]byte(uuid))
	return hex.EncodeToString(hash[:])
}

func (b *BoostStruct) generateNonce() string {
	if b.useNonce {
		hash := md5.Sum([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
		return hex.EncodeToString(hash[:])
	}
	return "empty"
}

func (b *BoostStruct) cacheLink() string {
	if b.cachedLink != "" && time.Since(b.cachedTime).Minutes() < 5 {
		return b.cachedLink
	}

	data := map[string]interface{}{
		"service":    b.service,
		"identifier": b.identifier,
	}
	body, _ := json.Marshal(data)
	resp, err := b.client.Post(b.hostname+"/public/start", "application/json", bytes.NewBuffer(body))
	if err != nil || resp.StatusCode != 200 {
		b.invokeCallback("Failed to cache link.")
		return ""
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			// ignore
		}
	}(resp.Body)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		b.invokeCallback("Failed to cache link. (invalid response)")
		return ""
	}

	if success, ok := result["success"].(bool); ok && success {
		b.cachedLink = result["data"].(map[string]interface{})["url"].(string)
		b.cachedTime = time.Now()
		return b.cachedLink
	}
	b.invokeCallback("Failed to cache link.")
	return ""
}

func (b *BoostStruct) verifyHash(data, nonce, secret, expectedHash string) bool {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%s", data, nonce, secret)))
	return hex.EncodeToString(hash[:]) == expectedHash
}

func (b *BoostStruct) invokeCallback(message string) {
	if b.callback != nil {
		b.callback(message)
	}
}

func (b *BoostStruct) GetLink() string {
	return b.cacheLink()
}

func (b *BoostStruct) Redeem(key string) bool {
	nonce := b.generateNonce()
	url := fmt.Sprintf("%s/public/redeem/%d", b.hostname, b.service)

	body := map[string]interface{}{
		"identifier": b.identifier,
		"key":        key,
	}

	if b.useNonce {
		body["nonce"] = nonce
	}

	jsonBody, _ := json.Marshal(body)
	resp, err := b.client.Post(url, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil || resp.StatusCode != 200 {
		b.invokeCallback("Failed to redeem key.")
		return false
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			// ignore
		}
	}(resp.Body)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		b.invokeCallback("Failed to redeem key. (invalid response)")
		return false
	}

	if success, ok := result["success"].(bool); ok && success {
		if valid, ok := result["data"].(map[string]interface{})["valid"].(bool); ok && valid {
			if b.useNonce {
				serverHash := result["data"].(map[string]interface{})["hash"].(string)
				if b.verifyHash(fmt.Sprintf("%t", valid), nonce, b.secret, serverHash) {
					return true
				} else {
					b.invokeCallback("Failed to verify integrity.")
					return false
				}
			}
			return true
		} else {
			b.invokeCallback("Key is invalid.")
			return false
		}
	}
	b.invokeCallback(result["message"].(string))
	return false
}

func (b *BoostStruct) Verify(key string) bool {
	nonce := b.generateNonce()
	url := fmt.Sprintf("%s/public/whitelist/%d?identifier=%s&key=%s", b.hostname, b.service, b.identifier, key)
	if b.useNonce {
		url += "&nonce=" + nonce
	}

	resp, err := b.client.Get(url)
	if err != nil || resp.StatusCode != 200 {
		b.invokeCallback("Server returned an invalid status code.")
		return false
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			// ignore
		}
	}(resp.Body)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		b.invokeCallback("Failed to verify key. (invalid response)")
		return false
	}
	if success, ok := result["success"].(bool); ok && success {
		if valid, ok := result["data"].(map[string]interface{})["valid"].(bool); ok && valid {
			if b.useNonce {
				serverHash := result["data"].(map[string]interface{})["hash"].(string)
				if b.verifyHash(fmt.Sprintf("%t", valid), nonce, b.secret, serverHash) {
					return true
				} else {
					b.invokeCallback("Failed to verify integrity.")
					return false
				}
			}
			return true
		} else if strings.HasPrefix(key, "KEY_") {
			return b.Redeem(key)
		} else {
			b.invokeCallback("Key is invalid.")
			return false
		}
	}
	b.invokeCallback(result["message"].(string))
	return false
}

func (b *BoostStruct) GetFlag(name string) interface{} {
	nonce := b.generateNonce()
	url := fmt.Sprintf("%s/public/flag/%d?name=%s", b.hostname, b.service, name)

	if b.useNonce {
		url += "&nonce=" + nonce
	}

	resp, err := b.client.Get(url)
	if err != nil || resp.StatusCode != 200 {
		b.invokeCallback(fmt.Sprintf("Failed to fetch flag '%s': %v", name, err))
		return nil
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			b.invokeCallback("Failed to close response body.")
		}
	}(resp.Body)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		b.invokeCallback("Invalid response while fetching flag.")
		return nil
	}

	if success, ok := result["success"].(bool); ok && success {
		data := result["data"].(map[string]interface{})
		value := data["value"]
		strValue := fmt.Sprintf("%v", value)

		if b.useNonce {
			serverHash := data["hash"].(string)
			if b.verifyHash(strValue, nonce, b.secret, serverHash) {
				return value
			}
			b.invokeCallback("Integrity check failed for flag.")
			return nil
		}

		return value
	}

	if message, ok := result["message"].(string); ok {
		b.invokeCallback(fmt.Sprintf("Failed to fetch flag '%s': %s", name, message))
	} else {
		b.invokeCallback("Unknown error while fetching flag.")
	}
	return nil
}
