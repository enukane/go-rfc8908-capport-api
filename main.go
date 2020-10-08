package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"
)

const (
	kHTTPHeaderContentType       = "application/captive+json"
	kHTTPHeaderCacheControl      = "no-store"
	kCapportAPIDefaultTimeLimit  = (60 * 60)                // 1H
	kCapportAPIDefaultBytesLimit = (1 * 1000 * 1000 * 1000) // 1G
)

type UserInfo struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}

type Config struct {
	UserDBPath string     `json:"userdb"`
	Users      []UserInfo `json:"users"`

	// API related
	UserPortalURL    string `json:"user-portal-url"`
	VenueInfoURL     string `json:"venue-info-url,omitempty"`
	CanExtendSession bool   `json:"can-extend-session"`

	// User limitation
	DefaultSeconds int64  `json:"default-seconds"`
	DefaultBytes   uint64 `json:"default-bytes"`
}

func loadConfig(confPath string) (Config, error) {
	var conf Config
	file, err := os.Open(confPath)
	if err != nil {
		return conf, fmt.Errorf("failed to open config path=%s", confPath)
	}

	dec := json.NewDecoder(file)
	err = dec.Decode(&conf)

	return conf, nil
}

var _globalConfig Config

type APIState struct {
	Captive          bool   `json:"captive"`
	UserPortalURL    string `json:"user-portal-url,omitempty"`
	VenueInfoURL     string `json:"venue-info-url,omitempty"`
	CanExtendSession bool   `json:"can-extend-session"`
	SecondsRemaining int64  `json:"seconds-remaining"`
	BytesRemaining   uint64 `json:"bytes-remaining"`

	LastAuthenticatedUserName string `json:"last-auth-username,omitempty"`
}

var _commonAPIState APIState

func (apistate *APIState) generateJSON() string {
	bytes, err := json.Marshal(apistate)
	if err != nil {
		return ""
	}
	return string(bytes)
}

type clientQueryInfo struct {
	Addr     string
	UserName string
	Password string
}

type clientAcceptInfo struct {
	Active    bool
	Addr      string
	UserName  string
	StartTime int64
	TimeLimit int64
	ByteLimit uint64
	ByteCount uint64
}

var _allowedList []clientAcceptInfo

func allowClient(cai clientAcceptInfo) error {
	// check if there is no duplicacy
	for _, entry := range _allowedList {
		if entry.UserName == cai.UserName && entry.Addr == cai.Addr {
			// already exists, do nothing or reflesh?
			return nil
		}
	}

	// set client to enforcer

	cai.Active = true
	cai.TimeLimit = kCapportAPIDefaultTimeLimit
	cai.ByteLimit = kCapportAPIDefaultBytesLimit
	_allowedList = append(_allowedList, cai)
	return nil
}

func dropClient(cqi clientAcceptInfo) error {
	matchedIdx := -1
	for idx, entry := range _allowedList {
		if entry.Addr == cqi.Addr {
			matchedIdx = idx
		}
	}

	if matchedIdx == -1 {
		return fmt.Errorf("entry with addr=%s not found", cqi.Addr)

	}

	deleteClient(matchedIdx)

	return nil
}

func deleteClient(elmIdx int) {
	// mutex.lock
	_allowedList = append(_allowedList[:elmIdx], _allowedList[elmIdx+1:]...)
	// mutex.unlock
}

func isClientAllowed(cqi clientQueryInfo) *clientAcceptInfo {
	matchedIdx := -1
	for idx, entry := range _allowedList {
		if entry.Addr == cqi.Addr && entry.Active == true {
			matchedIdx = idx
		}
	}

	if matchedIdx == -1 {
		return nil
	}

	// check limitation
	now := time.Now().Unix()
	if _allowedList[matchedIdx].StartTime+_allowedList[matchedIdx].TimeLimit < now {
		// it's over
		deleteClient(matchedIdx)
		return nil
	}

	if _allowedList[matchedIdx].ByteCount > _allowedList[matchedIdx].ByteLimit {
		deleteClient(matchedIdx)
		return nil
	}

	cai := _allowedList[matchedIdx]

	return &cai
}

func authenticate(cqi clientQueryInfo) error {
	matchedIdx := -1
	for idx, user := range _globalConfig.Users {
		if user.UserName == cqi.UserName && user.Password == cqi.Password {
			matchedIdx = idx
			break
		}
	}

	if matchedIdx < 0 {
		return fmt.Errorf("AUTH: failure on addr=%s, username=%s", cqi.Addr, cqi.UserName)
	}

	cai := clientAcceptInfo{
		Addr:      cqi.Addr,
		UserName:  cqi.UserName,
		StartTime: time.Now().Unix(),
		TimeLimit: 0,
		ByteLimit: 0,
		ByteCount: 0,
	}

	return allowClient(cai)
}

func extractRemoteAddressPort(remoteAddr string) (string, uint16, error) {
	readdr, err := regexp.Compile(`^(.+):(\d+)$`)
	if err != nil {
		return "", 0, fmt.Errorf("regexp failed")
	}
	addrMatched := readdr.FindSubmatch([]byte(remoteAddr))
	if len(addrMatched) != 3 {
		return "", 0, fmt.Errorf("not matching")
	}
	remoteAddress := addrMatched[1]
	remotePort, _ := strconv.Atoi(string(addrMatched[2]))

	return string(remoteAddress), uint16(remotePort), nil
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Data Handler: client=%s, method: %s, url: %s\n", r.RemoteAddr, r.Method, r.URL)
	http.ServeFile(w, r, "./data")
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Auth Handler: client=%s, method=%s, url=%s\n", r.RemoteAddr, r.Method, r.URL)
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "couldn't read", 401)
		return
	}

	re, err := regexp.Compile("^username=(.+)&password=(.+)$")
	if err != nil {
		log.Printf("Error: failed to compile regeex\n")
		http.Error(w, "internal server error", 505)
		return
	}

	matched := re.FindSubmatch(buf)
	if len(matched) != 3 { // including 0 as full text
		log.Printf("Invalid Authentication info: '%s'\n", string(buf))
		http.Error(w, "invalid auth body", 505)
		return
	}
	remoteAddr, _, err := extractRemoteAddressPort(r.RemoteAddr)
	if err != nil {
		log.Printf("failed %v\n", err)
		http.Error(w, "failed to extract address", 505)
		return
	}

	cqi := clientQueryInfo{
		Addr:     remoteAddr,
		UserName: string(matched[1]),
		Password: string(matched[2]),
	}

	err = authenticate(cqi)
	if err != nil {
		log.Printf("Error: failed to authenticate: %s\n", err)
		http.Error(w, "auth failure", 402)
		return
	}

	w.Write([]byte("ok\n"))
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("API handler: client=%s, method: %s, url: %s\n", r.RemoteAddr, r.Method, r.URL)
	remoteAddr, _, err := extractRemoteAddressPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "failed to parse address/port", 505)
	}
	cqi := clientQueryInfo{
		Addr: remoteAddr,
	}
	cai := isClientAllowed(cqi)

	apiState := _commonAPIState
	if cai == nil {
		apiState.Captive = true
		apiState.SecondsRemaining = 0
		apiState.BytesRemaining = 0
	} else if cai.Active == false {
		apiState.Captive = true
		apiState.SecondsRemaining = 0
		apiState.BytesRemaining = 0
	} else {
		apiState.Captive = false
		now := time.Now().Unix()
		apiState.SecondsRemaining = (cai.StartTime + cai.TimeLimit) - now
		apiState.BytesRemaining = (cai.ByteLimit - cai.ByteCount)
		apiState.LastAuthenticatedUserName = cai.UserName
	}

	jsonString := apiState.generateJSON()
	if len(jsonString) == 0 {
		http.Error(w, "Internal JSON dump error", 500)
		return
	}

	w.Header().Add("Content-Type", kHTTPHeaderContentType)
	w.Header().Add("Cache-Control", kHTTPHeaderCacheControl)
	w.Write([]byte(jsonString))
}

func main() {
	var err error
	confPathPtr := flag.String("conf", "./capportapi.json", "config file path")
	flag.Parse()

	_globalConfig, err = loadConfig(*confPathPtr)
	if err != nil {
		log.Printf("ERROR: failed to load config (path=%s)", *confPathPtr)
		os.Exit(1)
	}

	_allowedList = make([]clientAcceptInfo, 10, 100)

	_commonAPIState.UserPortalURL = _globalConfig.UserPortalURL
	_commonAPIState.VenueInfoURL = _globalConfig.VenueInfoURL
	_commonAPIState.CanExtendSession = _globalConfig.CanExtendSession
	_commonAPIState.SecondsRemaining = _globalConfig.DefaultSeconds
	_commonAPIState.BytesRemaining = _globalConfig.DefaultBytes

	http.HandleFunc("/data/", dataHandler)
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/api", apiHandler)
	http.HandleFunc("/", dataHandler)

	http.ListenAndServe(":8088", nil)
}
