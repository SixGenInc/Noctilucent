package server

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cbeuw/Cloak/internal/common"
	"github.com/cbeuw/Cloak/internal/server/usermanager"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"time"
)

type RawConfig struct {
	ProxyBook     map[string][]string
	BindAddr      []string
	BypassUID     [][]byte
	RedirAddr     string
	PrivateKey    []byte
	AdminUID      []byte
	DatabasePath  string
	StreamTimeout int
	KeepAlive     int
	CncMode       bool
}

// State type stores the global state of the program
type State struct {
	ProxyBook   map[string]net.Addr
	ProxyDialer common.Dialer

	WorldState common.WorldState
	AdminUID   []byte
	Timeout    time.Duration
	//KeepAlive time.Duration

	BypassUID map[[16]byte]struct{}
	StaticPv  crypto.PrivateKey

	// TODO: this doesn't have to be a net.Addr; resolution is done in Dial automatically
	RedirHost   net.Addr
	RedirPort   string
	RedirDialer common.Dialer

	usedRandomM sync.RWMutex
	UsedRandom  map[[32]byte]int64

	Panel *userPanel
}

func parseRedirAddr(redirAddr string) (net.Addr, string, error) {
	var host string
	var port string
	colonSep := strings.Split(redirAddr, ":")
	if len(colonSep) > 1 {
		if len(colonSep) == 2 {
			// domain or ipv4 with port
			host = colonSep[0]
			port = colonSep[1]
		} else {
			if strings.Contains(redirAddr, "[") {
				// ipv6 with port
				port = colonSep[len(colonSep)-1]
				host = strings.TrimSuffix(redirAddr, "]:"+port)
				host = strings.TrimPrefix(host, "[")
			} else {
				// ipv6 without port
				host = redirAddr
			}
		}
	} else {
		// domain or ipv4 without port
		host = redirAddr
	}

	redirHost, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, "", fmt.Errorf("unable to resolve RedirAddr: %v. ", err)
	}
	return redirHost, port, nil
}

func parseProxyBook(bookEntries map[string][]string) (map[string]net.Addr, error) {
	proxyBook := map[string]net.Addr{}
	for name, pair := range bookEntries {
		name = strings.ToLower(name)
		if len(pair) != 2 {
			return nil, fmt.Errorf("invalid proxy endpoint and address pair for %v: %v", name, pair)
		}
		network := strings.ToLower(pair[0])
		switch network {
		case "tcp":
			addr, err := net.ResolveTCPAddr("tcp", pair[1])
			if err != nil {
				return nil, err
			}
			proxyBook[name] = addr
			continue
		case "udp":
			addr, err := net.ResolveUDPAddr("udp", pair[1])
			if err != nil {
				return nil, err
			}
			proxyBook[name] = addr
			continue
		}
	}
	return proxyBook, nil
}

func ParseConfig(conf string) (raw RawConfig, err error) {
	content, errPath := ioutil.ReadFile(conf)
	if errPath != nil {
		errJson := json.Unmarshal(content, &raw)
		if errJson != nil {
			err = fmt.Errorf("failed to read/unmarshal configuration, path is invalid or %v", errJson)
			return
		}
	} else {
		errJson := json.Unmarshal(content, &raw)
		if errJson != nil {
			err = fmt.Errorf("failed to read configuration file: %v", errJson)
			return
		}
	}
	if raw.ProxyBook == nil {
		raw.ProxyBook = make(map[string][]string)
	}
	return
}

// ParseConfig parses the config (either a path to json or the json itself as argument) into a State variable
func InitState(preParse RawConfig, worldState common.WorldState) (sta *State, err error) {
	sta = &State{
		BypassUID:   make(map[[16]byte]struct{}),
		ProxyBook:   map[string]net.Addr{},
		UsedRandom:  map[[32]byte]int64{},
		RedirDialer: &net.Dialer{},
		WorldState:  worldState,
	}
	if preParse.CncMode {
		err = errors.New("command & control mode not implemented")
		return
	} else {
		manager, err := usermanager.MakeLocalManager(preParse.DatabasePath, worldState)
		if err != nil {
			return sta, err
		}
		sta.Panel = MakeUserPanel(manager)
	}

	if preParse.StreamTimeout == 0 {
		sta.Timeout = time.Duration(300) * time.Second
	} else {
		sta.Timeout = time.Duration(preParse.StreamTimeout) * time.Second
	}

	if preParse.KeepAlive <= 0 {
		sta.ProxyDialer = &net.Dialer{KeepAlive: -1}
	} else {
		sta.ProxyDialer = &net.Dialer{KeepAlive: time.Duration(preParse.KeepAlive) * time.Second}
	}

	sta.RedirHost, sta.RedirPort, err = parseRedirAddr(preParse.RedirAddr)
	if err != nil {
		err = fmt.Errorf("unable to parse RedirAddr: %v", err)
		return
	}

	sta.ProxyBook, err = parseProxyBook(preParse.ProxyBook)
	if err != nil {
		err = fmt.Errorf("unable to parse ProxyBook: %v", err)
		return
	}

	var pv [32]byte
	copy(pv[:], preParse.PrivateKey)
	sta.StaticPv = &pv

	sta.AdminUID = preParse.AdminUID

	var arrUID [16]byte
	for _, UID := range preParse.BypassUID {
		copy(arrUID[:], UID)
		sta.BypassUID[arrUID] = struct{}{}
	}
	copy(arrUID[:], sta.AdminUID)
	sta.BypassUID[arrUID] = struct{}{}

	go sta.UsedRandomCleaner()
	return sta, nil
}

// IsBypass checks if a UID is a bypass user
func (sta *State) IsBypass(UID []byte) bool {
	var arrUID [16]byte
	copy(arrUID[:], UID)
	_, exist := sta.BypassUID[arrUID]
	return exist
}

const TIMESTAMP_TOLERANCE = 180 * time.Second

const CACHE_CLEAN_INTERVAL = 12 * time.Hour

// UsedRandomCleaner clears the cache of used random fields every CACHE_CLEAN_INTERVAL
func (sta *State) UsedRandomCleaner() {
	for {
		time.Sleep(CACHE_CLEAN_INTERVAL)
		sta.usedRandomM.Lock()
		for key, t := range sta.UsedRandom {
			if time.Unix(t, 0).Before(sta.WorldState.Now().Add(TIMESTAMP_TOLERANCE)) {
				delete(sta.UsedRandom, key)
			}
		}
		sta.usedRandomM.Unlock()
	}
}

func (sta *State) registerRandom(r [32]byte) bool {
	sta.usedRandomM.Lock()
	_, used := sta.UsedRandom[r]
	sta.UsedRandom[r] = sta.WorldState.Now().Unix()
	sta.usedRandomM.Unlock()
	return used
}
