package main

import (
  "fmt"
  "time"
  "errors"
  _ "context"
  "sync"
  "bytes"
  "strings"
  //"runtime/debug"
  //"encoding/binary"
  . "github.com/ShyLionTjmn/m"
  //. "github.com/ShyLionTjmn/mygolib"
  "encoding/json"
  "crypto/tls"
  "io"
  "net/http"
  "net/http/cookiejar"

)

var ErrLoginReq error

func init() {
  ErrLoginReq = errors.New("UnifiLoginRequired")
}

func UnifiGet(client *http.Client, unifi_key string, uri string) (ret M, rerr error) {
  req, err := http.NewRequest("GET", "https://" + config.Unifis[unifi_key].Host + uri, nil)
  if err != nil { return nil, err }

  req.Header.Add("Content-type", "application/json")

  var resp *http.Response
  if resp, err = client.Do(req); err != nil { return nil, err }

  var resp_json []byte
  if resp_json, err = io.ReadAll(resp.Body); err != nil { return nil, err }

  var resp_m = M{}
  if err = resp_m.UnmarshalJSON(resp_json); err != nil { return nil, err }
  //if err = json.Unmarshal(resp_json, &resp_m); err != nil { return nil, err }

  if !resp_m.Evs("meta", "rc") {
    return nil, errors.New("Bad UniFi response: " + resp_m.ToJsonStr(false))
  }

  if resp_m.Vs("meta", "rc") == "error" {
    if !resp_m.Evs("meta", "msg") {
      return nil, errors.New("Bad UniFi response: " + resp_m.ToJsonStr(false))
    }
    if resp_m.Vs("meta", "msg") != "api.err.LoginRequired" {
      return nil, errors.New("UniFi error: " + resp_m.Vs("meta", "msg"))
    } else {
      return nil, ErrLoginReq
    }
  }
  return resp_m, nil
}

func UnifiPost(client *http.Client, unifi_key string, uri string, post_data M) (ret M, rerr error) {

  var send_bytes []byte
  var jerr error

  if send_bytes, jerr = json.Marshal(post_data); jerr != nil { return nil, jerr }

  req, err := http.NewRequest("POST", "https://" + config.Unifis[unifi_key].Host + uri, bytes.NewReader(send_bytes))
  if err != nil { return nil, err }

  req.Header.Add("Content-type", "application/json")

  var resp *http.Response
  if resp, err = client.Do(req); err != nil { return nil, err }

  var resp_json []byte
  if resp_json, err = io.ReadAll(resp.Body); err != nil { return nil, err }

  var resp_m = M{}

  if err = resp_m.UnmarshalJSON(resp_json); err != nil { return nil, err }

  if !resp_m.Evs("meta", "rc") {
    return nil, errors.New("Bad UniFi response: " + resp_m.ToJsonStr(false))
  }

  if resp_m.Vs("meta", "rc") == "error" {
    if !resp_m.Evs("meta", "msg") {
      return nil, errors.New("Bad UniFi response: " + resp_m.ToJsonStr(false))
    }
    if resp_m.Vs("meta", "msg") != "api.err.LoginRequired" {
      return nil, errors.New("UniFi error: " + resp_m.Vs("meta", "msg"))
    } else {
      return nil, ErrLoginReq
    }
  }

  return resp_m, nil
}

func UnifiLogin(client *http.Client, unifi_key string) error {
  _, err := UnifiGet(client, unifi_key, "/api/self")
  if err != nil && err != ErrLoginReq { return err }

  if err == ErrLoginReq {

    //fmt.Println("UnifiLogin: Login required, trying to login")

    // Try to login

    post_data := M{"username": config.Unifis[unifi_key].Login, "password": config.Unifis[unifi_key].Password} //, "remeber": "true"}

    client.Jar, _ = cookiejar.New(nil)

    _, err = UnifiPost(client, unifi_key, "/api/login", post_data)
    if err != nil { return err }

    //fmt.Println("UnifiLogin: Logged in. Response:", resp.ToJsonStr(true))
    return nil

  } else {
    //fmt.Println("UnifiLogin: No login required. Self info:", resp.ToJsonStr(true))
    return nil
  }
}

func unifi_server(stop chan string, wg *sync.WaitGroup) {
  defer wg.Done()

  if config.Unifis == nil || len(config.Unifis) == 0 {
    fmt.Println("Not starting UniFi scanner: none configured")
    return
  }

  fmt.Println("Starting UniFi scanner")

  unifis := make(map[string]*http.Client)

  for unifi_key, _ := range config.Unifis {
    tr := &http.Transport{
      TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }

    cj, _ := cookiejar.New(nil)

    unifis[unifi_key] = &http.Client {
      Timeout: 5*time.Second,
      Transport: tr,
      Jar: cj,
    }
  }

  UNIFI_LOOP: for {
    for unifi_key, _ := range config.Unifis {

      uerr := UnifiLogin(unifis[unifi_key], unifi_key)
      if uerr != nil {
	fmt.Println("ERROR:", uerr)
      } else {
	// get sites list

	if resp, rerr := UnifiGet(unifis[unifi_key], unifi_key, "/api/self/sites"); rerr != nil {
	  fmt.Println("ERROR:", rerr)
	} else {
	  //fmt.Println(resp.ToJsonStr(true))

	  if sites_a, ok := resp["data"].([]interface{}); ok {
            for _, site_data_i := range sites_a {
//              fmt.Println(site_data_i.(M).Vs("desc"), site_data_i.(M).Vs("name"))

	      // get wifi clients

	      site := site_data_i.(M).Vs("name")

	      if sresp, serr := UnifiGet(unifis[unifi_key], unifi_key, "/api/s/" + site + "/stat/sta"); serr != nil {
		fmt.Println("ERROR:", serr)
              } else {
		//fmt.Println(sresp.ToJsonStr(true))

		if sta_a, ok := sresp["data"].([]interface{}); ok {
		  globalMutex.Lock()

		  now := time.Now().Unix()

		  for _, sta_i := range sta_a {
		    if sta_i.(M).EvA("_is_guest_by_uap") && sta_i.(M).VA("_is_guest_by_uap").(bool) {
		      //fmt.Println(sta_i.(M).ToJsonStr(true))
		      sta_ip := ""
		      unifi_mac := ""
		      ssid := ""
		      sta_id := ""

                      if sta_i.(M).Evs("ip") { sta_ip = sta_i.(M).Vs("ip") }
                      if sta_i.(M).Evs("essid") { ssid = sta_i.(M).Vs("essid") }
                      if sta_i.(M).Evs("mac") {
			unifi_mac = sta_i.(M).Vs("mac")
			sta_id = FormatMAC(unifi_mac)
		      }

		      state := "portal"

		      if sta_i.(M).EvA("authorized") && sta_i.(M).VA("authorized").(bool) {
			state = "run"
		      }

		      if sta_ip != "" && unifi_mac != "" && ssid != "" && sta_id != "" {
                        sess_id := unifi_key + "/" + site + "/" + sta_ip + "/" + sta_id + "/" + ssid

			if !sessions.EvM(sess_id) {

			  acct_start := now
			  if sta_i.(M).Evi("assoc_time") {
			    acct_start = sta_i.(M).Vi("assoc_time")
			  }

			  sessions[sess_id] = M{
			    "sess_id": sess_id,
                            "sta_id": sta_id,
                            "unifi": "1",
                            "sta_ip": sta_ip,
                            "acct_update": now,
                            "acct_start": acct_start,
                            "unifi_controller": unifi_key,
                            "unifi_site": site,
                            "ssid": ssid,
                            "unifi_mac": unifi_mac,
                            "state": state,
			    "code": KeyGenDict([]rune(config.Sms_code_dict), config.Sms_code_length),
			    "create_time": now,
                          }

			  sess_class := "portal"

                          if random_reg.MatchString(sta_id) {
                            sessions.VM(sess_id)["vendor"] = "Random"
                          } else {
                            m := mac_reg.FindStringSubmatch(sta_id)
                            oui := strings.ToLower(strings.Join(m[1:4], ""))
                      
                            vendor, ex := vendors[oui]
                      
                            if ex {
                              sessions.VM(sess_id)["vendor"] = vendor
                            } else {
                              sessions.VM(sess_id)["vendor"] = "Unknown"
                            }
                          }
                      
                          if auth_cache.Evi(sta_id, "time") &&
                             (auth_cache.Vi(sta_id, "time") + config.Reauth_period) > now &&
                             auth_cache.Evs(sta_id, "login") &&
                          true {
                            sessions.VM(sess_id)["next_state"] = "run"
                            sess_class = "run"
                      
                            sessions.VM(sess_id)["authenticated"] = now
                            sessions.VM(sess_id)["auth_source"] = "cache"
                      
                            login := auth_cache.Vs(sta_id, "login")
                      
                            sessions.VM(sess_id)["login"] = login
                            sessions.VM(sess_id)["level"] = auth_cache.Vs(sta_id, "level")
                      
                            if login_devices.EvM(login, "devs", sta_id) {
                              login_devices.VM(login, "devs", sta_id)["last_cache_logon"] = now
                            }
                      
                            if auth_cache.Evs(sta_id, "auth_method") {
                              sessions.VM(sess_id)["auth_method"] = auth_cache.Vs(sta_id, "auth_method")
                            }
                          }

                          if auth_cache.Evs(sta_id, "voucher") &&
                             vouchers.EvM( auth_cache.Vs(sta_id, "voucher") ) &&
                             vouchers.Vs( auth_cache.Vs(sta_id, "voucher"), "mac") == sta_id &&
                             vouchers.Vi( auth_cache.Vs(sta_id, "voucher"), "until") > now &&
                          true {
                            sessions.VM(sess_id)["next_state"] = "run"
                            sess_class = "run"
                      
                            sessions.VM(sess_id)["authenticated"] = now
                            sessions.VM(sess_id)["auth_source"] = "cache"
                      
                            voucher := auth_cache.Vs(sta_id, "voucher")
                      
                            sessions.VM(sess_id)["voucher"] = voucher
                            sessions.VM(sess_id)["level"] = auth_cache.Vs(sta_id, "level")
                      
                            vouchers.VM(voucher)["last_cache_logon"] = now
                      
                      
                            if auth_cache.Evs(sta_id, "auth_method") {
                              sessions.VM(sess_id)["auth_method"] = auth_cache.Vs(sta_id, "auth_method")
                            }
                          }
                      
                          redis_log("radius_log", config.Radius_log_size, M{
                            "time": now,
                            "message": "Acct session create",
                            "state": sess_class,
                            "sta_id": sta_id,
                            "sta_ip": sta_ip,
                            "session": sessions.VM(sess_id).Copy(),
                          })

			} else {
			  sessions.VM(sess_id)["acct_update"] = now
			}
                        sessions.VM(sess_id)["state"] = state
                        sessions.VM(sess_id)["unifi_session"] = sta_i.(M)
		      }
		    }
		  }

		  globalMutex.Unlock()
		}
              }
/*
	      if sresp, serr := UnifiGet(unifis[unifi_key], unifi_key, "/api/s/" + site + "/stat/guest"); serr != nil {
		fmt.Println("ERROR:", serr)
              } else {
		//fmt.Println(sresp.ToJsonStr(true))

		if sta_a, ok := sresp["data"].([]interface{}); ok {
		  for _, sta_i := range sta_a {
		    _ = sta_i
//		    if sta_i.(M).EvA("_is_guest_by_uap") && sta_i.(M).VA("_is_guest_by_uap").(bool) {
//		      fmt.Println(sta_i.(M).ToJsonStr(true))
//		    }
		  }
		}
              }
	      */
	    }
	  }
	}
      }


    }

    loop_timer := time.NewTimer(time.Duration(config.Unifi_scan_period) * time.Second)
    select {
    case <-loop_timer.C:
      // continue loop
    case <-stop:
      loop_timer.Stop()
      break UNIFI_LOOP
    }
  }
  fmt.Println("Stopped UniFi scanner")
}


