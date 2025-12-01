package main

import (
  "fmt"
  "time"
  _ "errors"
  _ "context"
  "sync"
  "strings"
  "net"
  "runtime/debug"
  "encoding/binary"
  _ "github.com/fatih/color"
  "github.com/sergle/radius"
  //"github.com/sergle/radius/client"
  . "github.com/ShyLionTjmn/m"
  //. "github.com/ShyLionTjmn/mygolib"
  "crypto/tls"
  "net/http"
  "net/http/cookiejar"
)

type radiusService struct{}

type silentError string

func radius_server(stop chan string, wg *sync.WaitGroup) {
  defer wg.Done()

  fmt.Println("Starting RADIUS")

  server_shut := make(chan struct{})

  var s *radius.Server

  go func() {
    <-stop
    //if opt_v > 0 {
      fmt.Println("Shutting down RADIUS server")
    //}

    s.Stop()
    close(server_shut)
  }()

  s = radius.NewServer(config.Radius_listen, config.Radius_secret, radiusService{})

  clients := []radius.Client{}

  for _, cl := range config.Clients {
    clients = append(clients, radius.NewClient(cl.Ip, cl.Secret))
  }

  s.WithClientList(radius.NewClientList(clients))

  err := s.ListenAndServe()

  if err != nil {
    fmt.Println(err)
  }


  select {
  case <-server_shut:
  }
}

func (p radiusService) RadiusHandle(request *radius.Packet) (npac *radius.Packet) {

  now_t := time.Now()
  now := now_t.Unix()

  // a pretty print of the request.
  //fmt.Println("Request: ", request)

  defer func() {
    //fmt.Println("Answer: ", npac)
  } ()

  defer func() {
    if r := recover(); r != nil {
      switch request.Code {
      case radius.AccessRequest:
        npac.Code = radius.AccessReject
      case radius.AccountingRequest:
        npac.Code = radius.AccountingResponse
      default:
        npac.Code = radius.AccessReject
      }

      var message string

      switch v := r.(type) {
      case string:
        message = v
      case silentError:
        npac.SetAVP( radius.AVP{Type: radius.ReplyMessage, Value: []byte(v)} )
      case error:
        message = v.Error()
      default:
        message = "Unknown error"
      }

      if message != "" {
        fmt.Println(message)
        fmt.Println(string(debug.Stack()))

        npac.SetAVP( radius.AVP{Type: radius.ReplyMessage, Value: []byte(message)} )

        redis_log("radius_error_log", config.Radius_log_size, M{
          "time": now,
          "message": message,
          "stack": string(debug.Stack()),
          "request": request.String(),
        })
      }
    }
  } ()

  globalMutex.Lock()
  defer globalMutex.Unlock()

  now_debug := now_t.Format(time.DateTime) + " "
  _ = now_debug

	npac = request.Reply()


  var NasIdAVP = request.GetAVP(radius.NASIdentifier)
  var NasIpAVP = request.GetAVP(radius.NASIPAddress)
  var SessIdAVP = request.GetAVP(radius.AcctSessionId)
  var StaIdAVP = request.GetAVP(radius.CallingStationId)
  var CalledIdAVP = request.GetAVP(radius.CalledStationId)
  var StaIpAVP = request.GetAVP(radius.FramedIPAddress)
  var SessClassAVP = request.GetAVP(radius.Class)

  if NasIdAVP == nil ||
     NasIpAVP == nil ||
  false {
    panic("No AcctSessionId or CallingStationId in request")
  }

  nas_id := NasIdAVP.Decode(request).(string)
  nas_ip := NasIpAVP.Decode(request).(net.IP).String()

  if _, ex := config.Clients[nas_id]; !ex || config.Clients[nas_id].Ip != nas_ip {
    panic("Nas IP and Id does not match or exists")
  }


  if SessIdAVP == nil ||
     StaIdAVP == nil ||
  false {
    panic("No AcctSessionId or CallingStationId in request")
  }

  sess_id := SessIdAVP.Decode(request).(string)
  sta_id := StaIdAVP.Decode(request).(string)

  sta_ip := "0.0.0.0"

  if StaIpAVP != nil {
    sta_ip = StaIpAVP.Decode(request).(net.IP).String()
  }

  var called_id string

  if CalledIdAVP != nil {
    called_id = CalledIdAVP.Decode(request).(string)
  }

  secure := false

  if secure_clid_reg != nil && CalledIdAVP != nil &&
    secure_clid_reg.MatchString(called_id) &&
  true {
    secure = true
  }

  switch request.Code {
  case radius.AccessRequest:

    if secure {
      last_login := int64(0)
      dpsk := ""
      dpsk_voucher := ""
      dpsk_login := ""
      dpsk_username := ""
      dpsk_type := ""
      dpsk_level := ""

      for login, _ := range login_devices {
        login_last_login := int64(0)
        if ldap_users.EvM(login ) && ldap_users.Vi(login, "enabled") == 1 &&
           login_devices.Evs(login, "devs", sta_id, "dpsk") &&
           login_devices.Vs(login, "devs", sta_id, "dpsk") != "" &&
        true {
          if login_devices.Evi(login, "devs", sta_id, "last_cache_logon") &&
            login_devices.Vi(login, "devs", sta_id, "last_cache_logon") > login_last_login &&
          true {
            login_last_login = login_devices.Vi(login, "devs", sta_id, "last_cache_logon")
          }
          if login_devices.Evi(login, "devs", sta_id, "last_portal_logon") &&
            login_devices.Vi(login, "devs", sta_id, "last_portal_logon") > login_last_login &&
          true {
            login_last_login = login_devices.Vi(login, "devs", sta_id, "last_portal_logon")
          }

          if login_last_login > last_login {
            last_login = login_last_login
            dpsk = login_devices.Vs(login, "devs", sta_id, "dpsk")
            dpsk_login = login
            dpsk_type = "login"
            dpsk_username = ldap_users.Vs(login, "name")
            if login_devices.Evs(login, "devs", sta_id, "level") {
              if _, ex  := config.Levels[ login_devices.Vs(login, "devs", sta_id, "level") ]; ex {
                dpsk_level = login_devices.Vs(login, "devs", sta_id, "level")
              } else {
                dpsk_level = ""
              }
            } else {
              dpsk_level = ""
            }
          }
        }
      } // range login_devices

      for voucher, _ := range vouchers {
        if vouchers.Evi(voucher, "until") && vouchers.Vi(voucher, "until") > now &&
           vouchers.Evs(voucher, "mac") && vouchers.Vs(voucher, "mac") == sta_id &&
           vouchers.Evs(voucher, "dpsk") && vouchers.Vs(voucher, "dpsk") != "" &&
        true {
          last_voucher_login := int64(0)
          if vouchers.Evi(voucher, "last_cache_logon") &&
             vouchers.Vi(voucher, "last_cache_logon") > last_voucher_login &&
          true {
            last_voucher_login = vouchers.Vi(voucher, "last_cache_logon")
          }
          if vouchers.Evi(voucher, "last_portal_logon") &&
             vouchers.Vi(voucher, "last_portal_logon") > last_voucher_login &&
          true {
            last_voucher_login = vouchers.Vi(voucher, "last_portal_logon")
          }

          if last_voucher_login > last_login {
            last_login = last_voucher_login
            dpsk = vouchers.Vs(voucher, "dpsk")
            dpsk_type = "voucher"
            dpsk_voucher = voucher
            if vouchers.Evs(voucher, "level") {
              if _, ex  := config.Levels[ vouchers.Vs(voucher, "level") ]; ex {
                dpsk_level = vouchers.Vs(voucher, "level")
              } else {
                dpsk_level = ""
              }
            } else {
              dpsk_level = ""
            }
          }
        }
      } // range vouchers

      if last_login > 0 {
        if dpsk_level == "" {
          dpsk_level = config.Default_level_dpsk
        }

        a_cache := M{
          "auth_method": "dpsk",
          "level": dpsk_level,
          "time": now,
        }

        if dpsk_type == "login" {
          a_cache["login"] = dpsk_login
          a_cache["username"] = dpsk_username
        } else if dpsk_type == "voucher" {
          a_cache["voucher"] = dpsk_voucher
        }

        auth_cache[sta_id] = a_cache

        npac.AddVSA( dict.NewVSA("Huawei", "Huawei-DPSK-Info", dpsk) )

      } else {
        npac.Code = radius.AccessReject
        npac.SetAVP( radius.AVP{Type: radius.ReplyMessage, Value: []byte("No mac found in database")} )

        return
      }

    }

	  npac.Code = radius.AccessAccept

    buff := make([]byte, 4)
    binary.BigEndian.PutUint32(buff, uint32(config.Interim_update_period))

    npac.AddAVP( radius.AVP{Type: radius.AcctInterimInterval, Value: buff} )

    var sess_class string

    run := false
    run_reason := ""

    //fmt.Println("Auth: auth_cache:")
    //fmt.Println(auth_cache.ToJsonStr(true))

    if !run && secure {
      run = true
      run_reason = "dpsk auth"
    }

    if !run && auth_cache.Evi(sta_id, "time") &&
       (auth_cache.Vi(sta_id, "time") + config.Reauth_period) > now &&
    true {
      run = true
      run_reason = "sta_id in auth_cache, good time"
    }

    if !run && auth_cache.Evs(sta_id, "voucher") {
      voucher := auth_cache.Vs(sta_id, "voucher")
      if vouchers.EvM(voucher) && vouchers.Evi(voucher, "until") &&
         vouchers.Vi(voucher, "until") > now &&
      true {
        run = true
        run_reason = "sta_id in auth_cache, good voucher"
      }
    }

    if run {
      if !auth_cache.Evs(sta_id, "level") {
        panic("No level in cache")
      }

      if _, ex := config.Levels[ auth_cache.Vs(sta_id, "level") ]; !ex {
        panic("No level " + auth_cache.Vs(sta_id, "level") + " defined")
      }

      level := config.Levels[ auth_cache.Vs(sta_id, "level") ]

      npac.SetAVP( radius.AVP{Type: radius.Class, Value: []byte("run")} )
      sess_class = "run"

      if secure {
        if level.Secure_filter_acl != "" {
          npac.AddAVP( radius.AVP{Type: radius.FilterId, Value: []byte(level.Secure_filter_acl)} )
        }
      } else {
        if level.Filter_acl != "" {
          npac.AddAVP( radius.AVP{Type: radius.FilterId, Value: []byte(level.Filter_acl)} )
        }
      }

      if auth_cache.Evs(sta_id, "login") {
			  npac.AddAVP( radius.AVP{Type: radius.UserName, Value: []byte(auth_cache.Vs(sta_id, "login"))} )
      }

      if !secure && sess_class == "run" && auth_cache.Evs(sta_id, "login") &&
        sta_ip != "0.0.0.0" &&
        config.Fac_server != "" && config.Fac_secret != "" &&
      true {
        fac_login := auth_cache.Vs(sta_id, "login")
        go func() {
          fac := radius.NewRadClient(config.Fac_server, config.Fac_secret)
          fac.SetTimeout(time.Second)
          req := fac.NewRequest(radius.AccountingRequest)

          req.AddAVP( *SessIdAVP )
          req.AddAVP( radius.AVP{Type: radius.UserName, Value: []byte(fac_login)} )
          req.AddAVP( *StaIpAVP )

          acct_type_buff := make([]byte, 4)
          binary.BigEndian.PutUint32(acct_type_buff, uint32(radius.AcctStatusTypeEnumStart))

          req.AddAVP( radius.AVP{Type: radius.AcctStatusType, Value: acct_type_buff } )

          fac.Send(req)

        } ()
      }

      redis_log("radius_log", config.Radius_log_size, M{
        "time": now,
        "message": "Auth run",
        "state": "run",
        "run_reason": run_reason,
        "auth_cache": auth_cache.VM(sta_id),
        "sta_id": sta_id,
        "sta_ip": sta_ip,
        "sess_id": sess_id,
        "request": request.String(),
      })
		} else {
      npac.AddVSA( dict.NewVSA("Huawei", "Huawei-Portal-URL", config.Redir_uri) )
			npac.AddVSA( dict.NewVSA("Huawei", "Huawei-Redirect-ACL", config.Redir_acl) )
			npac.AddAVP( radius.AVP{Type: radius.FilterId, Value: []byte(config.Portal_filter_acl)} )
      sess_class = "portal"

      redis_log("radius_log", config.Radius_log_size, M{
        "time": now,
        "message": "Auth portal",
        "state": "portal",
        "sta_id": sta_id,
        "sta_ip": sta_ip,
        "sess_id": sess_id,
        "request": request.String(),
      })
    }
    npac.SetAVP( radius.AVP{Type: radius.Class, Value: []byte(sess_class)} )

    //fmt.Println(now_debug + "Auth sta: " +sta_id + " sess: " + sess_id + " class: " + sess_class)

  case radius.AccountingRequest:
    var sess_class string

    if SessClassAVP == nil {
      panic(silentError("No Class in Accounting"))
    }

    sess_class = SessClassAVP.Decode(request).(string)

    if !sessions.EvM(sess_id) &&
      ( request.GetAcctStatusType() == radius.AcctStatusTypeEnumStart ||
        request.GetAcctStatusType() == radius.AcctStatusTypeEnumInterimUpdate ||
      false) &&
    true {
      sessions[sess_id] = M{}

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

      sessions.VM(sess_id)["sess_user"] = request.GetUsername()
      sessions.VM(sess_id)["sess_id"] = sess_id
      sessions.VM(sess_id)["sta_id"] = sta_id
      sessions.VM(sess_id)["create_time"] = now


      sessions.VM(sess_id)["code"] = KeyGenDict([]rune(config.Sms_code_dict), config.Sms_code_length)

      if sess_class == "run" {
        if auth_cache.EvM(sta_id) {
          if request.GetAcctStatusType() == radius.AcctStatusTypeEnumStart {
            sessions.VM(sess_id)["auth_source"] = "cache"
          } else {
            sessions.VM(sess_id)["auth_source"] = "adopt"
          }

          if auth_cache.Evs(sta_id, "voucher") {
            voucher := auth_cache.Vs(sta_id, "voucher")
            sessions.VM(sess_id)["voucher"] = voucher
            if vouchers.EvM(voucher) {
              vouchers.VM(voucher)["last_cache_logon"] = now
            }
          }

          if auth_cache.Evs(sta_id, "login") {
            login := auth_cache.Vs(sta_id, "login")
            sessions.VM(sess_id)["login"] = login

            if login_devices.EvM(login, "devs", sta_id) {
              login_devices.VM(login, "devs", sta_id)["last_cache_logon"] = now
            }
          }

          sessions.VM(sess_id)["level"] = auth_cache.Vs(sta_id, "level")

          sessions.VM(sess_id)["authenticated"] = now

          if auth_cache.Evs(sta_id, "auth_method") {
            sessions.VM(sess_id)["auth_method"] = auth_cache.Vs(sta_id, "auth_method")
          }
        }
      }

      redis_log("radius_log", config.Radius_log_size, M{
        "time": now,
        "message": "Acct session create",
        "state": sess_class,
        "sta_id": sta_id,
        "sta_ip": sta_ip,
        "request": request.String(),
        "session": sessions.VM(sess_id).Copy(),
      })
    }

    if sessions.EvM(sess_id) {
      if sessions.Evs(sess_id, "state") && sessions.Vs(sess_id, "state") != sess_class {
        //fmt.Println(now_debug + "Acct sta: " +sta_id + " sess: " + sess_id +
          //" class change: " + sessions.Vs(sess_id, "state") + "->" + sess_class,
        //)
      }
      sessions.VM(sess_id)["state"] = sess_class

      sessions.VM(sess_id)["sess_user"] = request.GetUsername()

      if StaIpAVP != nil {
        sessions.VM(sess_id)["sta_ip"] = StaIpAVP.Decode(request).(net.IP).String()
      } else if !sessions.Evs(sess_id, "sta_ip") {
        sessions.VM(sess_id)["sta_ip"] = "0.0.0.0"
      }

      sessions.VM(sess_id)["nas_id"] = nas_id
      sessions.VM(sess_id)["nas_ip"] = nas_ip

      if sess_class == "run" && sessions.Evs(sess_id, "login") &&
        StaIpAVP != nil &&
        sessions.Evs(sess_id, "sta_ip") && sessions.Vs(sess_id, "sta_ip") != "0.0.0.0" &&
        config.Fac_server != "" && config.Fac_secret != "" &&
      true {
        fac_login := sessions.Vs(sess_id, "login")
        go func() {
          fac := radius.NewRadClient(config.Fac_server, config.Fac_secret)
          fac.SetTimeout(time.Second)
          req := fac.NewRequest(radius.AccountingRequest)

          req.AddAVP( *SessIdAVP )
          req.AddAVP( radius.AVP{Type: radius.UserName, Value: []byte(fac_login)} )
          req.AddAVP( *request.GetAVP(radius.AcctStatusType) )

          fac.Send(req)

        } ()
      }
    }


		// accounting start or end
    switch request.GetAcctStatusType() {
    case radius.AcctStatusTypeEnumStart:
      sessions.VM(sess_id)["acct_start"] = now
      sessions.VM(sess_id)["acct_update"] = now
      //fmt.Println(now_debug + "Acct start sta: " +sta_id + " sess: " + sess_id + " class: " + sess_class)

      redis_log("radius_log", config.Radius_log_size, M{
        "time": now,
        "message": "Acct start",
        "sta_id": sta_id,
        "sta_ip": sta_ip,
        "request": request.String(),
        "session": sessions.VM(sess_id).Copy(),
      })
    case radius.AcctStatusTypeEnumInterimUpdate:
      sessions.VM(sess_id)["acct_update"] = now

      if !sessions.Evi(sess_id, "acct_start") {
        start_time := int64(0)
        AcctSessTimeAVP := request.GetAVP(radius.AcctSessionTime)
        if AcctSessTimeAVP != nil {
          _int, _err := AnyToInt64(AcctSessTimeAVP.Decode(request))
          if _err == nil {
            start_time = now - _int
          }
        }
        sessions.VM(sess_id)["acct_start"] = start_time
      }
    case radius.AcctStatusTypeEnumStop:
      // TODO log session stop
      //fmt.Println(now_debug + "Acct stop sta: " +sta_id + " sess: " + sess_id + " class: " + sess_class)
      log_rec := M{
        "time": now,
        "message": "Acct stop",
        "sta_id": sta_id,
        "sta_ip": sta_ip,
        "request": request.String(),
      }

      if sessions.EvM(sess_id) {
        log_rec["session"] = sessions.VM(sess_id).Copy()
        delete(sessions, sess_id)
      }

      redis_log("radius_log", config.Radius_log_size, log_rec)
    default:
      panic(silentError("Unsupported Accounting Type"))
    }
		npac.Code = radius.AccountingResponse
	default:
    panic(silentError("Unsupported request Code"))
	}
  return
}

type CoA struct {
  action string
  session M
  sess_id string
}

func coa_server(stop chan string, wg *sync.WaitGroup) {
  defer wg.Done()

  clients := make(map[string]*radius.RadClient)

  for nas_id, client := range config.Clients {
    clients[nas_id] = radius.NewRadClient(client.Ip + ":" + client.CoA_Port, client.CoA_Secret)
  }

  COA_LOOP:
  for {
    timer := time.NewTimer(time.Duration(config.CoA_check_period) * time.Second)
    //timer := time.NewTimer(10000 * time.Second)

    coa_queue := make([]CoA, 0)

    select {
    case <-ch_coa:
      timer.Stop()
    case <-timer.C:
    case <-stop:
      break COA_LOOP
    }

    now_t := time.Now()
    now := now_t.Unix()
    now_debug := now_t.Format(time.DateTime) + " "

    globalMutex.Lock()
    //fmt.Println("coa loop: auth_cache:")
    //fmt.Println(auth_cache.ToJsonStr(true))
    for sess_id, _ := range sessions {

      if config.Stale_session_age > 0 &&
         sessions.Evi(sess_id, "acct_update") &&
         (sessions.Vi(sess_id, "acct_update") + config.Stale_session_age) < now &&
      true {

        redis_log("radius_log", config.Radius_log_size, M{
          "time": now,
          "message": "CoA sess cleanup",
          "session": sessions.VM(sess_id).Copy(),
        })

        delete(sessions, sess_id)
        continue
      }

      sta_id := sessions.Vs(sess_id, "sta_id")

      drop := false

      if !auth_cache.EvM(sta_id) {
        drop = true
      } else {
        if auth_cache.Evi(sta_id, "time") &&
           auth_cache.Vi(sta_id, "time") + config.Reauth_period <= now &&
           !auth_cache.Evs(sta_id, "voucher") &&
        true {
          drop = true
          //fmt.Println("DROP 1")
        }

        if auth_cache.Evs(sta_id, "voucher") {
          voucher := auth_cache.Vs(sta_id, "voucher")
          if !vouchers.EvM(voucher) ||
             vouchers.Vi(voucher, "until") <= now ||
          false {
            drop = true
            //fmt.Println("DROP 2, voucher:", voucher)
          }
        }

        if auth_cache.Evs(sta_id, "login") {
          login := auth_cache.Vs(sta_id, "login")
          if !ldap_users.EvM(login ) ||
            ldap_users.Vi(login, "enabled") == 0 ||
          false {
            drop = true
          //fmt.Println("DROP 3")
          }

          if sessions.Vs(sess_id, "state") == "run" && !login_devices.EvM(login, "devs", sta_id) {
            drop = true
          }
        }

        if drop {
          delete(auth_cache, sta_id)
        }
      }

      if drop && sessions.Vs(sess_id, "state") == "run" {
        sessions.VM(sess_id)["coa_state"] = "drop"
      }

      if sessions.Vs(sess_id, "coa_sent_state") != sessions.Vs(sess_id, "coa_state") &&
      true {
        coa_queue = append(coa_queue, CoA{
          sess_id: sess_id,
          session: sessions.VM(sess_id).Copy(),
          action: sessions.Vs(sess_id, "coa_state"),
        })
        //fmt.Println(now_debug + "CoA sta: " + sta_id + " sess: " + sess_id +
        //  " to state: " + sessions.Vs(sess_id, "coa_state"),
        //)
        //fmt.Println("auth_cache:")
        //fmt.Println(auth_cache.ToJsonStr(true))
      }
    }
    globalMutex.Unlock()

    unifis := make(map[string]*http.Client)

    for _, coa := range coa_queue {
      redis_log("radius_log", config.Radius_log_size, M{
        "time": now,
        "message": "CoA action",
        "action": coa.action,
        "session": coa.session,
      })

      if coa.session.Evs("unifi") {
        unifi_controller := coa.session.Vs("unifi_controller")
	      if config.Unifis != nil {
          if _, ex := config.Unifis[unifi_controller]; ex {

	          if _, ex := unifis[unifi_controller]; !ex {
	            cj, _ := cookiejar.New(nil)
	            tr := &http.Transport{
                TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
              }

	            unifis[unifi_controller] = &http.Client {
                Timeout: 5*time.Second,
                Transport: tr,
                Jar: cj,
              }

	            uerr := UnifiLogin(unifis[unifi_controller], unifi_controller)
	            if uerr != nil {
		            fmt.Println(now_debug + "Error: ", uerr.Error())
		            unifis[unifi_controller] = nil
		            continue
	            }
	          } else {
	            if unifis[unifi_controller] == nil {
		            continue
	            }
	          }

	          post_data := M{
	            "mac": coa.session.Vs("unifi_mac"),
	          }

	          post_uri := "/api/s/" + coa.session.Vs("unifi_site") + "/cmd/stamgr"

	          var perr error

	          if coa.action == "drop" {
              post_data["cmd"] = "unauthorize-guest"

	            _, perr = UnifiPost(unifis[unifi_controller], unifi_controller, post_uri, post_data)
	            if perr != nil {
		            fmt.Println(now_debug + "Error: unauthorize-guest:", perr.Error())
              } else {
	              post_data["cmd"] = "kick-sta"
		            _, perr = UnifiPost(unifis[unifi_controller], unifi_controller, post_uri, post_data)
		            if perr != nil && perr.Error() == "UniFi error: api.err.UnknownStation" {
		              perr = nil
		            }
		            if perr != nil { fmt.Println(now_debug + "Error: kick-sta:", perr.Error()) }
	            }
	          } else {
	            if coa.session.Vs("next_state") == "run" {
		            post_data["cmd"] = "authorize-guest"
	            } else {
		            post_data["cmd"] = "unauthorize-guest"
	            }
	            _, perr = UnifiPost(unifis[unifi_controller], unifi_controller, post_uri, post_data)
              if perr != nil { fmt.Println(now_debug + "Error: ", perr.Error()) }
	          }


	          if perr == nil {

              globalMutex.Lock()
              if sessions.EvM(coa.sess_id) {
                sessions.VM(coa.sess_id)["coa_sent_state"] = coa.action
              }

	            if coa.action == "drop" {
		            delete(sessions, coa.sess_id)
	            }
              globalMutex.Unlock()
	          }
	        }
	      }
      } else { // not unifi
        nas_id := coa.session.Vs("nas_id")

        if client, ex := clients[nas_id]; ex {
          var request *radius.Packet
          if coa.action == "drop" {
            request = client.NewRequest(radius.DisconnectRequest)
          } else {
            request = client.NewRequest(radius.CoARequest)
            request.AddVSA( dict.NewVSA("Huawei", "Huawei-Ext-Specific", "user-command=1") )
          }
          request.AddAVP( radius.AVP{Type: radius.AcctSessionId, Value: []byte(coa.sess_id)} )

          reply, err := client.Send(request)
          _ = reply

          if err != nil {
              fmt.Println(now_debug + "Error: ", err.Error())
          } else {
            globalMutex.Lock()
            if sessions.EvM(coa.sess_id) {
              sessions.VM(coa.sess_id)["coa_sent_state"] = coa.action
            }
            globalMutex.Unlock()
          }
        }
      } // not unifi
    }
  }
}
