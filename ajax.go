package main

import (
  "fmt"
  "time"
  "sync"
  "io"
  "strings"
  "slices"
  "encoding/json"
  "sort"
  "net/http"
  "github.com/gomodule/redigo/redis"
  "github.com/pquerna/otp/totp"
  . "github.com/ShyLionTjmn/m"
  . "github.com/ShyLionTjmn/mygolib"
)


func handleAjax(w http.ResponseWriter, req *http.Request) {
  if req.Method == "OPTIONS" {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "*")
    w.Header().Set("Access-Control-Allow-Headers", "*")
    w.WriteHeader(http.StatusOK)
    return
  }

  defer func() { handle_error_json(recover(), w, req); } ()

  var body []byte
  var err error

  if body, err = io.ReadAll(req.Body); err != nil {
    panic(err)
  }

  now := time.Now().Unix()
  now_str := fmt.Sprint(now)
  _ = now

  var user_sub string
  var user_name string
  var user_login string
  var user_email string
  var user_groups_string string

  remote_addr := req.RemoteAddr

  ip_a := remote_addr_reg.FindStringSubmatch(remote_addr)
  if ip_a == nil {
    panic("bad remote addr")
  }

  user_ip := ip_a[1]

  if config.Proxy_host != "" && config.Client_ip_header != "" {
    if user_ip != config.Proxy_host {
      panic("access denied for " + user_ip)
    }

    if header_values, ex := req.Header[config.Client_ip_header]; !ex || len(header_values) == 0 {
      panic("invalid headers")
    }

    user_ip = req.Header[config.Client_ip_header][0]

    if !ip_reg.MatchString(user_ip) {
      panic("bad header value")
    }
  }

  for header, header_values := range req.Header {
    if strings.ToLower(header) == "x-idp-sub" && len(header_values) > 0 {
      user_sub = strings.TrimSpace(header_values[0])
      _ = user_sub
    } else if strings.ToLower(header) == "x-idp-name" && len(header_values) > 0 {
      user_name = strings.TrimSpace(header_values[0])
    } else if strings.ToLower(header) == "x-idp-email" && len(header_values) > 0 {
      user_email = strings.ToLower(strings.TrimSpace(header_values[0]))
    } else if strings.ToLower(header) == "x-idp-username" && len(header_values) > 0 {
      user_login = strings.ToLower(strings.TrimSpace(header_values[0]))
    } else if strings.ToLower(header) == "x-idp-groups" && len(header_values) > 0 {
      user_groups_string = strings.TrimSpace(header_values[0])
      _ = user_groups_string
    }
  }

  if user_login == "" {
    panic("No authentication headers present")
  }

  out := make(M)

  once := &sync.Once{}

  globalMutex.Lock()

  defer func() {
    once.Do(func() {
      globalMutex.Unlock()
    })
  } ()

  var q M

  if req.Method == "GET" {
    q = make(M)
    values := req.URL.Query()
    for k, v := range values {
      if len(v) == 0 {
          q[k] = ""
      } else if len(v) == 1 {
          q[k] = v[0]
      } else {
        q[k] = v
      }
    }
  } else {
    if err = json.Unmarshal(body, &q); err != nil {
      panic(err)
    }
  }

  if _, action_ex := q["action"]; !action_ex {
    panic("no action in query")
  }

  is_login_admin := login_admins_reg.MatchString(user_groups_string)
  is_voucher_admin := voucher_admins_reg.MatchString(user_groups_string)

  action := q["action"].(string)

  if action == "userinfo" {
    out["name"] = user_name
    out["login"] = user_login
    out["email"] = user_email
    out["groups_string"] = user_groups_string
    out["is_login_admin"] = is_login_admin
    out["is_voucher_admin"] = is_voucher_admin

    if ldap_users.Evs(user_login, "totp_uri") {
      out["totp_created"] = ldap_users.Vs(user_login, "totp_created")
      out["totp_uri"] = ldap_users.Vs(user_login, "totp_uri")
    }

    goto OUT
  } else if action == "sessions" {
    if !is_login_admin && !is_voucher_admin {
      panic("No access")
    }

    out_sessions := []M{}

    for sess_id, _ := range sessions {
      out_sess := sessions.VM(sess_id).Copy()

      out_sess["duration"] = now - sessions.Vi(sess_id, "acct_start")

      sta_id := sessions.Vs(sess_id, "sta_id")

      if auth_cache.EvM(sta_id) {
        out_sess["auth_cache"] = auth_cache.VM(sta_id).Copy()
      }

      if sessions.Evs(sess_id, "login") {
        login := sessions.Vs(sess_id, "login")
        if ldap_users.EvM(login) {
          out_sess["login_info"] = ldap_users.VM(login).Copy()
        }
        if login_devices.EvM(login) {
          out_sess["login_devices"] = login_devices.VM(login).Copy()
        }
      }

      out_sessions = append(out_sessions, out_sess)
    }
    out["sessions"] = out_sessions
  } else if action == "drop" {
    if !is_login_admin && !is_voucher_admin {
      panic("No access")
    }

    if !q.Evs("sess_id") { panic("no sess_id") }
    sess_id := q.Vs("sess_id")

    if sessions.EvM(sess_id) {
      sta_id := sessions.Vs(sess_id, "sta_id")
      if auth_cache.EvM(sta_id) {
        delete(auth_cache, sta_id)
      }
      sessions.VM(sess_id)["next_state"] = "drop"
      sessions.VM(sess_id)["coa_state"] = "drop"
      if sessions.Vs(sess_id, "coa_sent_state") != "drop" {
        ch_coa <- sess_id
      }
      out["done"] = 1

      redis_log("audit_log", config.Audit_log_size, M{
        "time": now,
        "action": action,
        "user_login": user_login,
        "user_name": user_name,
        "user_ip": user_ip,
        "session": sessions.VM(sess_id).Copy(),
      })

    } else {
      out["done"] = 0
    }

  } else if action == "list_logins" {
    if !is_login_admin {
      panic("No access")
    }

    logins_list := ldap_users.Keys()

    //sort somehow

    if true {
      sort.Sort(ByNum(logins_list))
    }

    out_logins := make([]M, 0)

    for _, login := range logins_list {
      out_logins = append(out_logins, getLoginData(login) )
    }

    out["logins"] = out_logins


    out["total"] = len(logins_list)

  } else if action == "set_login_allowed" {
    if !is_login_admin {
      panic("No access")
    }

    if !q.Evs("login") { panic("no login") }

    login := q.Vs("login")

    if !q.Evs("allowed") { panic("no allowed") }

    if !ldap_users.EvM(login) { panic("No such login") }

    prev := ""

    if login_devices.Evi(login, "allowed") {
      prev = login_devices.Vs(login, "allowed")
    }

    if q.Vs("allowed") == "" {
      if login_devices.EvM(login) {
        delete(login_devices.VM(login), "allowed")
      }
    } else {
      if !num_reg.MatchString(q.Vs("allowed")) { panic("Bad allowed") }
      if !login_devices.EvM(login) {
        login_devices[login] = M{}
      }

      login_devices.VM(login)["allowed"] = q.Vi("allowed")
    }

    out["row"] = getLoginData(login)

    redis_log("audit_log", config.Audit_log_size, M{
      "time": now,
      "action": action,
      "user_login": user_login,
      "user_name": user_name,
      "user_ip": user_ip,
      "login": login,
      "allowed": q.Vs("allowed"),
      "prev": prev,
    })

  } else if action == "reset_totp" {
    if !q.Evs("login") { panic("no login") }

    login := q.Vs("login")

    if !ldap_users.EvM(login) { panic("No such login") }

    if !is_login_admin && login != user_login {
      panic("No access")
    }

    //prev := ""

    if ldap_users.Evs(login, "totp_uri") {
      //prev = ldap_users.Vs(login, "totp_uri")
    } else {
      panic("No totp in account")
    }

    totp_key, kerr := totp.Generate(totp.GenerateOpts{
      Issuer: config.Totp_issuer,
      AccountName: login,
    })

    if kerr == nil {
      ldap_users.VM(login)["totp_uri"] = totp_key.URL()
      ldap_users.VM(login)["totp_created"] = now
    }


    out["row"] = getLoginData(login)

    if login == user_login {
      out.VM("row")["totp_uri"] = totp_key.URL()
    }

    redis_log("audit_log", config.Audit_log_size, M{
      "time": now,
      "action": action,
      "user_login": user_login,
      "user_name": user_name,
      "user_ip": user_ip,
      "login": login,
      "totp_uri": "",
      "prev": "",
    })

  } else if action == "set_login_dev_level" {
    if !is_login_admin {
      panic("No access")
    }

    if !q.Evs("login") { panic("no login") }
    if !q.Evs("mac") { panic("no mac") }
    if !q.Evs("level") { panic("no level") }

    login := q.Vs("login")
    mac := q.Vs("mac")
    level := q.Vs("level")

    if !ldap_users.EvM(login) { panic("No such login") }
    if !login_devices.EvM(login, "devs", mac) { panic("No such login dev") }
    if _, ex := config.Levels[level]; level != "" && !ex { panic("No such level") }

    prev := ""
    if login_devices.Evs(login, "devs", mac, "level") {
      prev = login_devices.Vs(login, "devs", mac, "level")
    }

    if level == "" {
      delete(login_devices.VM(login, "devs", mac), "level")
    } else {
      login_devices.VM(login, "devs", mac)["level"] = level
    }

    if auth_cache.EvM(mac) &&
      auth_cache.Evs(mac, "login") &&
      auth_cache.Vs(mac, "login") == login &&
    true {
      current_level := auth_cache.Vs(mac, "level")

      var target_level string
      if level != "" {
        target_level = level
      } else {
        switch(auth_cache.Vs(mac, "auth_method")) {
        case "login":
          target_level = config.Default_level_login
        case "voucher":
          target_level = config.Default_level_voucher
        case "sms":
          target_level = config.Default_level_sms
        case "2fa":
          target_level = config.Default_level_2fa
        case "totp":
          target_level = config.Default_level_login
        default:
          panic("Cannot choose default level")
        }
      }

      if target_level != "" && target_level != current_level {
        auth_cache.VM(mac)["level"] = target_level
        for sess_id, _ := range sessions {
          if sessions.Vs(sess_id, "sta_id") == mac &&
             (sessions.Vs(sess_id, "state") == "run" ||
              sessions.Vs(sess_id, "next_state") == "run" ||
             false) &&
          true {
            sessions.VM(sess_id)["coa_state"] = "update_" + now_str
            sessions.VM(sess_id)["level"] = target_level
          }
        }
      }
    }

    redis_log("audit_log", config.Audit_log_size, M{
      "time": now,
      "action": action,
      "user_login": user_login,
      "user_name": user_name,
      "user_ip": user_ip,
      "login": login,
      "mac": mac,
      "level": level,
      "prev": prev,
    })


    out["done"] = 1

  } else if action == "del_login_dev" {
    if !is_login_admin {
      panic("No access")
    }

    if !q.Evs("login") { panic("no login") }
    if !q.Evs("mac") { panic("no mac") }

    login := q.Vs("login")
    mac := q.Vs("mac")

    if !ldap_users.EvM(login) { panic("No such login") }
    if !login_devices.EvM(login, "devs", mac) { panic("No such login dev") }

    delete(login_devices.VM(login, "devs"), mac)

    redis_log("audit_log", config.Audit_log_size, M{
      "time": now,
      "action": action,
      "user_login": user_login,
      "user_name": user_name,
      "user_ip": user_ip,
      "login": login,
      "mac": mac,
    })

    out["row"] = getLoginData(login)

  } else if action == "allow_swap_login_dev" {
    if !is_login_admin {
      panic("No access")
    }

    if !q.Evs("login") { panic("no login") }
    if !q.Evs("mac") { panic("no mac") }

    login := q.Vs("login")
    mac := q.Vs("mac")

    if !ldap_users.EvM(login) { panic("No such login") }
    if !login_devices.EvM(login, "devs", mac) { panic("No such login dev") }

    login_devices.VM(login, "devs", mac)["swap_from"] = int64(0)

    redis_log("audit_log", config.Audit_log_size, M{
      "time": now,
      "action": action,
      "user_login": user_login,
      "user_name": user_name,
      "user_ip": user_ip,
      "login": login,
      "mac": mac,
    })

    out["row"] = getLoginData(login)

  } else if action == "prolong_cache_login_dev" {
    if !is_login_admin {
      panic("No access")
    }

    if !q.Evs("login") { panic("no login") }
    if !q.Evs("mac") { panic("no mac") }

    login := q.Vs("login")
    mac := q.Vs("mac")

    if !ldap_users.EvM(login) { panic("No such login") }
    if !login_devices.EvM(login, "devs", mac) { panic("No such login dev") }

    if !auth_cache.Evs(mac, "login") || auth_cache.Vs(mac, "login") != login {
      panic("Not in cache")
    }

    auth_cache.VM(mac)["time"] = now

    redis_log("audit_log", config.Audit_log_size, M{
      "time": now,
      "action": action,
      "user_login": user_login,
      "user_name": user_name,
      "user_ip": user_ip,
      "login": login,
      "mac": mac,
    })

    out["row"] = getLoginData(login)
  } else if action == "unauth_login_dev" {
    if !is_login_admin {
      panic("No access")
    }

    if !q.Evs("login") { panic("no login") }
    if !q.Evs("mac") { panic("no mac") }

    login := q.Vs("login")
    mac := q.Vs("mac")

    if !ldap_users.EvM(login) { panic("No such login") }
    if !login_devices.EvM(login, "devs", mac) { panic("No such login dev") }

    if auth_cache.Evs(mac, "login") && auth_cache.Vs(mac, "login") == login {
      delete(auth_cache, mac)
    }

    redis_log("audit_log", config.Audit_log_size, M{
      "time": now,
      "action": action,
      "user_login": user_login,
      "user_name": user_name,
      "user_ip": user_ip,
      "login": login,
      "mac": mac,
    })

    out["row"] = getLoginData(login)
  } else if action == "manual_cache_login_dev" {
    if !is_login_admin {
      panic("No access")
    }

    if !q.Evs("login") { panic("no login") }
    if !q.Evs("mac") { panic("no mac") }
    if !q.Evs("level") { panic("no level") }

    login := q.Vs("login")
    mac := q.Vs("mac")
    level := q.Vs("level")

    if _, ex := config.Levels[level]; !ex { panic("No such level") }

    if !ldap_users.EvM(login) { panic("No such login") }
    if !login_devices.EvM(login, "devs", mac) { panic("No such login dev") }

    delete(auth_cache, mac)

    auth_cache[mac] = M{
      "time": now, "login": login, "level": level,
      "username": ldap_users.Vs(login, "name"),
      "auth_method": "admin",
    }

    send_coa := false

    for sess_id, _ := range sessions {
      if sessions.Vs(sess_id, "sta_id") == mac {
        sessions.VM(sess_id)["next_state"] = "drop"
        sessions.VM(sess_id)["coa_state"] = "drop"
        if sessions.Vs(sess_id, "coa_sent_state") != "drop" {
          send_coa = true
        }
      }
    }

    if send_coa {
      ch_coa <- "any"
    }

    redis_log("audit_log", config.Audit_log_size, M{
      "time": now,
      "action": action,
      "user_login": user_login,
      "user_name": user_name,
      "user_ip": user_ip,
      "login": login,
      "level": level,
      "mac": mac,
    })

    out["row"] = getLoginData(login)
  } else if action == "mail_login_totp" {
    if !is_login_admin {
      panic("No access")
    }

    if !q.Evs("login") { panic("no login") }

    login := q.Vs("login")

    if !ldap_users.EvM(login) {
      panic("No login!")
    }

    if !ldap_users.Evs(login, "mail") {
      panic("User has no mail")
    }

    if ldap_users.Vs(login, "mail") == "" {
      panic("Empty mail")
    }

    if !ldap_users.Evs(login, "totp_uri") || !ldap_users.Evi(login, "totp_created") {
      panic("User has no TOTP")
    }

    go mail_totp(ldap_users.VM(login).Copy())

    out["done"] = 1 
  } else if action == "add_login_dev" {
    if !is_login_admin {
      panic("No access")
    }

    if !q.Evs("login") { panic("no login") }
    if !q.Evs("mac") { panic("no mac") }
    if !q.Evs("level") { panic("no level") }

    login := q.Vs("login")
    mac := q.Vs("mac")
    level := q.Vs("level")

    if _, ex := config.Levels[level]; level != "" && !ex { panic("No such level") }

    if !ldap_users.EvM(login) { panic("No such login") }
    if login_devices.EvM(login, "devs", mac) { panic("Dev already exists") }

    if !login_devices.EvM(login) { login_devices[login] = M{} }
    if !login_devices.EvM(login, "devs") { login_devices.VM(login)["devs"] = M{} }

    new_dev := M{"added": now, "swap_from": now}

    if config.DPSK_length > 0 && config.DPSK_dict != "" {
      new_dev["dpsk"] = KeyGenDict([]rune(config.DPSK_dict), int(config.DPSK_length))
    }

    login_devices.VM(login, "devs")[mac] = new_dev

    if level != "" {
      login_devices.VM(login, "devs", mac)["level"] = level
    }

    redis_log("audit_log", config.Audit_log_size, M{
      "time": now,
      "action": action,
      "user_login": user_login,
      "user_name": user_name,
      "user_ip": user_ip,
      "login": login,
      "level": level,
      "mac": mac,
    })


    out["row"] = getLoginData(login)

  } else if action == "gen_vouchers" {
    if !is_voucher_admin {
      panic("No access")
    }
    if !q.Evi("count") { panic("no count") }
    count := q.Vi("count")

    if count < 1 || count > config.Max_vouchers_gen { panic("Bad count") }

    if !q.Evs("email") { panic("no email") }
    email := q.Vs("email")

    if email != "" && !email_reg.MatchString(email) { panic("Bad email") }

    if !q.Evs("comment") { panic("no comment") }
    comment := q.Vs("comment")
    if len(comment) > 256 { panic("comment to long") }

    if !q.Evs("level") { panic("no level") }
    level := q.Vs("level")
    if _, ex := config.Levels[level]; level != "" && !ex { panic("Bad level") }

    if !q.Evi("until") { panic("no until") }
    until := q.Vi("until")

    old_vouchers := vouchers.Keys()
    new_vouchers := M{}

    for i := 0; i < int(count); i++ {
      var voucher string
      for {
        voucher = KeyGenDict([]rune(config.Voucher_dict), int(config.Voucher_length))
        if !vouchers.EvM(voucher) {
          break
        }
      }
      new_vouchers[voucher] = M{
        "voucher": voucher,
        "until": until,
        "added": now,
        "by_login": user_login,
        "by_name": user_name,
        "comment": comment,
      }

      if config.DPSK_length > 0 && config.DPSK_dict != "" {
        new_vouchers.VM(voucher)["dpsk"] = KeyGenDict([]rune(config.DPSK_dict), int(config.DPSK_length))
      }

      if email != "" {
        new_vouchers.VM(voucher)["mailed_to"] = email
      }

      if level != "" {
        new_vouchers.VM(voucher)["level"] = level
      }
    }

    redis_log("audit_log", config.Audit_log_size, M{
      "time": now,
      "action": action,
      "user_login": user_login,
      "user_name": user_name,
      "user_ip": user_ip,
      "count": count,
      "until": until,
      "comment": comment,
      "email": email,
      "level": level,
      "list": new_vouchers.Keys(),
    })

    out["vouchers"] = new_vouchers


    if len(old_vouchers) > int(config.Max_total_vouchers) {

      slices.SortFunc(old_vouchers, func(a, b string) int {
        if vouchers.Vi(b, "added") < vouchers.Vi(a, "added") { return 1 }
        if vouchers.Vi(a, "added") < vouchers.Vi(b, "added") { return -1 }
        return 0
      })

      old_vouchers = slices.Delete(old_vouchers, 0, len(old_vouchers) - int(config.Max_total_vouchers))

      for _, voucher := range old_vouchers {
        delete(vouchers, voucher)
      }
    }

    for voucher, _ := range new_vouchers {
      vouchers[voucher] = new_vouchers.VM(voucher).Copy()
    }

    if email != "" {
      go mail_vouchers(new_vouchers, email)
    }

  } else if action == "get_vouchers" {
    if !is_voucher_admin {
      panic("No access")
    }

    out["vouchers"] = vouchers.Copy()

  } else if action == "set_voucher_level" {
    if !is_voucher_admin {
      panic("No access")
    }

    if !q.Evs("voucher") { panic("No voucher") }

    voucher := q.Vs("voucher")
    if !vouchers.EvM(voucher) { panic("No such voucher") }

    if !q.Evs("level") { panic("No level") }

    level := q.Vs("level")
    if _, ex := config.Levels[level]; level != "" && !ex { panic("No such level") }

    prev := ""
    if vouchers.Evs(voucher, "level") {
      prev = vouchers.Vs(voucher, "level")
    }

    if level == "" {
      delete(vouchers.VM(voucher), "level")
    } else {
      vouchers.VM(voucher)["level"] = level
    }

    vouchers.VM(voucher)["changed"] = now
    vouchers.VM(voucher)["changed_by_login"] = user_login
    vouchers.VM(voucher)["changed_by_name"] = user_name


    redis_log("audit_log", config.Audit_log_size, M{
      "time": now,
      "action": action,
      "user_login": user_login,
      "user_name": user_name,
      "user_ip": user_ip,
      "voucher": voucher,
      "level": level,
      "prev": prev,
    })

    out["voucher"] = vouchers.VM(voucher).Copy()

    if vouchers.Evs(voucher, "mac") {
      mac := vouchers.Vs(voucher, "mac")

      if auth_cache.EvM(mac) &&
        auth_cache.Evs(mac, "voucher") &&
        auth_cache.Vs(mac, "voucher") == voucher &&
      true {
        current_level := auth_cache.Vs(mac, "level")

        var target_level string
        if level != "" {
          target_level = level
        } else {
          switch(auth_cache.Vs(mac, "auth_method")) {
          case "login":
            target_level = config.Default_level_login
          case "voucher":
            target_level = config.Default_level_voucher
          case "sms":
            target_level = config.Default_level_sms
          case "2fa":
            target_level = config.Default_level_2fa
          case "totp":
            target_level = config.Default_level_login
          default:
            panic("Cannot choose default level")
          }
        }

        if target_level != "" && target_level != current_level {
          auth_cache.VM(mac)["level"] = target_level
          for sess_id, _ := range sessions {
            if sessions.Vs(sess_id, "sta_id") == mac &&
               (sessions.Vs(sess_id, "state") == "run" ||
                sessions.Vs(sess_id, "next_state") == "run" ||
               false) &&
            true {
              sessions.VM(sess_id)["coa_state"] = "update_" + now_str
              sessions.VM(sess_id)["level"] = target_level
            }
          }
        }
      }
    }
  } else if action == "set_voucher_until" {
    if !is_voucher_admin {
      panic("No access")
    }

    if !q.Evs("voucher") { panic("No voucher") }

    voucher := q.Vs("voucher")
    if !vouchers.EvM(voucher) { panic("No such voucher") }

    if !q.Evi("until") { panic("No until") }

    until := q.Vi("until")

    prev := vouchers.Vi(voucher, "until")

    vouchers.VM(voucher)["until"] = until


    vouchers.VM(voucher)["changed"] = now
    vouchers.VM(voucher)["changed_by_login"] = user_login
    vouchers.VM(voucher)["changed_by_name"] = user_name


    redis_log("audit_log", config.Audit_log_size, M{
      "time": now,
      "action": action,
      "user_login": user_login,
      "user_name": user_name,
      "user_ip": user_ip,
      "voucher": voucher,
      "until": until,
      "prev": prev,
    })

    out["voucher"] = vouchers.VM(voucher).Copy()

  } else if action == "del_vouchers" {
    if !is_voucher_admin {
      panic("No access")
    }

    if !q.EvA("vouchers") { panic("No vouchers") }

    del_list, ok := q.VA("vouchers").([]interface{})
    if !ok { panic("Bad list") }

    prev_list := []string{}

    for _, voucher := range del_list {
      delete(vouchers, voucher.(string))
      prev_list = append(prev_list, voucher.(string))
    }

    redis_log("audit_log", config.Audit_log_size, M{
      "time": now,
      "action": action,
      "user_login": user_login,
      "user_name": user_name,
      "user_ip": user_ip,
      "list": prev_list,
    })

    out["done"] = 1

  } else if action == "get_userlog" {
    if !is_voucher_admin && !is_login_admin {
      panic("No access")
    }

    once.Do(func() {
      globalMutex.Unlock()
    })

    var red redis.Conn
    var rerr error

    red, rerr = RedisCheck(red, "unix", config.Redis_socket, config.Redis_db)
    if rerr != nil { panic(rerr) }

    var events_list []string

    var portal_events []string

    events_list, rerr = redis.Strings(red.Do("LRANGE", config.Redis_prefix + "radius_log", 0, -1))
    if rerr == redis.ErrNil {
      events_list = []string{}
    } else if rerr != nil {
      panic(rerr)
    }

    portal_events, rerr = redis.Strings(red.Do("LRANGE", config.Redis_prefix + "portal_log", 0, -1))
    if rerr == redis.ErrNil {
      portal_events = []string{}
    } else if rerr != nil {
      panic(rerr)
    }

    events_list = append(events_list, portal_events...)

    out["events"] = events_list

  } else if action == "get_auditlog" {
    if !is_voucher_admin && !is_login_admin {
      panic("No access")
    }

    once.Do(func() {
      globalMutex.Unlock()
    })

    var red redis.Conn
    var rerr error

    red, rerr = RedisCheck(red, "unix", config.Redis_socket, config.Redis_db)
    if rerr != nil { panic(rerr) }

    var events_list []string

    events_list, rerr = redis.Strings(red.Do("LRANGE", config.Redis_prefix + "audit_log", 0, -1))
    if rerr == redis.ErrNil {
      events_list = []string{}
    } else if rerr != nil {
      panic(rerr)
    }

    out["events"] = events_list

  } else if action == "del_iot" {
    if !is_login_admin {
      panic("No access")
    }

    if !q.Evs("mac") { panic("params missing error") }

    mac := FormatMAC(q.Vs("mac"))

    if mac == "" { panic("bad mac") }

    if !iots.EvM(mac) { panic("Not exists") }

    prev := iots.VM(mac).Copy()

    delete(iots, mac)

    redis_log("audit_log", config.Audit_log_size, M{
      "time": now,
      "action": action,
      "user_login": user_login,
      "user_name": user_name,
      "user_ip": user_ip,
      "mac": mac,
      "prev": prev,
    })

    out["done"] = 1
    
  } else if action == "add_iot" {
    if !is_login_admin {
      panic("No access")
    }

    if !q.Evs("mac") { panic("params missing error") }
    if !q.Evs("prev_mac") { panic("params missing error") }
    if !q.Evs("descr") { panic("params missing error") }
    if !q.Evs("level") { panic("params missing error") }
    if !q.Evi("disabled") { panic("params missing error") }
    if !q.Evi("until") { panic("params missing error") }

    mac := FormatMAC(q.Vs("mac"))
    prev_mac := FormatMAC(q.Vs("prev_mac"))

    if mac == "" { panic("bad mac") }
    if q.Vs("prev_mac") != "" && prev_mac == "" { panic("bad prev_mac") }

    if q.Vi("disabled") != 0 && q.Vi("disabled") != 1 { panic("Bad disabled") }
    if q.Vi("until") < 0 { panic("Bad until") }

    if prev_mac == "" && iots.EvM(mac) { panic("Already exists") }

    if prev_mac != "" && !iots.EvM(prev_mac) { panic("Prev mac does not exists") }

    if prev_mac != "" && prev_mac != mac && iots.EvM(mac) { panic("Already exists") }

    level := q.Vs("level")
    if _, ex := config.Levels[level]; !ex && level != "" { panic("No such level") }

    if prev_mac != "" {
      delete(iots, prev_mac)
    }

    iots[mac] = M{
      "mac": mac,
      "descr": q.Vs("descr"),
      "disabled": q.Vi("disabled"),
      "level": q.Vs("level"),
      "until": q.Vi("until"),
      "added": now,
      "added_by_user_login": user_login,
      "added_by_user_name": user_name,
    }

    out["row"] = iots.VM(mac)

    redis_log("audit_log", config.Audit_log_size, M{
      "time": now,
      "action": action,
      "user_login": user_login,
      "user_name": user_name,
      "user_ip": user_ip,
      "mac": mac,
      "iot": out["row"],
    })


  } else if action == "list_iots" {
    if !is_login_admin {
      panic("No access")
    }

    iots_list := iots.Keys()

    //sort somehow

    if true {
      sort.Sort(ByNum(iots_list))
    }

    out_iots := make([]M, 0)

    for _, iot := range iots_list {
      out_iots = append(out_iots, iots.VM(iot).Copy() )
    }

    out["iots"] = out_iots


    out["total"] = len(iots_list)

  } else {
    panic("unknown action: "+action)
  }

OUT:

  ok_out := make(M)
  ok_out["ok"] = out
  json, jerr := json.MarshalIndent(ok_out, "", "  ")
  if jerr != nil {
    panic(jerr)
  }

  once.Do(func() {
    globalMutex.Unlock()
  })

  w.Header().Set("Content-Type", "text/javascript; charset=UTF-8")
  w.Header().Set("Cache-Control", "no-cache")
  w.Header().Set("Access-Control-Allow-Origin", "*")
  w.Header().Set("Access-Control-Allow-Methods", "*")
  w.Header().Set("Access-Control-Allow-Headers", "*")
  w.WriteHeader(http.StatusOK)

  w.Write(json)
  w.Write([]byte("\n"))
}
