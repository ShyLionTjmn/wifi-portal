package main

import (
  "fmt"
  "strings"
  "strconv"
  "sync"
  "time"
  "crypto/tls"
  . "github.com/ShyLionTjmn/m"
  ldap "github.com/go-ldap/ldap/v3"
  "github.com/pquerna/otp/totp"
)

func user_sync(stop chan string, wg *sync.WaitGroup) {
  defer wg.Done()

  if config.Ldap_uri == "" ||
     config.Ldap_user == "" ||
     config.Ldap_search_base == "" ||
  false {
    return
  }

  once_timer := sync.Once{}

  USER_SYNC_LOOP:
  for {

    sleep_time := time.Duration(config.Ldap_sync_period) * time.Second

    once_timer.Do(func() {
      sleep_time = 0
    })

    timer := time.NewTimer(sleep_time)
    select {
    case <-stop:
      timer.Stop()
      break USER_SYNC_LOOP
    case <-timer.C:
    }

    ldapSync()
  }
}

func ldapSync() {
  var err error
  var l *ldap.Conn

  defer func() {
    if r := recover(); r != nil {
      switch v := r.(type) {
      case string:
        fmt.Println("LDAP sync error: " + v)
      case error:
        fmt.Println("LDAP sync error: " + v.Error())
      default:
        fmt.Println("LDAP sync error: unknown error type")
      }
    }
  } ()

  l, err = ldap.DialURL(config.Ldap_uri)
  if err != nil { panic(err) }
  defer l.Close()

  l.SetTimeout(time.Duration(config.Ldap_timeout) * time.Second)

  err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
  if err != nil { panic(err) }

  err = l.Bind(config.Ldap_user, config.Ldap_password)
  if err != nil { panic(err) }

  searchRequest := ldap.NewSearchRequest(
    config.Ldap_search_base,
    ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
    config.Ldap_users_query,
    []string{"dn", "displayName", "memberOf", "userAccountControl", "samAccountName", "mobile", "mail"},
    nil,
  )

  var sr *ldap.SearchResult

  sr, err = l.SearchWithPaging(searchRequest, config.Ldap_page_size)
  if err != nil { panic(err) }

  globalMutex.Lock()
  defer globalMutex.Unlock()

  now_time := time.Now()
  now := now_time.Unix()

  for _, entry := range sr.Entries {
    user_groups := []string{}
    uac := int64(0)
    var mail string
    var mobile string
    var login string
    var name string

    for _, attr := range entry.Attributes {
      for _, value := range attr.Values {
        switch strings.ToLower(attr.Name) {
        case "memberof":
          if ldap_groups_reg.MatchString(value) &&
          true {
            user_groups = append(user_groups, value)
          }
        case "useraccountcontrol":
          uac, _ = strconv.ParseInt(value, 10, 64)
        case "mail":
          mail = value
        case "displayname":
          name = value
        case "mobile":
          mobile = value
        case "samaccountname":
          login = strings.ToLower(value)
        }
      }
    }

    if login != "" && uac != 0 && len(user_groups) > 0 &&
       name != "" &&
    true {
      // user is valid for authentication
      user_row := M{
        "dn": entry.DN,
        "time": now,
        "login": login,
        "mobile": mobile,
        "mail": mail,
        "groups": user_groups,
        "uac": uac,
        "name": name,
        "enabled": int64(1),
      }

      if ldap_users.EvM(login) {
        user_row["added"] = ldap_users.Vs(login, "added")

        if ldap_users.Evs(login, "totp_uri") {
          user_row["totp_uri"] = ldap_users.Vs(login, "totp_uri")
          user_row["totp_created"] = ldap_users.Vi(login, "totp_created")
        }
      } else {
        user_row["added"] = now
      }

      ldap_users[login] = user_row
    }
  }

  for login, _ := range ldap_users {
    if ldap_users.Vi(login, "time") != now &&
       ldap_users.Vi(login, "enabled") == 1 &&
    true {
      // account does not match criteria
      ldap_users.VM(login)["enabled"] = int64(0)
      ldap_users.VM(login)["disabled"] = now
      delete(ldap_users.VM(login), "groups")
      delete(ldap_users.VM(login), "totp_uri")

      if login_devices.EvM(login, "devs") {
        for sta_id, _ := range login_devices.VM(login, "devs") {
          if auth_cache.EvM(sta_id) && auth_cache.Vs(sta_id, "login") == login {
            delete(auth_cache, sta_id)
          }
        }
      }
    }
    if ldap_users.Vi(login, "time") == now &&
       !ldap_users.Evs(login, "totp_uri") &&
    true {
      totp_key, kerr := totp.Generate(totp.GenerateOpts{
        Issuer: config.Totp_issuer,
        AccountName: login,
      })

      if kerr == nil {
        ldap_users.VM(login)["totp_uri"] = totp_key.URL()
        ldap_users.VM(login)["totp_created"] = now
      }

    }
  }
}
