package main

import (
  "fmt"
  "time"
  "errors"
  "context"
  "sync"
  "os"
  "strings"
  "strconv"
  "net"
  "runtime/debug"
  "encoding/json"
  "regexp"
  "encoding/base64"
  "bytes"
  "image"
  "image/png"
  //"reflect"
  "sort"
  "net/http"
  "net/url"
  "golang.org/x/net/netutil"
  "github.com/fatih/color"
  "github.com/rohanthewiz/element"
  "crypto/tls"
  ldap "github.com/go-ldap/ldap/v3"
  "github.com/gomodule/redigo/redis"
  "github.com/wneessen/go-mail"
  "github.com/pquerna/otp/totp"
  "github.com/pquerna/otp"
  . "github.com/ShyLionTjmn/m"
  . "github.com/ShyLionTjmn/mygolib"
)

const PE = "Backend Program error"

const LDAP_BAD_LOGIN_PASS = "Ldap bad login pass"
const TOTP_BAD_CODE = "Bad TOTP Code"

var epoch = time.Unix(0, 0).Format(time.RFC1123)

var remote_addr_reg *regexp.Regexp
var random_reg *regexp.Regexp
var page_split_reg *regexp.Regexp
var spaces_reg *regexp.Regexp
var ip_reg *regexp.Regexp
var mac_reg *regexp.Regexp
var num_reg *regexp.Regexp
var site_uri_reg *regexp.Regexp
var template_reg *regexp.Regexp


type Msg struct {
  *M
}

func (msg *Msg) Msg(key ... string) string {
  if msg.Evs(key...) { return msg.Vs(key...) }
  return "unknown_" + strings.Join(key, "_")
}

var noCacheHeaders = map[string]string{
  "Expires":         epoch,
  "Cache-Control":   "no-cache, private, max-age=0",
  "Pragma":          "no-cache",
  "X-Accel-Expires": "0",
}

var etagHeaders = []string{
  "ETag",
  "If-Modified-Since",
  "If-Match",
  "If-None-Match",
  "If-Range",
  "If-Unmodified-Since",
}

func NoCache(h http.Handler) http.Handler {
  fn := func(w http.ResponseWriter, r *http.Request) {

    if r.RequestURI == "/" {
      // Delete any ETag headers that may have been set
      for _, v := range etagHeaders {
        if r.Header.Get(v) != "" {
          r.Header.Del(v)
        }
      }

      // Set our NoCache headers
      for k, v := range noCacheHeaders {
        w.Header().Set(k, v)
      }

      //w.Header().Add("X-Debug-RequestURI", r.RequestURI)
    }

    h.ServeHTTP(w, r)
  }

  return http.HandlerFunc(fn)
}

// Locked by globalMutex
var templates_cache M

func init() {
  _ = errors.New("")
  remote_addr_reg = regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+$`)
  ip_reg = regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$`)
  mac_reg = regexp.MustCompile(`^([0-9a-fA-F]{2})[\-:\.]?([0-9a-fA-F]{2})[\-:\.]?([0-9a-fA-F]{2})[\-:\.]?([0-9a-fA-F]{2})[\-:\.]?([0-9a-fA-F]{2})[\-:\.]?([0-9a-fA-F]{2})$`)
  random_reg = regexp.MustCompile(`^[0-9a-fA-F][1235679abdefABDEF]`)
  page_split_reg = regexp.MustCompile(`%[0-9a-zA-Z_\-\.]+%`)
  spaces_reg = regexp.MustCompile(`\s+`)
  num_reg = regexp.MustCompile(`^\d+$`)
  site_uri_reg = regexp.MustCompile(`^/unifi/([a-zA-Z0-9]+)/$`)

  template_reg = regexp.MustCompile(`^[0-9a-zA-Z_\-]+$`)

  templates_cache = M{}
}

func getFile(filename string) (string, error) {
  if !templates_cache.EvM(filename) ||
    (templates_cache.Vi(filename, "time") + config.File_cache_time) < time.Now().Unix() ||
  false {
    b, err := os.ReadFile(filename)
    if err != nil { return "", err }
    templates_cache[filename] = M{ "contents": string(b), "time": time.Now().Unix() }
  }

  return templates_cache.Vs(filename, "contents"), nil
}

func containsDotFile(name string) bool {
    parts := strings.Split(name, "/")
    for _, part := range parts {
        if strings.HasPrefix(part, ".") {
            return true
        }
    }
    return false
}

type dotFileHidingFileSystem struct {
    http.FileSystem
}

type dotFileHidingFile struct {
    http.File
}

func (fsys dotFileHidingFileSystem) Open(name string) (http.File, error) {
    if containsDotFile(name) { // If dot file, return 403 response
        return nil, errors.New("No permission")
    }

    file, err := fsys.FileSystem.Open(name)
    if err != nil {
        return nil, err
    }
    return dotFileHidingFile{file}, err
}

func http_server(stop chan string, wg *sync.WaitGroup) {
  defer wg.Done()
  s := &http.Server{}

  fmt.Println("HTTP starting")

  server_shut := make(chan struct{})

  go func() {
    <-stop
    //if opt_v > 0 {
      fmt.Println("Shutting down HTTP server")
    //}
    ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(500 * time.Millisecond))
    defer cancel()

    shut_err := s.Shutdown(ctx)
    if shut_err != nil {
      if opt_v > 0 {
        color.Red("HTTP server Shutdown error: %v\n", shut_err)
      }
    }
    close(server_shut)
  }()

  fsys := dotFileHidingFileSystem{http.Dir(config.Www_root)}

  http.HandleFunc("/", handleRoot)
  http.HandleFunc("/unifi/", handleUnifi)
  http.HandleFunc("/headers", handleHeaders)
  http.HandleFunc("/session/", handlePortalTemplate)
  http.Handle("/admin/", NoCache(http.StripPrefix("/admin/", http.FileServer(fsys))))
  http.HandleFunc("/admin/ajax", handleAjax)
  http.HandleFunc("/admin/consts.js", handleConsts)

  http.HandleFunc("/pages", handlePages)
  http.HandleFunc("/static/", handleStatic)

  listener, listen_err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", config.Www_port))
  if listen_err != nil {
    panic("Listening error: "+listen_err.Error())
  }

  defer listener.Close()

  listener = netutil.LimitListener(listener, 100)
  http_err := s.Serve(listener)
  if http_err != http.ErrServerClosed {
    if opt_v > 0 {
      color.Red("HTTP server shot down with error: %s", http_err)
    }
  }
  select {
  case <-server_shut:
  }
}

func location(loc string, w http.ResponseWriter) {
  w.Header().Set("Content-Type", "text/html; charset=UTF-8")
  w.Header().Set("Cache-Control", "no-cache")
  w.Header().Set("Access-Control-Allow-Origin", "*")
  w.Header().Set("Access-Control-Allow-Methods", "*")
  w.Header().Set("Access-Control-Allow-Headers", "*")
  w.Header().Set("Location", loc)
  w.WriteHeader(http.StatusFound)
}

func handle_error_html(r interface{}, w http.ResponseWriter, req *http.Request) {
  if r == nil {
    return
  }

  w.Header().Set("Content-Type", "text/html; charset=UTF-8")
  w.Header().Set("Cache-Control", "no-cache")
  w.Header().Set("Access-Control-Allow-Origin", "*")
  w.Header().Set("Access-Control-Allow-Methods", "*")
  w.Header().Set("Access-Control-Allow-Headers", "*")
  w.WriteHeader(http.StatusOK)

  b := element.NewBuilder()
  e := b.Ele
  t := b.Text

  _ = b.WriteString("<!DOCTYPE html>\n")
  e("html", "lang", "en").R(
    e("head").R(
      e("title").R(t(`Portal Error`)),
      e("meta", "charset", "UTF-8"),
      e("meta", "http-equiv", "Cache-control", "content", "no-cache"),
      e("link", "rel", "icon", "href", "data:,"),
    ),
    e("body").R(
      func() (_ any) {
        switch v := r.(type) {
        case string:
          e("div").R(
            t(v),
          )
        case error:
          e("div").R(
            t(v.Error()),
          )
          e("div").R(
            e("pre").R(
              t(string(debug.Stack())),
            ),
          )
        case M:
          e("div").R(
            e("pre").R(
              t(v.ToJsonStr(true)),
            ),
          )
        default:
          e("div").R(
            t("Unknown error"),
          )
          e("div").R(
            e("pre").R(
              t(string(debug.Stack())),
            ),
          )
        }
        return
      } (),
    ),
  )

  w.Write([]byte(b.String()))
  w.Write([]byte("\n"))


  return
}

func handle_error_json(r interface{}, w http.ResponseWriter, req *http.Request) {
  if r == nil {
    return
  }

  w.Header().Set("Content-Type", "text/javascript; charset=UTF-8")
  w.Header().Set("Cache-Control", "no-cache")
  w.Header().Set("Access-Control-Allow-Origin", "*")
  w.Header().Set("Access-Control-Allow-Methods", "*")
  w.Header().Set("Access-Control-Allow-Headers", "*")
  w.WriteHeader(http.StatusOK)

  var out M

  switch v := r.(type) {
  case string:
    out = make(M)
    out["error"] = "Server message:\n"+v;
    if v == PE {
      out["error"] = out["error"].(string) + "\n\n" + string(debug.Stack())
    }
  case error:
    out = make(M)
    out["error"] = v.Error() + "\n\n" + string(debug.Stack())
  case M:
    out = v
  default:
    out = make(M)
    out["error"] = "Unknown error\n\n" + string(debug.Stack())
  }

  json, jerr := json.MarshalIndent(out, "", "  ")
  if jerr != nil {
    panic(jerr)
  }

  w.Write(json)
  w.Write([]byte("\n"))
  return
}

func handleRoot(w http.ResponseWriter, req *http.Request) {
  if req.Method == "OPTIONS" {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "*")
    w.Header().Set("Access-Control-Allow-Headers", "*")
    w.WriteHeader(http.StatusOK)
    return
  }

  //fmt.Println(req)
}

func handleHeaders(w http.ResponseWriter, req *http.Request) {
  if req.Method == "OPTIONS" {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "*")
    w.Header().Set("Access-Control-Allow-Headers", "*")
    w.WriteHeader(http.StatusOK)
    return
  }
  w.Header().Set("Content-Type", "text/javascript; charset=UTF-8")
  w.Header().Set("Cache-Control", "no-cache")
  w.Header().Set("Access-Control-Allow-Origin", "*")
  w.Header().Set("Access-Control-Allow-Methods", "*")
  w.Header().Set("Access-Control-Allow-Headers", "*")
  w.WriteHeader(http.StatusOK)

  b := element.NewBuilder()
  e := b.Ele
  t := b.Text


  _ = b.WriteString("<!DOCTYPE html>\n")
  e("html", "lang", "en").R(
    e("head").R(
      e("title").R(t(`Headers`)),
      e("meta", "charset", "UTF-8"),
      e("meta", "http-equiv", "Cache-control", "content", "no-cache"),
      e("link", "rel", "icon", "href", "data:,"),
    ),
    e("body").R(
      e("pre").R(
        func() (_ any) {
          for header, values := range req.Header {
            for _, value := range values {
              t(header)
              t(": ")
              t(value)
              t("\n")
            }
          }
          return
        } (),
      ),
    ),
  )

  w.Write([]byte(b.String()))
  w.Write([]byte("\n"))
}

func rateCheck(ip string) bool {
  // TODO requests rate check
  return true
}

func sendSMS(phone, code string) error {

  if config.Sms_queue_dir == "" {
    return errors.New("No sms queue dir in config")
  }

  now := time.Now()

  now_sec := now.Unix()

  now_mic := now.UnixMicro() % 1000000

  filename := fmt.Sprintf("%s/%d.%06d", config.Sms_queue_dir, now_sec, now_mic)

  msg := phone + "\n" + "WiFi code: " + code

  err := os.WriteFile(filename, []byte(msg), 0660)

  return err
}

func totpAuth(password, uri string) error {
  var key *otp.Key
  var err error

  if uri == "" { return errors.New(TOTP_BAD_CODE) }

  key, err = otp.NewKeyFromURL(uri)
  if err != nil { return err }

  var code_ok bool

  code_ok = totp.Validate(password, key.Secret() )

  if code_ok { return nil }

  return errors.New(TOTP_BAD_CODE)
}

func ldapAuth(login, password string) error {
  var err error
  var l *ldap.Conn

  l, err = ldap.DialURL(config.Ldap_uri)
  if err != nil { return err }

  defer l.Close()

  l.SetTimeout(time.Duration(config.Ldap_timeout) * time.Second)

  err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
  if err != nil { return err }

  ldap_login := login
  if config.Ldap_domain != "" {
    ldap_login += "@" + config.Ldap_domain
  }

  err = l.Bind(ldap_login, password)

  if err != nil {
    if ldap.IsErrorAnyOf(err,
       ldap.LDAPResultInvalidCredentials,
       ldap.LDAPResultInsufficientAccessRights,
       ldap.LDAPResultAuthorizationDenied,
    ) {
      return errors.New(LDAP_BAD_LOGIN_PASS)
    }

    return err
  }

  return nil
}

func handlePortalTemplate(w http.ResponseWriter, req *http.Request) {
  if req.Method == "OPTIONS" {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "*")
    w.Header().Set("Access-Control-Allow-Headers", "*")
    w.WriteHeader(http.StatusOK)
    return
  }

  defer func() { handle_error_html(recover(), w, req) } ()

  // find user session

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

  var C M = M{}

  var page string

  sess_info := M{}

  once := &sync.Once{}

  now := time.Now().Unix()
  now_str := fmt.Sprint(now)
  _ = now_str

  globalMutex.Lock()

  defer func() {
    once.Do(func() {
      globalMutex.Unlock()
    })
  } ()

  var sess_id string
  var sess_update int64

  for _sess_id, _ := range sessions {
    if sessions.Vs(_sess_id, "sta_ip") == user_ip {
      _sess_update := sessions.Vi(_sess_id, "acct_update")
      if sess_id != "" {
        if _sess_update > sess_update {
          sess_id = _sess_id
          sess_update = _sess_update
        }
      } else {
        sess_id = _sess_id
        sess_update = _sess_update
      }
    }
  }

  if sess_id == "" {
    panic("Cannot find user session for " + user_ip)
  }

  sta_id := sessions.Vs(sess_id, "sta_id")

  is_random := random_reg.MatchString(sta_id)

  if is_random {
    C["random"] = "shown"
  } else {
    C["random"] = "hidden"
  }

  lang := req.FormValue("lang")
  if lang == "" {
    lang = config.Default_lang
  }

  C["refresh_delay"] = "1"

  messages_file := config.Templates_dir + "/" + config.Template + "/messages.json"
  messages_json, _ := getFile(messages_file)
  if messages_json == "" {
    panic("Cannot load messages file: " + messages_file)
  }

  var messages M
  if jerr := messages.UnmarshalJSON([]byte(messages_json)); jerr != nil { panic(jerr) }

  if !messages.EvM(lang) {
    lang = "ru"
  }

  msg := Msg{&messages}

  if config.Prohibit_random != 0 {
    C["random_body"] = msg.Msg(lang, "random_body_prohibited")
  } else {
    C["random_body"] = msg.Msg(lang, "random_body")
  }

  var auth_method string
  req_auth_method := req.FormValue("auth_method")

  if req_auth_method == "sms" && config.Allow_sms != 1 { panic("Auth method not allowed") }
  if req_auth_method == "voucher" && config.Allow_voucher != 1 { panic("Auth method not allowed") }
  if req_auth_method == "login" && config.Allow_login != 1 { panic("Auth method not allowed") }
  if req_auth_method == "2fa" && config.Allow_2fa != 1 { panic("Auth method not allowed") }
  if req_auth_method == "totp" && config.Allow_totp != 1 { panic("Auth method not allowed") }

  if req_auth_method == "reset" {

    if auth_cache.EvM(sta_id) {
      delete(auth_cache, sta_id)
    }
    sessions.VM(sess_id)["next_state"] = "drop"
    sessions.VM(sess_id)["coa_state"] = "drop"
    if sessions.Vs(sess_id, "coa_sent_state") != "drop" {
      ch_coa <- sess_id
    }

    C["message"] = msg.Msg(lang, "disconnect_soon")
    C["message_class"] = "shown"
    page = "disconnect"

    redis_log("portal_log", config.Portal_log_size, M{
      "time": now,
      "event": "reset",
      "sta_id": sta_id,
      "session": sessions.VM(sess_id).Copy(),
    })

    goto RENDER_PAGE
  }

  if !sessions.Evs(sess_id, "auth_method") ||
     sessions.Vs(sess_id, "auth_method") == "" ||
  false {
    if req_auth_method == "2fa" ||
       req_auth_method == "sms" ||
       req_auth_method == "login" ||
       req_auth_method == "voucher" ||
       req_auth_method == "totp" ||
    false {
      auth_method = req_auth_method
      sessions.VM(sess_id)["auth_method"] = auth_method
    }
  } else {
    auth_method = sessions.Vs(sess_id, "auth_method")
  }

  C["message_class"] = "hidden"

  C["debug_code"] = ""
  //C["debug_code"] = sessions.Vs(sess_id, "code") // TODO REMOVE

  if sessions.Evi(sess_id, "authenticated") {
    if sessions.Vs(sess_id, "next_state") == "run" || sessions.Vs(sess_id, "state") == "run" {
      C["message"] = msg.Msg(lang, "authorized_wait")
      C["message_class"] = "shown"
      page = "authorized"

      if sessions.Evs(sess_id, "unifi") && sessions.EvM(sess_id, "unifi_session") &&
         sessions.EvA(sess_id, "unifi_session", "authorized") &&
         !sessions.VA(sess_id, "unifi_session", "authorized").(bool) &&
         sessions.Vs(sess_id, "state") != "run" &&
      true {
        sessions.VM(sess_id)["coa_state"] = "update_" + now_str
        ch_coa <- sess_id
      }
      goto RENDER_PAGE
    }

    login := sessions.Vs(sess_id, "login")
    devs_allowed := config.Devs_allowed_per_login
    if login_devices.Evi(login, "allowed") {
      devs_allowed = login_devices.Vi(login, "allowed")
    }

    if devs_allowed == 0 {
      C["message"] = msg.Msg(lang, "zero_allowed")
      C["message_class"] = "shown_error"
      page = "message"
      goto RENDER_PAGE
    }

    replaceable_list := []string{}

    devs_count := int64(0)

    dev_in_list := false

    if login_devices.EvM(login, "devs") {
      for dev_mac, _ := range login_devices.VM(login, "devs") {
        if dev_mac == sta_id {
          dev_in_list = true
          break
        }
        devs_count ++
        if login_devices.Vi(login, "devs", dev_mac, "swap_from") + config.Min_dev_swap_period < now {
          replaceable_list = append(replaceable_list, dev_mac)
        }
      }
    }

    if !dev_in_list && config.Prohibit_random != 0 && is_random {
      C["message"] = msg.Msg(lang, "random_prohibited")
      C["message_class"] = "shown_error"
      page = "message"
      goto RENDER_PAGE
    }

    if dev_in_list || devs_count < devs_allowed {
      if !dev_in_list {

        if !login_devices.EvM(login) { login_devices[login] = M{} }
        if !login_devices.EvM(login, "devs") { login_devices.VM(login)["devs"] = M{} }
        if !login_devices.EvM(login, "devs", sta_id) {
          new_dev := M{"added": now, "swap_from": now}
          if config.DPSK_length > 0 && config.DPSK_dict != "" {
            new_dev["dpsk"] = KeyGenDict([]rune(config.DPSK_dict), int(config.DPSK_length))
          }
          login_devices.VM(login, "devs")[sta_id] = new_dev
        }
      }

      var level string
      switch sessions.Vs(sess_id, "auth_method") {
      case "login":
        level = config.Default_level_login
      case "sms":
        level = config.Default_level_sms
      case "2fa":
        level = config.Default_level_2fa
      case "totp":
        level = config.Default_level_login
      default:
        panic("bad auth_method")
      }

      if login_devices.Evs(login, "devs", sta_id, "level") {
        level = login_devices.Vs(login, "devs", sta_id, "level")
      }

      auth_cache[sta_id] = M{
        "time": now, "login": login, "level": level,
        "username": ldap_users.Vs(login, "name"),
        "auth_method": sessions.Vs(sess_id, "auth_method"),
      }
      sessions.VM(sess_id)["coa_state"] = "update_" + now_str
      sessions.VM(sess_id)["next_state"] = "run"
      sessions.VM(sess_id)["level"] = level

      login_devices.VM(login, "devs", sta_id)["last_portal_logon"] = now

      ch_coa <- sess_id

      C["message"] = msg.Msg(lang, "authorized_wait")
      C["message_class"] = "shown"
      page = "authorized"

      redis_log("portal_log", config.Portal_log_size, M{
        "time": now,
        "event": "auth",
        "sta_id": sta_id,
        "session": sessions.VM(sess_id).Copy(),
      })

      goto RENDER_PAGE
    }

    if len(replaceable_list) == 0 {
      C["message"] = msg.Msg(lang, "too_early_for_swap")
      C["message_class"] = "shown_error"
      page = "message"
      goto RENDER_PAGE
    }

    swap_mac := req.FormValue("swap_mac")

    if swap_mac != "" {
      swap_in_list := false
      for _, dev_mac := range replaceable_list {
        if dev_mac == swap_mac {
          swap_in_list = true
          break
        }
      }

      if swap_in_list {
        var level string
        switch sessions.Vs(sess_id, "auth_method") {
        case "login":
          level = config.Default_level_login
        case "sms":
          level = config.Default_level_sms
        case "2fa":
          level = config.Default_level_2fa
        case "totp":
          level = config.Default_level_login
        default:
          panic("bad auth_method")
        }

        prev_level := ""
        if login_devices.Evs(login, "devs", swap_mac, "level") {
          level = login_devices.Vs(login, "devs", swap_mac, "level")
          prev_level = level
        }

        delete(auth_cache, swap_mac)
        delete(login_devices.VM(login)["devs"].(M), swap_mac)

        new_dev := M{"added": now, "swap_from": now}
        if config.DPSK_length > 0 && config.DPSK_dict != "" {
          new_dev["dpsk"] = KeyGenDict([]rune(config.DPSK_dict), int(config.DPSK_length))
        }
        login_devices.VM(login, "devs")[sta_id] = new_dev

        if prev_level != "" {
          login_devices.VM(login, "devs", sta_id)["level"] = prev_level
        }

        auth_cache[sta_id] = M{
          "time": now, "login": login, "level": level,
          "username": ldap_users.Vs(login, "name"),
          "auth_method": sessions.Vs(sess_id, "auth_method"),
        }
        sessions.VM(sess_id)["coa_state"] = "update_" + now_str
        sessions.VM(sess_id)["next_state"] = "run"
        sessions.VM(sess_id)["level"] = level

        login_devices.VM(login, "devs", sta_id)["last_portal_logon"] = now

        ch_coa <- sess_id

        C["message"] = msg.Msg(lang, "authorized_wait")
        C["message_class"] = "shown"
        page = "authorized"

        redis_log("portal_log", config.Portal_log_size, M{
          "time": now,
          "event": "auth_swap",
          "from": swap_mac,
          "sta_id": sta_id,
          "session": sessions.VM(sess_id).Copy(),
        })

        goto RENDER_PAGE

      }
    }

    // let user select device to replace

    page = "swap_mac"

    sort.Sort(ByNum(replaceable_list))

    b := element.NewBuilder()
    e := b.Ele
    t := b.Text

    for i, dev_mac := range replaceable_list {

      m := mac_reg.FindStringSubmatch(dev_mac)
      oui := strings.ToLower(strings.Join(m[1:4], ""))

      var vendor string
      var vendor_class string
      if random_reg.MatchString(dev_mac) {
        vendor = msg.Msg(lang, "random_mac")
        vendor_class = msg.Msg(lang, "random_mac_class")
      } else {


        vendor_name, ex := vendors[oui]

        if !ex {
          vendor_name = "Unknown"
        }


        vendor = msg.Msg(lang, "vendor") + vendor_name
        vendor_class = msg.Msg(lang, "factory_mac_class")
      }

      e("div", "class", "mac_row").R(
        e("div", "class", "mac_radio_row").R(
          e("input", "type", "radio", "name", "swap_mac", "value", dev_mac, "id", "mac_" + fmt.Sprint(i)),
          e("label", "class", "mac_label", "for", "mac_" + fmt.Sprint(i)).R(
            t(dev_mac),
          ),
        ),
        func() (_ any) {
          if login_devices.Evs(login, "devs", dev_mac, "name") {
            e("div", "class", "mac_name_row ").R(
              t(msg.Msg(lang, "dev_name") + login_devices.Vs(login, "devs", dev_mac, "name")),
            )
          }
          return
        } (),
        e("div", "class", "mac_vendor_row " + vendor_class).R( t(vendor) ),
        e("div", "class", "mac_added_row ").R(
          t(msg.Msg(lang, "added") +
            time.Unix( login_devices.Vi(login, "devs", dev_mac, "added"), 0 ).Format(time.DateTime),
          ),
        ),
        e("div", "class", "mac_last_use_row ").R(
          t(msg.Msg(lang, "last_use") +
            time.Unix( login_devices.Vi(login, "devs", dev_mac, "last_portal_logon"), 0 ).Format(time.DateTime),
          ),
        ),
      )
    }

    C["macs_list"] = b.String()

    goto RENDER_PAGE
  }

  C["message"] = ""
  C["message_class"] = "hidden"

  if auth_method == "sms" {

    if sessions.EvA(sess_id, "sms_in_progress") {
      page = "refresh"
      C["message"] = msg.Msg(lang, "sms_in_progress")
      C["message_class"] = "shown"
      C["lang"] = lang
      goto RENDER_PAGE
    }


    C["show_phone_div"] = "hidden"
    C["show_code_div"] = "hidden"

    code := req.FormValue("code")
    phone := req.FormValue("phone")
    phone = spaces_reg.ReplaceAllString(phone, "")

    if !sessions.Evs(sess_id, "phone") {
      if phone_reg.MatchString(phone) {

        if !rateCheck(user_ip) {
          panic("Too many requests")
        }

        found_login := ""
        found_username := ""
        found_count := 0
        for login, _ := range ldap_users {
          if ldap_users.Vi(login, "enabled") == 1 &&
             ldap_users.Vs(login, "mobile") == phone &&
          true {

            devs_allowed := config.Devs_allowed_per_login

            if login_devices.Evi(login, "allowed") {
              devs_allowed = login_devices.Vi(login, "allowed")
            }

            if devs_allowed > 0 {
              found_count ++
              if found_count > 1 { break }
              found_login = login
              found_username = ldap_users.Vs(login, "name")
            }
          }
        }

        if found_count > 1 {
          C["message"] = msg.Msg(lang, "too_many_devices_per_number")
          C["message_class"] = "shown_error"
          C["show_phone_div"] = "shown"
          page = "phone"

          redis_log("portal_log", config.Portal_log_size, M{
            "time": now,
            "event": "phone_fail",
            "reason": "too_many_per_phone",
            "phone": phone,
            "sta_id": sta_id,
            "session": sessions.VM(sess_id).Copy(),
          })

          goto RENDER_PAGE
        }

        if found_count == 0 {
          C["message"] = msg.Msg(lang, "number") + phone + msg.Msg(lang, "no_devices_per_number")
          C["message_class"] = "shown_error"
          C["show_phone_div"] = "shown"
          page = "phone"
          redis_log("portal_log", config.Portal_log_size, M{
            "time": now,
            "event": "phone_fail",
            "reason": "no_accounts_for_phone",
            "phone": phone,
            "sta_id": sta_id,
            "session": sessions.VM(sess_id).Copy(),
          })

          goto RENDER_PAGE
        }

        redis_log("portal_log", config.Portal_log_size, M{
          "time": now,
          "event": "sms_queued",
          "phone": phone,
          "sta_id": sta_id,
          "session": sessions.VM(sess_id).Copy(),
        })

        sessions.VM(sess_id)["sms_in_progress"] = int64(1)
        sessions.VM(sess_id)["username"] = found_username

        go func() {
          err := sendSMS(phone, sessions.Vs(sess_id, "code"))
          globalMutex.Lock()
          defer globalMutex.Unlock()

          delete(sessions.VM(sess_id), "sms_in_progress")

          if err != nil {
            sessions.VM(sess_id)["sms_error"] = msg.Msg(lang, "could_not_send_sms") + phone
          } else {
            delete(sessions.VM(sess_id), "sms_error")
            sessions.VM(sess_id)["phone"] = phone
            sessions.VM(sess_id)["sms_sent"] = now
            sessions.VM(sess_id)["login"] = found_login
          }
        } ()

        location("?lang="+lang, w)
        return

      } else {
        //no phone submitted yet
        page = "phone"
        if sessions.Evs(sess_id, "sms_error") {
          C["message"] = sessions.Vs(sess_id, "sms_error")
          C["message_class"] = "shown_error"
        }
        C["show_phone_div"] = "shown"
        goto RENDER_PAGE
      }
    } else {
      // session phone is set and SMS were sent
      if phone_reg.MatchString(phone) {
        if phone != sessions.Vs(sess_id, "phone") {
          panic("Session phone already set")
        }
      }

      failed_count := int64(0)

      if sessions.Evi(sess_id, "code_failed_count") {
        failed_count = sessions.Vi(sess_id, "code_failed_count")
      }

      if code != "" && code != sessions.Vs(sess_id, "code") {
        failed_count ++
        sessions.VM(sess_id)["code_failed_count"] = failed_count

        redis_log("portal_log", config.Portal_log_size, M{
          "time": now,
          "event": "bad_code",
          "count": failed_count,
          "sta_id": sta_id,
          "session": sessions.VM(sess_id).Copy(),
        })
      }


      if failed_count >= config.Max_sms_tries {
        page = "message"
        C["message"] = msg.Msg(lang, "too_many_code_tries")
        C["message_class"] = "shown_error"
        goto RENDER_PAGE
      }

      if code != "" {
        if code != sessions.Vs(sess_id, "code") {
          // bad code

          page = "phone"
          C["show_code_div"] = "shown"
          C["message"] = msg.Msg(lang, "wrong_code")
          C["message_class"] = "shown_error"

          goto RENDER_PAGE
          // bad code
        }
        // good code
        sessions.VM(sess_id)["authenticated"] = now
        sessions.VM(sess_id)["auth_source"] = "sms_code"
        location("?lang="+lang, w)

        redis_log("portal_log", config.Portal_log_size, M{
          "time": now,
          "event": "good_code",
          "sta_id": sta_id,
          "session": sessions.VM(sess_id).Copy(),
        })
        return
      }

      if !sessions.Evi(sess_id, "authenticated") {
        page = "phone"
        C["show_code_div"] = "shown"
        C["message"] = msg.Msg(lang, "sms_sent_to") + sessions.Vs(sess_id, "phone")
        C["message_class"] = "shown"

        goto RENDER_PAGE
      }
      //
    }
  } else if auth_method == "login" {

    if sessions.EvA(sess_id, "login_in_progress") {
      page = "refresh"
      C["message"] = msg.Msg(lang, "login_in_progress")
      C["message_class"] = "shown"
      C["lang"] = lang
      goto RENDER_PAGE
    }

    C["message"] = ""
    C["message_class"] = "hidden"

    if sessions.Evi(sess_id, "login_failures") &&
       sessions.Vi(sess_id, "login_failures") >= config.Max_login_failures &&
    true {
      C["message_class"] = "shown_error"
      C["message"] = msg.Msg(lang, "too_many_logon_attempts")
      page = "message"
      goto RENDER_PAGE
    }

    if sessions.Evi(sess_id, "login_failures") {
      C["message_class"] = "shown_error"
      C["message"] = msg.Msg(lang, "bad_login_password")
    }

    login := req.FormValue("login")
    login, _, _ = strings.Cut(login, "@")
    login = strings.ToLower(strings.TrimSpace(login))
    password := req.FormValue("password")

    if login == "" || password == "" {
      if sessions.Evs(sess_id, "login_error") {
        C["message_class"] = "shown_error"
        C["message"] = sessions.Vs(sess_id, "login_error")
      }
      page = "login"
      goto RENDER_PAGE
    }

    if !rateCheck(user_ip) {
      panic("Too many requests")
    }

    if !ldap_users.EvM(login) || ldap_users.Vi(login, "enabled") != 1 {
      C["message_class"] = "shown_error"
      C["message"] = msg.Msg(lang, "no_user_access")
      page = "login"

      redis_log("portal_log", config.Portal_log_size, M{
        "time": now,
        "event": "bad_login",
        "reason": "no_login_or_disabled",
        "login": login,
        "sta_id": sta_id,
        "session": sessions.VM(sess_id).Copy(),
      })
      goto RENDER_PAGE
    }

    redis_log("portal_log", config.Portal_log_size, M{
      "time": now,
      "event": "login_check",
      "login": login,
      "sta_id": sta_id,
      "session": sessions.VM(sess_id).Copy(),
    })

    username := ldap_users.Vs(login, "name")
    sessions.VM(sess_id)["username"] = username

    sessions.VM(sess_id)["login_in_progress"] = int64(1)

    go func() {

      err := ldapAuth(login, password)

      globalMutex.Lock()
      defer globalMutex.Unlock()

      delete(sessions.VM(sess_id), "login_in_progress")

      if err == nil {
        delete(sessions.VM(sess_id), "login_error")
        sessions.VM(sess_id)["authenticated"] = now
        sessions.VM(sess_id)["auth_source"] = "login"
        sessions.VM(sess_id)["login"] = login
      } else {
        if err.Error() == LDAP_BAD_LOGIN_PASS {
          fails := int64(0)
          if sessions.Evi(sess_id, "login_failures") {
            fails = sessions.Vi(sess_id, "login_failures")
          }
          fails ++
          sessions.VM(sess_id)["login_failures"] = fails
          sessions.VM(sess_id)["login_fail_time"] = now

          sessions.VM(sess_id)["login_error"] = msg.Msg(lang, "bad_login_password")

          redis_log("portal_log", config.Portal_log_size, M{
            "time": now,
            "event": "login_fail",
            "count": fails,
            "login": login,
            "sta_id": sta_id,
            "session": sessions.VM(sess_id).Copy(),
          })

        } else {
          sessions.VM(sess_id)["login_error"] = "LDAP Auth err: " + err.Error()

          redis_log("portal_log", config.Portal_log_size, M{
            "time": now,
            "event": "login_error",
            "error": err.Error(),
            "login": login,
            "sta_id": sta_id,
            "session": sessions.VM(sess_id).Copy(),
          })

        }
      }
    } ()

    location("?lang="+lang, w)
    return

  } else if auth_method == "totp" {

    if sessions.EvA(sess_id, "login_in_progress") {
      page = "refresh"
      C["message"] = msg.Msg(lang, "login_in_progress")
      C["message_class"] = "shown"
      C["lang"] = lang
      goto RENDER_PAGE
    }

    C["message"] = ""
    C["message_class"] = "hidden"

    if sessions.Evi(sess_id, "login_failures") &&
       sessions.Vi(sess_id, "login_failures") >= config.Max_login_failures &&
    true {
      C["message_class"] = "shown_error"
      C["message"] = msg.Msg(lang, "too_many_logon_attempts")
      page = "message"
      goto RENDER_PAGE
    }

    if sessions.Evi(sess_id, "login_failures") {
      C["message_class"] = "shown_error"
      C["message"] = msg.Msg(lang, "bad_login_password")
    }

    login := req.FormValue("login")
    login, _, _ = strings.Cut(login, "@")
    login = strings.ToLower(strings.TrimSpace(login))
    password := req.FormValue("totp_code")

    if login == "" || password == "" {
      if sessions.Evs(sess_id, "login_error") {
        C["message_class"] = "shown_error"
        C["message"] = sessions.Vs(sess_id, "login_error")
      }
      page = "totp"
      goto RENDER_PAGE
    }

    if !rateCheck(user_ip) {
      panic("Too many requests")
    }

    if !ldap_users.EvM(login) || ldap_users.Vi(login, "enabled") != 1 {
      C["message_class"] = "shown_error"
      C["message"] = msg.Msg(lang, "no_user_access")
      page = "totp"

      redis_log("portal_log", config.Portal_log_size, M{
        "time": now,
        "event": "bad_login",
        "reason": "no_login_or_disabled",
        "login": login,
        "sta_id": sta_id,
        "session": sessions.VM(sess_id).Copy(),
      })
      goto RENDER_PAGE
    }

    redis_log("portal_log", config.Portal_log_size, M{
      "time": now,
      "event": "totp_check",
      "login": login,
      "sta_id": sta_id,
      "session": sessions.VM(sess_id).Copy(),
    })

    username := ldap_users.Vs(login, "name")
    sessions.VM(sess_id)["username"] = username

    sessions.VM(sess_id)["login_in_progress"] = int64(1)

    totp_uri := ""
    if ldap_users.Evs(login, "totp_uri") {
      totp_uri = ldap_users.Vs(login, "totp_uri")
    }

    go func() {

      err := totpAuth(password, totp_uri)

      globalMutex.Lock()
      defer globalMutex.Unlock()

      delete(sessions.VM(sess_id), "login_in_progress")

      if err == nil {
        delete(sessions.VM(sess_id), "login_error")
        sessions.VM(sess_id)["authenticated"] = now
        sessions.VM(sess_id)["auth_source"] = "totp"
        sessions.VM(sess_id)["login"] = login
      } else {
        if err.Error() == TOTP_BAD_CODE {
          fails := int64(0)
          if sessions.Evi(sess_id, "login_failures") {
            fails = sessions.Vi(sess_id, "login_failures")
          }
          fails ++
          sessions.VM(sess_id)["login_failures"] = fails
          sessions.VM(sess_id)["login_fail_time"] = now

          sessions.VM(sess_id)["login_error"] = msg.Msg(lang, "bad_login_totp")

          redis_log("portal_log", config.Portal_log_size, M{
            "time": now,
            "event": "totp_fail",
            "count": fails,
            "login": login,
            "sta_id": sta_id,
            "session": sessions.VM(sess_id).Copy(),
          })

        } else {
          sessions.VM(sess_id)["login_error"] = "TOTP Auth err: " + err.Error()

          redis_log("portal_log", config.Portal_log_size, M{
            "time": now,
            "event": "totp_error",
            "error": err.Error(),
            "login": login,
            "sta_id": sta_id,
            "session": sessions.VM(sess_id).Copy(),
          })

        }
      }
    } ()

    location("?lang="+lang, w)
    return

  } else if auth_method == "2fa" {

    if sessions.EvA(sess_id, "sms_in_progress") {
      page = "refresh"
      C["message"] = msg.Msg(lang, "sms_in_progress")
      C["message_class"] = "shown"
      C["lang"] = lang
      goto RENDER_PAGE
    }

    if sessions.EvA(sess_id, "login_in_progress") {
      page = "refresh"
      C["message"] = msg.Msg(lang, "login_in_progress")
      C["message_class"] = "shown"
      C["lang"] = lang
      goto RENDER_PAGE
    }

    C["message"] = ""
    C["message_class"] = "hidden"

    C["show_code_div"] = "hidden"
    C["show_login_div"] = "hidden"

    if sessions.Evi(sess_id, "login_failures") &&
       sessions.Vi(sess_id, "login_failures") >= config.Max_login_failures &&
    true {
      C["message_class"] = "shown_error"
      C["message"] = msg.Msg(lang, "too_many_logon_attempts")
      page = "message"
      goto RENDER_PAGE
    }

    if sessions.Evi(sess_id, "login_failures") && !sessions.Evi(sess_id, "logged_in") {
      C["message_class"] = "shown_error"
      C["message"] = msg.Msg(lang, "bad_login_password")
    }

    login := req.FormValue("login")
    login, _, _ = strings.Cut(login, "@")
    login = strings.ToLower(strings.TrimSpace(login))
    password := req.FormValue("password")

    if !sessions.Evi(sess_id, "logged_in") {

      if !sessions.Evs(sess_id, "login") {
        if login == "" || password == "" {
          if sessions.Evs(sess_id, "sms_error") {
            C["message_class"] = "shown_error"
            C["message"] = sessions.Vs(sess_id, "sms_error")
          } else if sessions.Evs(sess_id, "login_error") {
            C["message_class"] = "shown_error"
            C["message"] = sessions.Vs(sess_id, "login_error")
          }
          C["show_login_div"] = "shown"
          page = "2fa"
          goto RENDER_PAGE
        }

        if !rateCheck(user_ip) {
          panic("Too many requests")
        }

        if !ldap_users.EvM(login) || ldap_users.Vi(login, "enabled") != 1 {
          C["show_login_div"] = "shown"
          C["message_class"] = "shown_error"
          C["message"] = msg.Msg(lang, "no_user_access")
          page = "2fa"

          redis_log("portal_log", config.Portal_log_size, M{
            "time": now,
            "event": "bad_login",
            "reason": "no_login_or_disabled",
            "login": login,
            "sta_id": sta_id,
            "session": sessions.VM(sess_id).Copy(),
          })
          goto RENDER_PAGE
        }

        if !ldap_users.Evs(login, "mobile") ||
           !phone_reg.MatchString(ldap_users.Vs(login, "mobile")) ||
        false {
          C["message_class"] = "shown_error"
          C["message"] = msg.Msg(lang, "no_user_mobile")
          C["show_login_div"] = "shown"
          page = "2fa"

          redis_log("portal_log", config.Portal_log_size, M{
            "time": now,
            "event": "bad_login",
            "reason": "no_login_mobile",
            "login": login,
            "sta_id": sta_id,
            "session": sessions.VM(sess_id).Copy(),
          })
          goto RENDER_PAGE
        }

        phone := ldap_users.Vs(login, "mobile")

        redis_log("portal_log", config.Portal_log_size, M{
          "time": now,
          "event": "login_check",
          "login": login,
          "sta_id": sta_id,
          "session": sessions.VM(sess_id).Copy(),
        })

        username := ldap_users.Vs(login, "username")
        sessions.VM(sess_id)["username"] = username

        sessions.VM(sess_id)["login_in_progress"] = int64(1)

        go func() {

          err := ldapAuth(login, password)

          globalMutex.Lock()
          defer globalMutex.Unlock()

          delete(sessions.VM(sess_id), "login_in_progress")

          if err == nil {
            delete(sessions.VM(sess_id), "login_error")
            sessions.VM(sess_id)["login"] = login
            sessions.VM(sess_id)["phone"] = phone
          } else {
            if err.Error() == LDAP_BAD_LOGIN_PASS {
              fails := int64(0)
              if sessions.Evi(sess_id, "login_failures") {
                fails = sessions.Vi(sess_id, "login_failures")
              }
              fails ++
              sessions.VM(sess_id)["login_failures"] = fails
              sessions.VM(sess_id)["login_fail_time"] = now

              sessions.VM(sess_id)["login_error"] = msg.Msg(lang, "bad_login_password")

              redis_log("portal_log", config.Portal_log_size, M{
                "time": now,
                "event": "login_fail",
                "count": fails,
                "login": login,
                "sta_id": sta_id,
                "session": sessions.VM(sess_id).Copy(),
              })

            } else {
              sessions.VM(sess_id)["login_error"] = "LDAP Auth err: " + err.Error()

              redis_log("portal_log", config.Portal_log_size, M{
                "time": now,
                "event": "login_error",
                "error": err.Error(),
                "login": login,
                "sta_id": sta_id,
                "session": sessions.VM(sess_id).Copy(),
              })
            }
          }
        } ()

        location("?lang="+lang, w)
        return

      } else {
        phone := sessions.Vs(sess_id, "phone")

        redis_log("portal_log", config.Portal_log_size, M{
          "time": now,
          "event": "sms_queued",
          "phone": phone,
          "sta_id": sta_id,
          "session": sessions.VM(sess_id).Copy(),
        })

        sessions.VM(sess_id)["sms_in_progress"] = int64(1)

        go func() {
          err := sendSMS(phone, sessions.Vs(sess_id, "code"))
          globalMutex.Lock()
          defer globalMutex.Unlock()

          delete(sessions.VM(sess_id), "sms_in_progress")

          if err != nil {
            sessions.VM(sess_id)["sms_error"] = msg.Msg(lang, "could_not_send_sms") + phone
            delete(sessions.VM(sess_id), "login")
            delete(sessions.VM(sess_id), "username")
            delete(sessions.VM(sess_id), "phone")
          } else {
            delete(sessions.VM(sess_id), "sms_error")
            sessions.VM(sess_id)["sms_sent"] = now
            sessions.VM(sess_id)["logged_in"] = now
          }
        } ()

        location("?lang="+lang, w)
        return
      }
    } else {
      // logged_in
      code := req.FormValue("code")

      failed_count := int64(0)
      if sessions.Evi(sess_id, "code_failed_count") {
        failed_count = sessions.Vi(sess_id, "code_failed_count")
      }

      if code != "" && code != sessions.Vs(sess_id, "code") {
        failed_count ++
        sessions.VM(sess_id)["code_failed_count"] = failed_count

        redis_log("portal_log", config.Portal_log_size, M{
          "time": now,
          "event": "bad_code",
          "count": failed_count,
          "sta_id": sta_id,
          "session": sessions.VM(sess_id).Copy(),
        })
      }

      if failed_count >= config.Max_sms_tries {
        page = "message"
        C["message"] = msg.Msg(lang, "too_many_code_tries")
        C["message_class"] = "shown_error"

        goto RENDER_PAGE
      }

      if code != "" {
        if code != sessions.Vs(sess_id, "code") {
          // bad code

          page = "2fa"

          C["show_code_div"] = "shown"
          C["message"] = msg.Msg(lang, "wrong_code")
          C["message_class"] = "shown_error"

          goto RENDER_PAGE
          // bad code
        }
        // good code
        sessions.VM(sess_id)["authenticated"] = now
        sessions.VM(sess_id)["auth_source"] = "2fa"
        location("?lang="+lang, w)

        redis_log("portal_log", config.Portal_log_size, M{
          "time": now,
          "event": "good_code",
          "sta_id": sta_id,
          "session": sessions.VM(sess_id).Copy(),
        })

        return
      }

      if !sessions.Evi(sess_id, "authenticated") {
        page = "2fa"
        C["show_code_div"] = "shown"
        C["message"] = msg.Msg(lang, "sms_sent_to") + sessions.Vs(sess_id, "phone")
        C["message_class"] = "shown"

        goto RENDER_PAGE
      } else {
        panic("Should not get here")
      }
    }

    panic("Should not get here")

  } else if auth_method == "voucher" {

    if sessions.Evi(sess_id, "voucher_failures") &&
       sessions.Vi(sess_id, "voucher_failures") >= config.Max_voucher_failures &&
    true {
      C["message_class"] = "shown_error"
      C["message"] = msg.Msg(lang, "too_many_voucher_attempts")
      page = "message"
      goto RENDER_PAGE
    }

    voucher := req.FormValue("voucher")

    if voucher != "" {
      if !rateCheck(user_ip) {
        panic("Too many requests")
      }

      if !vouchers.EvM(voucher) ||
        vouchers.Vi(voucher, "until") <= now ||
        (vouchers.Evi(voucher, "activated") && vouchers.Vs(voucher, "mac") != sta_id) ||
      false {
        fails := int64(0)
        if sessions.Evi(sess_id, "voucher_failures") {
          fails = sessions.Vi(sess_id, "voucher_failures")
        }
        fails ++
        sessions.VM(sess_id)["voucher_failures"] = fails

        location("?lang=" + lang, w)

        redis_log("portal_log", config.Portal_log_size, M{
          "time": now,
          "event": "bad_voucher",
          "voucher": voucher,
          "count": fails,
          "sta_id": sta_id,
          "session": sessions.VM(sess_id).Copy(),
        })
        return
      }

      if (!vouchers.Evs(voucher, "mac") || vouchers.Vs(voucher, "mac") == "") &&
         config.Prohibit_random != 0 && is_random &&
      true {
        page = "message"
        C["message"] = msg.Msg(lang, "random_prohibited")
        C["message_class"] = "shown_error"
        goto RENDER_PAGE
      }

      vouchers.VM(voucher)["mac"] = sta_id
      vouchers.VM(voucher)["last_portal_logon"] = now
      if !vouchers.Evi(voucher, "activated") {
        vouchers.VM(voucher)["activated"] = now
      }

      sessions.VM(sess_id)["authenticated"] = now
      sessions.VM(sess_id)["auth_source"] = "voucher"
      sessions.VM(sess_id)["voucher"] = voucher

      level := config.Default_level_voucher
      if vouchers.Evs(voucher, "level") {
        level = vouchers.Vs(voucher, "level")
      }
      auth_cache[sta_id] = M{
        "voucher": voucher, "level": level,
        "auth_method": "voucher",
      }

      sessions.VM(sess_id)["coa_state"] = "update_" + now_str
      sessions.VM(sess_id)["next_state"] = "run"
      sessions.VM(sess_id)["level"] = level

      ch_coa <- sess_id

      C["message"] = msg.Msg(lang, "authorized_wait")
      C["message_class"] = "shown"
      page = "authorized"

      redis_log("portal_log", config.Portal_log_size, M{
        "time": now,
        "event": "auth_voucher",
        "voucher": voucher,
        "sta_id": sta_id,
        "session": sessions.VM(sess_id).Copy(),
      })
      goto RENDER_PAGE
    }

    if config.Prohibit_random != 0 && is_random {
      page = "message"
      C["message"] = msg.Msg(lang, "random_prohibited")
      C["message_class"] = "shown_error"
      goto RENDER_PAGE
    }

    if sessions.Evi(sess_id, "voucher_failures") {
      C["message"] = msg.Msg(lang, "wrong_voucher")
      C["message_class"] = "shown_error"
    }

    page = "voucher"
    goto RENDER_PAGE

  } else {
    page = "start"

    if config.Allow_sms != 1 { C["allow_sms_class"] = "hidden" } else { C["allow_sms_class"] = "" }
    if config.Allow_login != 1 { C["allow_login_class"] = "hidden" } else { C["allow_login_class"] = "" }
    if config.Allow_voucher != 1 { C["allow_voucher_class"] = "hidden" } else { C["allow_voucher_class"] = "" }
    if config.Allow_2fa != 1 { C["allow_2fa_class"] = "hidden" } else { C["allow_2fa_class"] = "" }
    if config.Allow_totp != 1 { C["allow_totp_class"] = "hidden" } else { C["allow_totp_class"] = "" }
  }

RENDER_PAGE:

  template := config.Template

  result_page, render_err := RenderPage(page, C, template, sess_info, messages, lang, msg)
  if render_err != nil { panic(render_err) }


  once.Do(func() {
    globalMutex.Unlock()
  })

  w.Header().Set("Content-Type", "text/html; charset=UTF-8")
  w.Header().Set("Cache-Control", "no-cache")
  w.Header().Set("Access-Control-Allow-Origin", "*")
  w.Header().Set("Access-Control-Allow-Methods", "*")
  w.Header().Set("Access-Control-Allow-Headers", "*")

  //w.WriteHeader(http.StatusOK)

  w.Write([]byte(result_page))

  //fmt.Println(req)
}

func getLoginData(login string) M {

  login_data := ldap_users.VM(login).Copy()
  if login_data.Evs("totp_uri") {
    delete(login_data, "totp_uri")
  }

  if login_devices.EvM(login) {
    out_devs := login_devices.VM(login).Copy()
    if out_devs.EvM("devs") {
      for sta_id, _ := range out_devs.VM("devs") {
        m := mac_reg.FindStringSubmatch(sta_id)
        oui := strings.ToLower(strings.Join(m[1:4], ""))


        if random_reg.MatchString(sta_id) {
          out_devs.VM("devs", sta_id)["vendor"] = "Random"
        } else {
          if vendor_name, ex := vendors[oui]; ex {
            out_devs.VM("devs", sta_id)["vendor"] = vendor_name
          } else {
            out_devs.VM("devs", sta_id)["vendor"] = "Unknown"
          }
        }

        if auth_cache.EvM(sta_id) {
          out_devs.VM("devs", sta_id)["auth_cache"] = auth_cache.VM(sta_id).Copy()
        }
      }
    }
    login_data["devs"] = out_devs
  }

  return login_data
}

func handleConsts(w http.ResponseWriter, req *http.Request) {
  if req.Method == "OPTIONS" {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "*")
    w.Header().Set("Access-Control-Allow-Headers", "*")
    w.WriteHeader(http.StatusOK)
    return
  }

  w.Header().Set("Content-Type", "text/javascript; charset=UTF-8")
  w.Header().Set("Cache-Control", "no-cache")
  w.Header().Set("Access-Control-Allow-Origin", "*")
  w.Header().Set("Access-Control-Allow-Methods", "*")
  w.Header().Set("Access-Control-Allow-Headers", "*")
  w.WriteHeader(http.StatusOK)

  w.Write([]byte(fmt.Sprintf("const const_allowed_devices = %d;\n", config.Devs_allowed_per_login)))
  w.Write([]byte(fmt.Sprintf("const const_admin_input_save_timeout = %d;\n", config.Admin_input_save_timeout)))
  w.Write([]byte(fmt.Sprintf("const const_min_dev_swap_period = %d;\n", config.Min_dev_swap_period)))
  w.Write([]byte(fmt.Sprintf("const const_reauth_period = %d;\n", config.Reauth_period)))
  w.Write([]byte(fmt.Sprintf("const const_voucher_days = %d;\n", config.Voucher_days)))
  w.Write([]byte(fmt.Sprintf("const const_max_vouchers_gen = %d;\n", config.Max_vouchers_gen)))
  w.Write([]byte(fmt.Sprintf("const const_support_contact = \"%s\";\n", config.Support_contact)))
  w.Write([]byte(fmt.Sprintf("const const_secure_ssid = \"%s\";\n", config.Secure_ssid)))

  buff, jerr := json.MarshalIndent(config.Levels, "", "  ")

  if jerr == nil {
    w.Write([]byte(fmt.Sprintf("const const_access_levels = %s;\n", string(buff))))
  }

  w.Write([]byte("\n"))
}

func mail_vouchers(v M, email string) {
  if config.Mail_host == "" || config.Mail_from == "" { return }


  b := element.NewBuilder()
  e := b.Ele
  t := b.Text

  _ = b.WriteString("<!DOCTYPE html>\n")
  e("html").R(
    e("head").R(
      e("meta", "charset", "UTF-8"),
    ),
    e("body").R(
      e("div").R(
        e("h2").R(t("Внимание: при первом использовании, ваучер привязывается к устройству, с которого он активирован. Использовать его на другом устройстве невозможно.")),
        e("br"),
        e("h2").R(t("Внимание: доступ в сеть будет прекращен по окончании срока действия, независимо от времени активации.")),
      ),
      e("div").R(
        e("table").R(
          e("tr").R(
            e("th").R(t("Ваучер")),
            e("th").R(t("Срок действия")),
          ),
          func() (_ any) {
            for voucher, _ := range v {
              until := v.Vi(voucher, "until")
              until_str := time.Unix(until, 0).Format("02.01.2006")
              e("tr").R(
                e("td", "style", "padding-right: 1em;").R(t(v.Vs(voucher, "voucher"))),
                e("td").R(t(until_str)),
              )
            }
            return
          } (),
        ),
      ),
    ),
  )

  html := b.String()

  message := mail.NewMsg()

  if err := message.From(config.Mail_from); err != nil {
    fmt.Println(err.Error())
    return
  }

  if err := message.To(email); err != nil {
    fmt.Println(err.Error())
    return
  }

  message.Subject("Новые ваучеры WiFi")

  message.SetBodyString(mail.TypeTextHTML, html)

  client, err := mail.NewClient(config.Mail_host,
    mail.WithPort(int(config.Mail_port)),
    mail.WithoutNoop(),
  )

  if err != nil {
    fmt.Println(err.Error())
    return
  }

  client.SetTLSPolicy(mail.NoTLS)

  err = client.DialAndSend(message)
  if err != nil {
    fmt.Println(err.Error())
    return
  }
}

func redis_log(log_name string, log_limit int64, rec M) {
  go func() {
    var red redis.Conn
    var rerr error

    red, rerr = RedisCheck(red, "unix", config.Redis_socket, config.Redis_db)
    if rerr != nil { return }

    defer red.Close()

    rec["log"] = log_name
    rec["time_sort"] = time.Now().UnixNano()

    red.Do("LPUSH", config.Redis_prefix + log_name, rec.ToJsonStr(false))
    red.Do("LTRIM", config.Redis_prefix + log_name, 0, log_limit)
  } ()
}

func FormatMAC(anymac string) string {
  mac_a := mac_reg.FindStringSubmatch(anymac)
  if mac_a == nil { return "" }

  return strings.ToLower(mac_a[1] + mac_a[2] + "-" + mac_a[3] + mac_a[4] + "-" + mac_a[5] + mac_a[6])
}

func handleUnifi(w http.ResponseWriter, req *http.Request) {
  if req.Method == "OPTIONS" {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "*")
    w.Header().Set("Access-Control-Allow-Headers", "*")
    w.WriteHeader(http.StatusOK)
    return
  }

  defer func() { handle_error_html(recover(), w, req) } ()

  now := time.Now().Unix()

  // find user session

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


  once := &sync.Once{}

  globalMutex.Lock()

  defer func() {
    once.Do(func() {
      globalMutex.Unlock()
    })
  } ()

  path_a := site_uri_reg.FindStringSubmatch(req.URL.Path)
  if path_a == nil { panic("Bad url path") }

  unifi_site := path_a[1]

  unifi_controller := req.FormValue("unifi_controller")
  if unifi_controller == "" { panic("Bad unifi_controller") }

  if config.Unifis == nil { panic("No Unifis in config") }
  if _, ex := config.Unifis[unifi_controller]; !ex {
    panic("No Unifi in config")
  }


  sta_id := FormatMAC(req.FormValue("id"))
  if sta_id == "" { panic("Bad MAC") }

  ap_id := FormatMAC(req.FormValue("ap"))
  _ = ap_id

  ssid := req.FormValue("ssid")

  check_ts := req.FormValue("t")
  if !num_reg.MatchString(check_ts) { panic("Bad time") }

  check_t, terr := strconv.ParseInt(check_ts, 10, 64)
  if terr != nil { panic("Bad time value") }

  time_diff := now - check_t
  if time_diff < -config.Unifi_max_redir_age || time_diff > config.Unifi_max_redir_age { panic("Too old URL: " + fmt.Sprint(time_diff)) }


  sess_id := unifi_controller + "/" + unifi_site + "/" + user_ip + "/" + sta_id + "/" + ssid

  for _sess_id, _ := range sessions {
    if sessions.Evs(_sess_id, "sta_id") && sessions.Vs(_sess_id, "sta_id") == sta_id &&
       sessions.Evs(_sess_id, "sta_ip") && sessions.Vs(_sess_id, "sta_ip") == user_ip &&
       sessions.Evs(_sess_id, "unifi") && sessions.Vs(_sess_id, "unifi") == "1" &&
       sessions.Evs(_sess_id, "unifi_site") && sessions.Vs(_sess_id, "unifi_site") == unifi_site &&
       sessions.Evs(_sess_id, "unifi_controller") && sessions.Vs(_sess_id, "unifi_controller") == unifi_controller &&
       sessions.Evs(_sess_id, "ssid") && sessions.Vs(_sess_id, "ssid") == ssid &&
    true {
      sess_id = _sess_id
      break
    }
  }

  if !sessions.EvM(sess_id) {

    sessions[sess_id] = M{
      "sess_id": sess_id,
      "sta_id": sta_id,
      "unifi": "1",
      "sta_ip": user_ip,
      "acct_update": now,
      "acct_start": now,
      "unifi_controller": unifi_controller,
      "unifi_site": unifi_site,
      "ssid": ssid,
      "unifi_mac": req.FormValue("id"),
      "state": "portal",
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
      "sta_ip": user_ip,
      "session": sessions.VM(sess_id).Copy(),
    })

  }

  once.Do(func() {
    globalMutex.Unlock()
  })

  location(config.Redir_uri, w)

  //w.Header().Set("Content-Type", "text/html; charset=UTF-8")
  /*
  w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
  w.Header().Set("Cache-Control", "no-cache")
  w.Header().Set("Access-Control-Allow-Origin", "*")
  w.Header().Set("Access-Control-Allow-Methods", "*")
  w.Header().Set("Access-Control-Allow-Headers", "*")

  w.Write([]byte("User IP: " + user_ip + "\n"))
  w.Write([]byte("Site: " + unifi_site + "\n"))
  w.Write([]byte("Sta-id: " + sta_id + "\n"))
  w.Write([]byte("AP-id: " + ap_id + "\n"))
  w.Write([]byte("SSID: " + ssid + "\n"))
  */
  //w.Write([]byte("Headers:\n"))

}

func mail_totp(l M) {
  if config.Mail_host == "" || config.Mail_from == "" { return }

  if !l.Evs("totp_uri") { return }
  if !l.Evs("mail") { return }
  if !l.Evi("totp_created") { return }

  if l.Vs("mail") == "" { return }

  email := l.Vs("mail")

  var key *otp.Key
  var err error

  key, err = otp.NewKeyFromURL(l.Vs("totp_uri"))
  if err != nil { return }

  var img image.Image

  img, err = key.Image(200, 200)
	if err != nil {
		return
	}

  var buf bytes.Buffer

	png.Encode(&buf, img)

  image64 := base64.StdEncoding.EncodeToString(buf.Bytes())

  b := element.NewBuilder()
  e := b.Ele
  t := b.Text

  _ = b.WriteString("<!DOCTYPE html>\n")
  e("html").R(
    e("head").R(
      e("meta", "charset", "UTF-8"),
    ),
    e("body").R(
      e("div").R(
        e("h2").R(t("Ваш TOTP QR код")),
      ),
      e("div").R(
        e("span").R(t("Время создания ключа: ")),
        e("span").R(t( time.Unix(l.Vi("totp_created"), 0).Format("15:04:05 02.01.2006") )),
      ),
      e("div").R(t("Используйте приложение Google authenticator, FreeOTP+ или подобные")),
      e("div").R(
        e("img", "src", "data:image/png;base64," + image64),
      ),
    ),
  )

  html := b.String()

  message := mail.NewMsg()

  if err := message.From(config.Mail_from); err != nil {
    fmt.Println(err.Error())
    return
  }

  if err := message.To(email); err != nil {
    fmt.Println(err.Error())
    return
  }

  message.Subject("Ваш TOTP QR код")

  message.SetBodyString(mail.TypeTextHTML, html)

  client, err := mail.NewClient(config.Mail_host,
    mail.WithPort(int(config.Mail_port)),
    mail.WithoutNoop(),
  )
  if err != nil {
    fmt.Println(err.Error())
    return
  }

  client.SetTLSPolicy(mail.NoTLS)

  err = client.DialAndSend(message)
  if err != nil {
    fmt.Println(err.Error())
    return
  }
}

func handlePages(w http.ResponseWriter, req *http.Request) {
  if req.Method == "OPTIONS" {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "*")
    w.Header().Set("Access-Control-Allow-Headers", "*")
    w.WriteHeader(http.StatusOK)
    return
  }

  defer func() {
    handle_error_html(recover(), w, req)
  } ()

  // find user session

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

  var C M = M{}

  var template = config.Template
  if template_reg.MatchString(req.FormValue("template")) {
    template = req.FormValue("template")
  }

  sess_info := M{}

  once := &sync.Once{}

  now := time.Now().Unix()
  now_str := fmt.Sprint(now)
  _ = now_str

  globalMutex.Lock()

  defer func() {
    once.Do(func() {
      globalMutex.Unlock()
    })
  } ()


  lang := req.FormValue("lang")
  if lang == "" {
    lang = config.Default_lang
  }

  messages_file := config.Templates_dir + "/" + template + "/messages.json"
  messages_json, _ := getFile(messages_file)
  if messages_json == "" {
    panic("Cannot load messages file: " + messages_file)
  }

  var messages M
  if jerr := messages.UnmarshalJSON([]byte(messages_json)); jerr != nil { panic(jerr) }

  if !messages.EvM(lang) {
    lang = "ru"
  }

  msg := Msg{&messages}

  page := req.FormValue("page")

  if req.FormValue("random") != "0" && req.FormValue("random") != "1" {
    b := element.NewBuilder()
    e := b.Ele
    t := b.Text

    w.Header().Set("Content-Type", "text/html; charset=UTF-8")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "*")
    w.Header().Set("Access-Control-Allow-Headers", "*")
    w.WriteHeader(http.StatusOK)

    _ = b.WriteString("<!DOCTYPE html>\n")
    e("html", "lang", "en").R(
      e("head").R(
        e("title").R(t(`Portal preview`)),
        e("meta", "charset", "UTF-8"),
        e("meta", "http-equiv", "Cache-control", "content", "no-cache"),
        e("link", "rel", "icon", "href", "data:,"),
      ),
      e("body").R(
        e("ui").R(
          e("li").R(
            e("a", "href", "?random=0&template=" + template).R(
              t("Factory MAC"),
            ),
          ),
          e("li").R( e("span").R( t(" ") ),),
          e("li").R(
            e("a", "href", "?random=1&template=" + template).R(
              t("Random MAC"),
            ),
          ),
        ),
      ),
    )
    w.Write([]byte(b.String()))
    w.Write([]byte("\n"))


    return

  }

  is_random := (req.FormValue("random") == "1")

  if config.Prohibit_random != 0 {
    C["random_body"] = msg.Msg(lang, "random_body_prohibited")
  } else {
    C["random_body"] = msg.Msg(lang, "random_body")
  }

  if page == "" {
    b := element.NewBuilder()
    e := b.Ele
    t := b.Text

    w.Header().Set("Content-Type", "text/html; charset=UTF-8")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "*")
    w.Header().Set("Access-Control-Allow-Headers", "*")
    w.WriteHeader(http.StatusOK)


    rand := "&random=0"
    if is_random { rand = "&random=1" }

    href_prefix := "?template=" + template + rand

    _ = b.WriteString("<!DOCTYPE html>\n")
    e("html", "lang", "en").R(
      e("head").R(
        e("title").R(t(`Portal preview`)),
        e("meta", "charset", "UTF-8"),
        e("meta", "http-equiv", "Cache-control", "content", "no-cache"),
        e("link", "rel", "icon", "href", "data:,"),
      ),
      e("body").R(
        e("ui").R(
          e("li").R(
            e("a", "href", href_prefix + "&page=random").R(
              t("random prohibited"),
            ),
          ),
          e("li").R( e("span").R( t(" ") ),),
          e("li").R(
            e("a", "href", href_prefix + "&page=start").R(
              t("start"),
            ),
          ),
          e("li").R( e("span").R( t(" ") ),),
          e("li").R(
            e("a", "href", href_prefix + "&page=message").R(
              t("message"),
            ),
          ),
          e("li").R(
            e("a", "href", href_prefix + "&page=message&state=message_error").R(
              t("ERROR message"),
            ),
          ),
          e("li").R( e("span").R( t(" ") ),),
          e("li").R(
            e("a", "href", href_prefix + "&page=phone").R(
              t("phone"),
            ),
          ),
          e("li").R(
            e("a", "href", href_prefix + "&page=phone&state=phone_error").R(
              t("phone with error"),
            ),
          ),
          e("li").R(
            e("a", "href", href_prefix + "&page=phone&state=phone_code").R(
              t("phone, code enter"),
            ),
          ),
          e("li").R(
            e("a", "href", href_prefix + "&page=phone&state=phone_bad_code").R(
              t("phone, bad code entered"),
            ),
          ),
          e("li").R( e("span").R( t(" ") ),),
          e("li").R(
            e("a", "href", href_prefix + "&page=login").R(
              t("login"),
            ),
          ),
          e("li").R(
            e("a", "href", href_prefix + "&page=login&state=login_error").R(
              t("login error"),
            ),
          ),
          e("li").R( e("span").R( t(" ") ),),
          e("li").R(
            e("a", "href", href_prefix + "&page=totp").R(
              t("totp"),
            ),
          ),
          e("li").R(
            e("a", "href", href_prefix + "&page=totp&state=login_error").R(
              t("totp error"),
            ),
          ),
          e("li").R( e("span").R( t(" ") ),),
          e("li").R(
            e("a", "href", href_prefix + "&page=voucher").R(
              t("voucher"),
            ),
          ),
          e("li").R(
            e("a", "href", href_prefix + "&page=voucher&state=bad_voucher").R(
              t("bad voucher"),
            ),
          ),
          e("li").R( e("span").R( t(" ") ),),
          e("li").R(
            e("a", "href", href_prefix + "&page=2fa").R(
              t("2fa login"),
            ),
          ),
          e("li").R(
            e("a", "href", href_prefix + "&page=2fa&state=login_error").R(
              t("2fa login with error"),
            ),
          ),
          e("li").R(
            e("a", "href", href_prefix + "&page=2fa&state=2fa_code").R(
              t("2fa code enter"),
            ),
          ),
          e("li").R(
            e("a", "href", href_prefix + "&page=2fa&state=2fa_bad_code").R(
              t("2fa bad code entered"),
            ),
          ),
          e("li").R( e("span").R( t(" ") ),),
          e("li").R(
            e("a", "href", href_prefix + "&page=refresh").R(
              t("refresh"),
            ),
          ),
          e("li").R( e("span").R( t(" ") ),),
          e("li").R(
            e("a", "href", href_prefix + "&page=swap_mac").R(
              t("Swap MAC"),
            ),
          ),
          e("li").R( e("span").R( t(" ") ),),
          e("li").R(
            e("a", "href", href_prefix + "&page=authorized").R(
              t("authorized"),
            ),
          ),
          e("li").R( e("span").R( t(" ") ),),
          e("li").R(
            e("a", "href", href_prefix + "&page=disconnect").R(
              t("disconnect"),
            ),
          ),
        ),
      ),
    )
    w.Write([]byte(b.String()))
    w.Write([]byte("\n"))


    return
  }


  C["message_class"] = "hidden"

  C["refresh_delay"] = "9999999"

  C["debug_code"] = ""

  state := req.FormValue("state")

  if is_random {
    C["random"] = "shown"
  } else {
    C["random"] = "hidden"
  }

  switch(page) {
  case "random":
    page = "message"
    C["message"] = msg.Msg(lang, "random_prohibited")
    C["message_class"] = "shown_error"
  case "start":
    if config.Allow_sms != 1 { C["allow_sms_class"] = "hidden" } else { C["allow_sms_class"] = "" }
    if config.Allow_login != 1 { C["allow_login_class"] = "hidden" } else { C["allow_login_class"] = "" }
    if config.Allow_voucher != 1 { C["allow_voucher_class"] = "hidden" } else { C["allow_voucher_class"] = "" }
    if config.Allow_2fa != 1 { C["allow_2fa_class"] = "hidden" } else { C["allow_2fa_class"] = "" }
    if config.Allow_totp != 1 { C["allow_totp_class"] = "hidden" } else { C["allow_totp_class"] = "" }
  case "message":
    C["message"] = msg.Msg(lang, "test_message")
    C["message_class"] = "shown"
    if state == "message_error" {
      C["message_class"] = "shown_error"
    }
  case "voucher":
    if state == "bad_voucher" {
      C["message"] = msg.Msg(lang, "wrong_voucher")
      C["message_class"] = "shown_error"
    }
  case "login":
    if state == "login_error" {
      C["message_class"] = "shown_error"
      C["message"] = "Some login error occured"
    }
  case "2fa":
    C["show_code_div"] = "hidden"
    C["show_login_div"] = "hidden"

    if state == "" {
      C["show_login_div"] = "shown"
    } else if state == "login_error" {
      C["show_login_div"] = "shown"
      C["message_class"] = "shown_error"
      C["message"] = "Some login error occured"
    } else if state == "2fa_code" {
      C["show_code_div"] = "shown"
      C["message_class"] = "shown"
      C["message"] = msg.Msg(lang, "sms_sent_to") + "9999999999"
    } else if state == "2fa_code_warn" {
      C["show_code_div"] = "shown"
      C["message_class"] = "shown"
      C["message"] = msg.Msg(lang, "sms_sent_to") + "9999999999"
      C["phone_change_after_class"] = "shown_warn"
      C["phone_change_after"] = time.Now().Format("15:04:05")
    } else if state == "2fa_bad_code" {
      C["show_code_div"] = "shown"
      C["message_class"] = "shown_error"
      C["message"] = msg.Msg(lang, "wrong_code")
    }
  case "totp":
    if state == "login_error" {
      C["message_class"] = "shown_error"
      C["message"] = "Some TOTP error occured"
    }
  case "phone":
    C["show_phone_div"] = "hidden"
    C["show_code_div"] = "hidden"

    if state == "" {
      C["show_phone_div"] = "shown"
    } else if state == "phone_error" {
      C["show_phone_div"] = "shown"
      C["message"] = msg.Msg(lang, "too_many_devices_per_number")
      C["message_class"] = "shown_error"
    } else if state == "phone_code" {
      C["show_code_div"] = "shown"
      C["message"] = msg.Msg(lang, "sms_sent_to") + "9999999999"
      C["message_class"] = "shown"
    } else if state == "phone_bad_code" {
      C["show_code_div"] = "shown"
      C["message"] = msg.Msg(lang, "wrong_code")
      C["message_class"] = "shown_error"
    }

  case "authorized":
    C["message"] = msg.Msg(lang, "authorized_wait")
    C["message_class"] = "shown"
  case "disconnect":
    C["message"] = msg.Msg(lang, "disconnect_soon")
    C["message_class"] = "shown"
  case "refresh":
    C["message"] = msg.Msg(lang, "sms_in_progress")
    C["message_class"] = "shown"
  case "swap_mac":
    {
      b := element.NewBuilder()
      e := b.Ele
      t := b.Text

      dev_mac := "0001-0203-0405"
      i := 0
      vendor := "Izhevsk Dynamics Inc"
      vendor_class := msg.Msg(lang, "factory_mac_class")

      e("div", "class", "mac_row").R(
        e("div", "class", "mac_radio_row").R(
          e("input", "type", "radio", "name", "swap_mac", "value", dev_mac, "id", "mac_" + fmt.Sprint(i)),
          e("label", "class", "mac_label", "for", "mac_" + fmt.Sprint(i)).R(
            t(dev_mac),
          ),
        ),
        e("div", "class", "mac_name_row ").R(
          t(msg.Msg(lang, "dev_name") + "Айпадик Иванова И.И."),
        ),
        e("div", "class", "mac_vendor_row " + vendor_class).R( t(vendor) ),
        e("div", "class", "mac_added_row ").R(
          t(msg.Msg(lang, "added") +
            time.Unix( 1761538927, 0 ).Format(time.DateTime),
          ),
        ),
        e("div", "class", "mac_last_use_row ").R(
          t(msg.Msg(lang, "last_use") +
            time.Unix( 1761538927 + 3601, 0 ).Format(time.DateTime),
          ),
        ),
      )

      dev_mac = "0203-0405-0607"
      i = 1
      vendor = msg.Msg(lang, "random_mac")
      vendor_class = msg.Msg(lang, "random_mac_class")

      e("div", "class", "mac_row").R(
        e("div", "class", "mac_radio_row").R(
          e("input", "type", "radio", "name", "swap_mac", "value", dev_mac, "id", "mac_" + fmt.Sprint(i)),
          e("label", "class", "mac_label", "for", "mac_" + fmt.Sprint(i)).R(
            t(dev_mac),
          ),
        ),
        e("div", "class", "mac_name_row ").R(
          t(msg.Msg(lang, "dev_name") + "Робот Иванова И.И."),
        ),
        e("div", "class", "mac_vendor_row " + vendor_class).R( t(vendor) ),
        e("div", "class", "mac_added_row ").R(
          t(msg.Msg(lang, "added") +
            time.Unix( 1761539927, 0 ).Format(time.DateTime),
          ),
        ),
        e("div", "class", "mac_last_use_row ").R(
          t(msg.Msg(lang, "last_use") +
            time.Unix( 1761539927 + 3601, 0 ).Format(time.DateTime),
          ),
        ),
      )

      C["macs_list"] = b.String()

    }
  default:
    page = "message"
    C["message"] = "Unknown page"
    C["message_class"] = "shown_error"
  }

  result_page, render_err := RenderPage(page, C, template, sess_info, messages, lang, msg)
  if render_err != nil { panic(render_err) }

  once.Do(func() {
    globalMutex.Unlock()
  })

  w.Header().Set("Content-Type", "text/html; charset=UTF-8")
  w.Header().Set("Cache-Control", "no-cache")
  w.Header().Set("Access-Control-Allow-Origin", "*")
  w.Header().Set("Access-Control-Allow-Methods", "*")
  w.Header().Set("Access-Control-Allow-Headers", "*")

  //w.WriteHeader(http.StatusOK)

  w.Write([]byte(result_page))

  //fmt.Println(req)
}

func RenderPage(page string, C M, template string, sess_info M, messages M, lang string, msg Msg) (ret string, ret_err error) {
  defer func() {
    if r := recover(); r != nil {
      ret = ""
      switch v := r.(type) {
      case string:
        ret_err = errors.New(v)
      case error:
        ret_err = v
      default:
        ret_err = errors.New("RenderPage unknown error")
      }
    }
  } ()

  page_file := config.Templates_dir + "/" + template + "/" + page

  page_src, _ := getFile(page_file)
  if page_src == "" {
    panic("Cannot load page file \"" + page_file + "\"")
  }

  var_indexes := page_split_reg.FindAllStringIndex(page_src, -1)

  prev_start := 0

  result_page := ""

  src_len := len(page_src)

  for _, a := range var_indexes {
    if a[0] > prev_start {
      result_page += page_src[prev_start:a[0]]
    }
    prev_start = a[1]

    var_name := page_src[a[0]+1:a[1]-1]

    if strings.HasPrefix(var_name, "F_") && len(var_name) > 2 {
      file_name := config.Templates_dir + "/" + template + "/" + var_name[2:]
      file_cont, ferr := getFile(file_name)
      if ferr != nil { panic(ferr) }
      result_page += file_cont
    } else if var_name == "S_" {
      result_page += "const sess_info = " + sess_info.ToJsonStr(true) + ";\n"
    } else if strings.HasPrefix(var_name, "C_") && len(var_name) > 2 {
      if C.Evs(var_name[2:]) {
        result_page += C.Vs(var_name[2:])
      } else {
        result_page += "unknown_C_" + var_name[2:]
      }
    } else {
      if messages.Evs(lang, var_name) {
        result_page += msg.Msg(lang, var_name)
      } else if messages.Evs(config.Default_lang, var_name) {
        result_page += msg.Msg(config.Default_lang, var_name)
      } else {
        result_page += "unknown_" + var_name
      }
    }
  }

  if var_indexes[len(var_indexes) - 1][1] < src_len {
    result_page += page_src[var_indexes[len(var_indexes) - 1][1]:]
  }

  return result_page, nil

}

func handleStatic(w http.ResponseWriter, req *http.Request) {
  if req.Method == "OPTIONS" {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "*")
    w.Header().Set("Access-Control-Allow-Headers", "*")
    w.WriteHeader(http.StatusOK)
    return
  }

  defer func() {
    handle_error_html(recover(), w, req)
  } ()

  // find user session

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


  var template = config.Template
  var referer string

  if header_values, ex := req.Header["Referer"]; ex && len(header_values) == 1 {
    referer = req.Header["Referer"][0]
    ref_url, url_err := url.Parse(referer)
    if url_err == nil {
      q := ref_url.Query()
      if q.Get("template") != "" {
        template = q.Get("template")
      }
    }
  } else {
    req_template := req.URL.Query().Get("template")
    if req_template != "" {
      template = req_template
    }
  }

  //fmt.Println("Static handler:")
  //fmt.Println("\ttemplate: ", template)
  //fmt.Println("\tr.URL.Path: ", req.URL.Path)
  //fmt.Println("\tReferer: ", referer)

  dir := os.DirFS(config.Templates_dir + "/" + template + "/static")

  req_resourse, _ := strings.CutPrefix(req.URL.Path, "/static")

  //fmt.Println("\tFile: ", req_resourse)
  //fmt.Println()

  http.ServeFileFS(w, req, dir, req_resourse)
}
