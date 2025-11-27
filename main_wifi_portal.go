package main

import (
  "fmt"
  "log"
  "time"
  "flag"
  "strings"
  "os"
  "sync"
  "syscall"
  "regexp"
  "os/signal"
  "math/rand"

  "github.com/sergle/radius"
  "github.com/gomodule/redigo/redis"
  . "github.com/ShyLionTjmn/mygolib"
  . "github.com/ShyLionTjmn/m"
)

var opt_v int
var opt_n bool
var opt_c string

var config Config

var dict *radius.Dictionary

var globalMutex = &sync.RWMutex{}
// Locks:
var sessions M = M{}
var auth_cache M = M{}
var ldap_users M = M{}
var login_devices M = M{}
var vouchers M = M{}
var vendors map[string]string

//

var ch_coa chan string

var phone_reg *regexp.Regexp
var ldap_groups_reg *regexp.Regexp
var ldap_dn_reg *regexp.Regexp

var login_admins_reg *regexp.Regexp
var voucher_admins_reg *regexp.Regexp
var email_reg *regexp.Regexp

var secure_clid_reg *regexp.Regexp

func init() {

  flag.IntVar(&opt_v, "v", 0, "set verbosity level")
  flag.BoolVar(&opt_n, "n", false, "do not load/save session data from/to Redis")
  flag.StringVar(&opt_c, "c", DEFAULT_CONFIG_FILE, "mapper.conf location")

  flag.Parse()

  config = LoadConfig(opt_c, FlagPassed("c"))

  phone_reg = regexp.MustCompile(config.Phone_reg)
  ldap_groups_reg = regexp.MustCompile(config.Ldap_groups_reg)
  ldap_dn_reg = regexp.MustCompile(config.Ldap_dn_regexp)

  login_admins_reg = regexp.MustCompile(config.Login_admins_group_reg)
  voucher_admins_reg = regexp.MustCompile(config.Voucher_admins_group_reg)
  email_reg = regexp.MustCompile(`^[a-zA-Z0-9\_\-\.]+@[a-zA-Z0-9\_\-]+[a-zA-Z0-9\_\-\.]?[a-zA-Z0-9]+$`)

  if config.Secure_clid_reg != "" {
    secure_clid_reg = regexp.MustCompile(config.Secure_clid_reg)
  }

  if config.Levels == nil {
    log.Fatal("No Levels defined")
  }

  if _, ex := config.Levels[config.Default_level_login]; config.Default_level_login == "" || !ex {
    log.Fatal("No Default_level_login defined")
  }

  if _, ex := config.Levels[config.Default_level_sms]; config.Default_level_sms == "" || !ex {
    log.Fatal("No Default_level_sms defined")
  }

  if _, ex := config.Levels[config.Default_level_voucher]; config.Default_level_voucher == "" || !ex {
    log.Fatal("No Default_level_voucher defined")
  }

  if _, ex := config.Levels[config.Default_level_2fa]; config.Default_level_2fa == "" || !ex {
    log.Fatal("No Default_level_2fa defined")
  }

  if _, ex := config.Levels[config.Default_level_dpsk]; config.Default_level_dpsk == "" || !ex {
    log.Fatal("No Default_level_dpsk defined")
  }

  if config.Radius_dictionary == "" {
    log.Fatal("No Radius_dictionary defined")
  }

  dict = radius.NewDictionary()
  err := dict.LoadFile(config.Radius_dictionary)
  if err != nil {
    log.Fatal("Failed to load dictionary: %s", err)
  }

  ch_coa = make(chan string, 100)
}

type RedBackup struct {
  key string
  hash *M
}

func KeyGenDict(dict []rune, n int) string {
  b := make([]rune, n)
  for i := range b {
    b[i] = dict[rand.Intn(len(dict))]
  }
  return string(b)
}

func main() {
  fmt.Println("wifi_portal starting")
  if opt_v > 0 {
    fmt.Println("Log level:", opt_v)
  }

  // load saved sessions and authcache

  red_backup := []RedBackup{
    RedBackup{"sessions", &sessions},
    RedBackup{"auth_cache", &auth_cache},
    RedBackup{"login_devices", &login_devices},
    RedBackup{"ldap_users", &ldap_users},
    RedBackup{"vouchers", &vouchers},
  }

  if !opt_n {
    var red redis.Conn
    var rerr error

    red_wait_start := time.Now().Unix()

    red, rerr = RedisCheck(red, "unix", config.Redis_socket, config.Redis_db)

    for rerr != nil && strings.Contains(rerr.Error(), "LOADING Redis is loading the dataset in memory") {
      if time.Now().Unix() > (red_wait_start + int64(config.Redis_wait)) { break }
      time.Sleep(time.Second)
      red, rerr = RedisCheck(red, "unix", config.Redis_socket, config.Redis_db)
    }

    if rerr != nil { log.Fatal(rerr.Error()) }

    var json_str string


    for _, rb := range red_backup {

      json_str, rerr = redis.String(red.Do("GET", config.Redis_prefix + rb.key))
      if rerr != nil && rerr != redis.ErrNil { log.Fatal(rerr.Error()) }
      if rerr == nil {
        if jerr := (*rb.hash).UnmarshalJSON([]byte(json_str)); jerr != nil { panic(jerr) }
      }
    }

    red.Close()
  }

  if true {
    var red redis.Conn
    var rerr error

    red, rerr = RedisCheck(red, "unix", config.Redis_socket, config.Redis_db)
    if rerr != nil { log.Fatal(rerr.Error()) }

    vendors, rerr = redis.StringMap(red.Do("HGETALL", "oui"))
    if rerr != nil { log.Fatal(rerr.Error()) }
    red.Close()
  }


  sig_ch := make(chan os.Signal, 1)
  signal.Notify(sig_ch, syscall.SIGHUP)
  signal.Notify(sig_ch, syscall.SIGINT)
  signal.Notify(sig_ch, syscall.SIGTERM)
  signal.Notify(sig_ch, syscall.SIGQUIT)

  var wg sync.WaitGroup
  var stop_channels []chan string

  user_sync_ch := make(chan string, 1)
  stop_channels = append(stop_channels, user_sync_ch)
  wg.Add(1)
  go user_sync(user_sync_ch, &wg)

  http_stop_ch := make(chan string, 1)
  stop_channels = append(stop_channels, http_stop_ch)
  wg.Add(1)
  go http_server(http_stop_ch, &wg)

  coa_stop_ch := make(chan string, 1)
  stop_channels = append(stop_channels, coa_stop_ch)
  wg.Add(1)
  go coa_server(coa_stop_ch, &wg)

  radius_stop_ch := make(chan string, 1)
  stop_channels = append(stop_channels, radius_stop_ch)
  wg.Add(1)
  go radius_server(radius_stop_ch, &wg)

  unifi_stop_ch := make(chan string, 1)
  stop_channels = append(stop_channels, unifi_stop_ch)
  wg.Add(1)
  go unifi_server(unifi_stop_ch, &wg)

  MAIN_LOOP:
  for {
    timer := time.NewTimer(1*time.Second)
    select {
    case s := <-sig_ch:
      if s != syscall.SIGHUP && s != syscall.SIGUSR1 {
        timer.Stop()
        break MAIN_LOOP
      }
      continue MAIN_LOOP
    case <-timer.C:

      var red redis.Conn
      var rerr error

      if !opt_n {
        globalMutex.Lock()

        save_str := make(map[string]string)

        for _, rb := range red_backup {
          save_str[rb.key] = (*rb.hash).ToJsonStr(true)
        }
        globalMutex.Unlock()

        red, rerr = RedisCheck(red, "unix", config.Redis_socket, config.Redis_db)
        if rerr == nil {
          for _, rb := range red_backup {
            red.Do("SET", config.Redis_prefix + rb.key, save_str[rb.key])
          }
        }
      }

      if red == nil {
        red, rerr = RedisCheck(red, "unix", config.Redis_socket, config.Redis_db)
      }

      if red != nil {
        var oui_time string

        oui_time, rerr = redis.String(red.Do("HGET", "oui", "time"))

        if _, ex := vendors["time"]; ex && rerr == nil && vendors["time"] != oui_time {
          var new_vendors map[string]string
          new_vendors, rerr = redis.StringMap(red.Do("HGETALL", "oui"))
          if rerr == nil {
            globalMutex.Lock()
            vendors = new_vendors
            globalMutex.Unlock()
          }
        }
      }

      if red != nil {
        red.Close()
        red = nil
      }
    }
  }

  for _, ch := range stop_channels {
    //ch <- "stop"
    close(ch)
  }
  if WaitTimeout(&wg, 5*time.Second) {
    fmt.Println("main wait timed out")
  }

  if !opt_n {
    var red redis.Conn
    var rerr error

    red, rerr = RedisCheck(red, "unix", config.Redis_socket, config.Redis_db)
    if rerr != nil { log.Fatal(rerr.Error()) }

    for _, rb := range red_backup {
      json_str := (*rb.hash).ToJsonStr(true)

      _, rerr = red.Do("SET", config.Redis_prefix + rb.key, json_str)
      if rerr != nil && rerr != redis.ErrNil { log.Fatal(rerr.Error()) }
    }

    red.Close()
  }

  fmt.Println("main done")
}
