package main

import (
  "encoding/json"
  "log"
  "os"
  "flag"
)

const DEFAULT_REDIS_SOCKET="/tmp/redis.sock"
const DEFAULT_REDIS_DB="0"
const DEFAULT_REDIS_ERR_SLEEP=5
const DEFAULT_REDIS_PREFIX="wifi_portal."

const DEFAULT_WWW_PORT = 8002
const DEFAULT_WWW_ROOT = "/opt/wifi_portal/www/"

const DEFAULT_ADMIN_GROUP = "usr_netapp_wifi_admins"

//const DEFAULT_REAUTH_PERIOD = 60*5 //seconds. make it reasonable
const DEFAULT_REAUTH_PERIOD = 60*60*24*7 //seconds. make it reasonable

const DEFAULT_SMS_CODE_LENGTH = 5
const DEFAULT_SMS_CODE_DICT = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTVWXY23456789"

const DEFAULT_TEMPLATES_DIR = "/opt/wifi_portal/templates"
const DEFAULT_TEMPLATE = "default"
const DEFAULT_LANG = "ru"
const DEFAULT_LANGS = "ru,en"

const DEFAULT_FILE_CACHE_TIME = 10 //seconds

const DEFAULT_PHONE_REG = `^\+79\d{9}`

const DEFAULT_MAX_SMS_TRIES = 3

const DEFAULT_DEVS_ALLOWED_PER_LOGIN = 1

const DEFAULT_PHONE_CHANGE_PERIOD = 300 //seconds
//const DEFAULT_PHONE_CHANGE_PERIOD = 20 //seconds

const DEFAULT_MIN_DEV_SWAP_PERIOD = 60*60*24*7 //?
//const DEFAULT_MIN_DEV_SWAP_PERIOD = 120 //seconds

const DEFAULT_RADIUS_LISTEN = ":1812"
//const DEFAULT_SECURE_RADIUS_LISTEN = ":1814"
const DEFAULT_COA_CHECK_PERIOD = 5 //seconds
const DEFAULT_INTERIM_UPDATE_PERIOD = 60 //seconds

const DEFAULT_LDAP_SYNC_PERIOD = 300
const DEFAULT_LDAP_USERS_QUERY = `(&(userAccountControl:1.2.840.113556.1.4.803:=512)` +
                                   `(!(userAccountControl:1.2.840.113556.1.4.803:=2)))`
const DEFAULT_LDAP_PAGE_SIZE = 1000
const DEFAULT_LDAP_TIMEOUT = 5 //seconds

const DEFAULT_MAX_LOGIN_FAILURES = 3
// const DEFAULT_LOGIN_LOCKOUT_TIME = 300 //seconds // WHY have it at all?

const DEFAULT_STALE_SESSION_AGE = 60*60*24 //seconds

const DEFAULT_CLIENT_IP_HEADER = "X-Forwarded-For"

const DEFAULT_MAX_VOUCHER_FAILURES = 5

const DEFAULT_Login_admins_group_reg = `(?i)/(?:usr_netapp_wifi_users_managers|usr_netapp_wifi_admins)(?:\W|$)`
const DEFAULT_Voucher_admins_group_reg = `(?i)/(?:usr_netapp_wifi_cards_managers|usr_netapp_wifi_admins)(?:\W|$)`

const DEFAULT_ADMIN_INPUT_SAVE_TIMEOUT = 1000

const DEFAULT_VOUCHER_DAYS = 31
const DEFAULT_MAX_VOUCHERS_GEN = 100
const DEFAULT_Max_total_vouchers = 2000 //wipe old on creation
const DEFAULT_Voucher_length = 8
const DEFAULT_Voucher_dict = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTVWXY23456789"

const DEFAULT_DPSK_length = 10
const DEFAULT_DPSK_dict = "!?%#$@*-_abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTVWXY23456789"

const DEFAULT_Audit_log_size = 1000
const DEFAULT_Portal_log_size = 1000
const DEFAULT_Radius_log_size = 1000


type Radius_Client struct {
  Ip                            string
  Secret                        string
  CoA_Port                      string
  CoA_Secret                    string
  Type                          string
}

type AccessLevel struct {
  Name                          string
  Filter_acl                    string
  Secure_filter_acl             string
}

type Config struct {
  Clients                       map[string]Radius_Client
  Redis_socket                  string
  Redis_db                      string
  Redis_err_sleep               uint
  Redis_prefix                  string

  Www_port                      uint
  Www_root                      string

  Redir_uri                     string
  Proxy_host                    string
  Client_ip_header              string

  Admin_group                   string

  Reauth_period                 int64


  Sms_code_length               int
  Sms_code_dict                 string

  Max_login_failures            int64

  Templates_dir                 string
  Template                      string
  Default_lang                  string
  Langs                         string

  File_cache_time               int64

  Phone_reg                     string

  Max_sms_tries                 int64

  Phone_change_period           int64

  Devs_allowed_per_login        int64

  Min_dev_swap_period           int64

  Radius_secret                 string
  Radius_listen                 string
  //Secure_radius_listen          string
  Interim_update_period         uint32

  Radius_dictionary             string

  Secure_clid_reg               string
  Secure_ssid                   string // for messages

  CoA_check_period              int64

  Stale_session_age             int64

  Ldap_sync_period              int64
  Ldap_users_query              string
  Ldap_page_size                uint32
  Ldap_search_base              string
  Ldap_uri                      string
  Ldap_user                     string
  Ldap_password                 string
  Ldap_timeout                  int64
  Ldap_groups_reg               string
  Ldap_domain                   string

  Mysql_dsn                     string

  Max_voucher_failures          int64

  Sms_queue_dir                 string

  Default_level_login           string
  Default_level_voucher         string
  Default_level_sms             string
  Default_level_2fa             string
  Default_level_dpsk             string

  Redir_acl                     string
  Portal_filter_acl             string

  Levels                        map[string]AccessLevel

  Login_admins_group_reg        string
  Voucher_admins_group_reg      string

  Fac_server                    string
  Fac_secret                    string

  Admin_input_save_timeout      int64

  Voucher_days                  int64
  Max_vouchers_gen              int64
  Max_total_vouchers            int64
  Voucher_length                int64
  Voucher_dict                  string

  DPSK_length                   int64
  DPSK_dict                     string

  Mail_host                     string
  Mail_from                     string

  Support_contact               string

  Audit_log_size                int64
  Portal_log_size               int64
  Radius_log_size               int64

  Config_origin                 string
}

const DEFAULT_CONFIG_FILE = "/etc/wifi_portal/wifi_portal.conf"

func LoadConfig(file string, from_opt_c bool) Config {
  ret := Config{
    Redis_socket:                  DEFAULT_REDIS_SOCKET,
    Redis_db:                      DEFAULT_REDIS_DB,
    Redis_err_sleep:               DEFAULT_REDIS_ERR_SLEEP,
    Redis_prefix:                  DEFAULT_REDIS_PREFIX,

    Www_port:                      DEFAULT_WWW_PORT,
    Www_root:                      DEFAULT_WWW_ROOT,

    Redir_uri:                     "https://change.me/wifi_portal/portal/",
    Client_ip_header:              DEFAULT_CLIENT_IP_HEADER,

    Admin_group:                   DEFAULT_ADMIN_GROUP,

    Reauth_period:                 DEFAULT_REAUTH_PERIOD,

    Sms_code_length:               DEFAULT_SMS_CODE_LENGTH,
    Sms_code_dict:                 DEFAULT_SMS_CODE_DICT,

    Templates_dir:                 DEFAULT_TEMPLATES_DIR,
    Template:                      DEFAULT_TEMPLATE,
    Default_lang:                  DEFAULT_LANG,
    Langs:                         DEFAULT_LANGS,

    File_cache_time:               DEFAULT_FILE_CACHE_TIME,

    Phone_reg:                     DEFAULT_PHONE_REG,

    Max_sms_tries:                 DEFAULT_MAX_SMS_TRIES,

    Max_login_failures:            DEFAULT_MAX_LOGIN_FAILURES,

    //Login_lockout_time:            DEFAULT_LOGIN_LOCKOUT_TIME,

    Phone_change_period:           DEFAULT_PHONE_CHANGE_PERIOD,

    Devs_allowed_per_login:        DEFAULT_DEVS_ALLOWED_PER_LOGIN,

    Min_dev_swap_period:           DEFAULT_MIN_DEV_SWAP_PERIOD,

    Radius_listen:                 DEFAULT_RADIUS_LISTEN,
    //Secure_radius_listen:          DEFAULT_SECURE_RADIUS_LISTEN,
    CoA_check_period:              DEFAULT_COA_CHECK_PERIOD,
    Interim_update_period:         DEFAULT_INTERIM_UPDATE_PERIOD,

    Ldap_sync_period:              DEFAULT_LDAP_SYNC_PERIOD,
    Ldap_users_query:              DEFAULT_LDAP_USERS_QUERY,
    Ldap_page_size:                DEFAULT_LDAP_PAGE_SIZE,
    Ldap_timeout:                  DEFAULT_LDAP_TIMEOUT,

    Stale_session_age:             DEFAULT_STALE_SESSION_AGE,

    Max_voucher_failures:          DEFAULT_MAX_VOUCHER_FAILURES,

    Login_admins_group_reg:        DEFAULT_Login_admins_group_reg,
    Voucher_admins_group_reg:      DEFAULT_Voucher_admins_group_reg,

    Admin_input_save_timeout:      DEFAULT_ADMIN_INPUT_SAVE_TIMEOUT,

    Voucher_days:                  DEFAULT_VOUCHER_DAYS,
    Max_vouchers_gen:              DEFAULT_MAX_VOUCHERS_GEN,
    Max_total_vouchers:            DEFAULT_Max_total_vouchers,
    Voucher_length:                DEFAULT_Voucher_length,
    Voucher_dict:                  DEFAULT_Voucher_dict,

    DPSK_length:                   DEFAULT_DPSK_length,
    DPSK_dict:                     DEFAULT_DPSK_dict,

    Audit_log_size:                DEFAULT_Audit_log_size,
    Portal_log_size:               DEFAULT_Portal_log_size,
    Radius_log_size:               DEFAULT_Radius_log_size,

    Config_origin:                 "Default values",
  }

  if fi, fe := os.Stat(file); fe == nil && fi.Mode().IsRegular() {
    var err error
    var conf_json []byte
    if conf_json, err = os.ReadFile(file); err != nil { log.Fatal(err.Error()) }

    if err = json.Unmarshal(conf_json, &ret); err != nil {
      log.Fatal("Error unmarshalling config file: " + err.Error())
    }

    if ret.Clients == nil || len(ret.Clients) == 0 {
      log.Fatal("No servers configured")
    }

    if from_opt_c {
      ret.Config_origin = "opt_c file"
    } else {
      ret.Config_origin = "default mapper.conf file"
    }
  } else if from_opt_c {
    log.Fatal("Cannot read config file " + file)
  }

  return ret
}

func FlagPassed(name string) bool {
  found := false
  flag.Visit(func(f *flag.Flag) {
    if f.Name == name {
      found = true
    }
  })
  return found
}

