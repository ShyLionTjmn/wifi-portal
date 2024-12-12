var g_mac_free_reg = new RegExp("^([0-9a-fA-F]{2})[:\.\-]?([0-9a-fA-F]{2})[:\.\-]?([0-9a-fA-F]{2})[:\.\-]?"+
                                "([0-9a-fA-F]{2})[:\.\-]?([0-9a-fA-F]{2})[:\.\-]?([0-9a-fA-F]{2})$"
);

var mac_formats = ["u6c", "l6h", "l3d", "l3h", "l12"];

function format_mac(mac, view="huawei", null_on_error=false) {
  let m = String(mac).match(g_mac_free_reg);
  if(m === null) {
    if(null_on_error) {
      return null;
    } else {
      return mac;
    };
  };

  switch(view) {
  case "canonic":
  case "u6c":
      return(m[1].toUpperCase()+":"+m[2].toUpperCase()+":"+m[3].toUpperCase()+
        ":"+m[4].toUpperCase()+":"+m[5].toUpperCase()+":"+m[6].toUpperCase());
  case "snr":
  case "l6h":
      return(m[1].toLowerCase()+"-"+m[2].toLowerCase()+"-"+m[3].toLowerCase()+
        "-"+m[4].toLowerCase()+"-"+m[5].toLowerCase()+"-"+m[6].toLowerCase());
  case "cisco":
  case "l3d":
      return(m[1].toLowerCase()+m[2].toLowerCase()+"."+m[3].toLowerCase()+m[4].toLowerCase()+
        "."+m[5].toLowerCase()+m[6].toLowerCase());
  case "huawei":
  case "l3h":
      return(m[1].toLowerCase()+m[2].toLowerCase()+"-"+m[3].toLowerCase()+m[4].toLowerCase()+
        "-"+m[5].toLowerCase()+m[6].toLowerCase());
  case "l12":
      return(m[1].toLowerCase()+m[2].toLowerCase()+m[3].toLowerCase()+m[4].toLowerCase()+
        m[5].toLowerCase()+m[6].toLowerCase());
  };
  return mac;
};

function wdhm(time) {
  time=Math.floor(time);
  let w=Math.floor(time / (7*24*60*60));
  time = time - w*(7*24*60*60);

  let d=Math.floor(time / (24*60*60));
  time = time - d*(24*60*60);

  let h=Math.floor(time / (60*60));
  time = time - h*(60*60);

  let m=Math.floor(time / 60);
  let s=time - m*60;

  let ret="";
  if(w > 0) {
    ret = String(w)+" н. ";
  };
  if(d > 0 || w > 0) {
    ret += String(d)+" д. ";
  };
  if(h > 0 || d > 0 || w > 0) {
    ret += String(h)+" ч. ";
  };
  if(m > 0 || h > 0 || d > 0 || w > 0) {
    ret += String(m)+" м. ";
  };

  ret += String(s)+" с.";

  return ret;
};

function debugLog(text) {
  if(!DEBUG) return;

  $("#debug_win").text( $("#debug_win").text() + "\n" + text);
  $("#debug_win").scrollTop($("#debug_win").prop("scrollHeight"));
};

var userinfo = {};
var body;
var workarea;
var fixed_div;

$( document ).ready(function() {
  //BEGIN begin
  window.onerror=function(errorMsg, url, lineNumber) {
    alert("Error occured: " + errorMsg + ", at line: " + lineNumber);//or any message
    return false;
  };
  $(document).click(function() { $("UL.popupmenu").remove(); });
  $(document).keyup(function(e) {
    if (e.key === "Escape") { // escape key maps to keycode `27`
      $("UL.popupmenu").remove();
      $(".tooltip").remove();
    };
  });

  $("BODY").empty();

  $("BODY").append (
    $(DIV).css({"position": "fixed", "right": "0.5em", "top": "0.5em", "min-width": "2em",
                "border": "1px solid black", "background-color": "lightgrey"
    }).prop("id", "indicator").text("Запуск интерфейса...")
  );
  if(version.match(/devel/)) {
    $("BODY")
     .append ( $(DIV).css({"position": "fixed", "right": "1em", "bottom": "1em", "color": "red" }).text("DEVELOPMENT"))
     .append ( $(DIV).css({"position": "fixed", "left": "1em", "bottom": "1em", "color": "red" }).text("DEVELOPMENT"))
    ;
  };

  $(document).ajaxComplete(function() {
    $("#indicator").text("Запрос завершен").css("background-color", "lightgreen");
  });

  $(document).ajaxStart(function() {
    $("#indicator").text("Запрос ...").css("background-color", "yellow");
  });

  $( document ).tooltip({ items: ".tooltip[title]", show: null });
  body=$( "body" );
  body.css({"height": "100%", "margin": "0"});
  $("HTML").css({"height": "100%", "margin": "0"});

  if(DEBUG) {
    body
     .append( $(DIV).prop("id", "debug_win")
       .addClass("wsp")
       .css({"position": "fixed", "bottom": "1em", "right": "1em", "width": "35em",
             "top": "15em", "overflow": "auto", "border": "1px black solid", "background-color": "white",
             "z-index": 100000}
       )
       .toggle(false)
     )
     .append( $(LABEL)
       .prop("id", "debug_clear_btn")
       .css({"position": "fixed", "bottom": "0em", "right": "3em",
             "z-index": 100001}
       )
       .append( $(LABEL)
         .addClass(["ui-icon", "ui-icon-delete", "button"])
         .click(function() {
           $("#debug_win").contents().filter(function(){
              return (this.nodeType == 3);
           }).remove();
         })
       )
       .toggle(false)
     )
     .append( $(LABEL)
       .css({"position": "fixed", "bottom": "0em", "right": "1em",
             "z-index": 100001}
       )
       .append( $(LABEL)
         .addClass(["ui-icon", "ui-icon-arrowthick-2-n-s", "button"])
         .click(function() {
           $("#debug_win,#debug_clear_btn").toggle();
         })
       )
     )
    ;
  };


  run_query({"action": "userinfo"}, function(res) {

    userinfo = res["ok"];

    let menu = $(DIV).addClass("menu");
    body.append( menu );

    workarea = $(DIV).prop("id", "workarea").addClass("workarea");
    fixed_div = $(DIV).prop("id", "fixed_div").addClass("fixed_div");

    body.append( workarea );

    menu
     .append( userinfo_btn() )
    ;

    if(userinfo["is_login_admin"] || userinfo["is_voucher_admin"]) {
      menu
       .append( $(SPAN).addClass("bigbutton").text("Сеансы")
         .click( function() {
           window.location = "?action=sessions"+(DEBUG?"&debug":"");
         })
       )
      ;
    };
    if(userinfo["is_login_admin"]) {
      menu
       .append( $(SPAN).addClass("bigbutton").text("Учетные записи")
         .click( function() {
           window.location = "?action=logins"+(DEBUG?"&debug":"");
         })
       )
      ;
    };
    if(userinfo["is_voucher_admin"]) {
      menu
       .append( $(SPAN).addClass("bigbutton").text("Ваучеры")
         .click( function() {
           window.location = "?action=vouchers"+(DEBUG?"&debug":"");
         })
       )
      ;
    };

    if(userinfo["is_login_admin"] || userinfo["is_voucher_admin"]) {
      menu
       .append( $(SPAN).addClass("bigbutton").text("Лог пользователей")
         .click( function() {
           window.location = "?action=userlog"+(DEBUG?"&debug":"");
         })
       )
      ;
    };

    if(userinfo["is_login_admin"] || userinfo["is_voucher_admin"]) {
      menu
       .append( $(SPAN).addClass("bigbutton").text("Аудит лог")
         .click( function() {
           window.location = "?action=auditlog"+(DEBUG?"&debug":"");
         })
       )
      ;
    };

    menu.append( fixed_div );

    let action=getUrlParameter("action");
    switch(action) {
    case "sessions":
      actionSessions();
      break;
    case "logins":
      actionLogins();
      break;
    case "vouchers":
      actionVouchers();
      break;
    case "userlog":
      actionUserLog();
      break;
    case "auditlog":
      actionAuditLog();
      break;
    };

  });
});

function userinfo_btn() {
  let ret=$(DIV)
   .addClass("userinfo")
   .css({"display": "inline-block", "padding": "0.5em"})
   .append( $(LABEL)
     .addClass(["button", "ui-icon", "ui-icon-user"])
     .css({"margin-right": "0.5em"})
     .click(function() { $(this).closest(".userinfo").find(".hideable").toggle(); })
   )
   .append( $(DIV)
     .css({"display": "inline-block", "position": "absolute", "top": "0em",
            "left": "2em", "background-color": "white", "z-index": 1000000,
            "border": "1px solid black", "padding": "0.5em"}
     )
     .addClass("hideable")
     .hide()
     .append( $(SPAN).text(userinfo["name"]).css({"margin-right": "0.5em"}) )
     .append( $(SPAN).text(userinfo["login"]).css({"margin-right": "0.5em"}) )
     .append( $(LABEL).addClass(["ui-icon", "ui-icon-info", "button"]).title(jstr(userinfo))
       .click(function() { show_dialog(jstr(userinfo)); })
     )
     .append( $(LABEL).css({"margin-left": "0.2em"}) )
     .append( $(LABEL).title("Выход")
       .addClass(["button", "ui-icon", "ui-icon-logout"])
       .click(function() { window.location = "/logout"; })
     )
   )
  ;
  return ret;
};

function actionSessions() {
  workarea.empty();
  fixed_div.empty();

  let table = $(TABLE)
   .css({"white-space": "pre"})
   .append($(THEAD)
     .append($(TR)
       .append($(TH).text(""))
       .append($(TH).text("MAC"))
       .append($(TH).text("Доступ"))
       .append($(TH).text("Тип"))
       .append($(TH).text("Логин/Ваучер"))
       .append($(TH).text("Пользователь"))
       .append($(TH).text("Старт"))
       .append($(TH).text("Длительность"))
       .append($(TH).text("Состояние"))
     )
   )
   .append( $(TBODY) )
   .appendTo(workarea)
  ;

  let dt = table.DataTable({
    columns: [
      { name: "buttons", searchable: false, orderable: false },
      { name: "mac", orderable: false },
      { name: "level", orderable: false },
      { name: "type", orderable: false },
      { name: "login", orderable: false },
      { name: "username", orderable: false },
      { name: "created", orderable: false },
      { name: "duration", orderable: false },
      { name: "state", orderable: false }
    ],
    order: {
      name: "created_sort",
      dir: 'desc'
    },
    pageLength: 25
  });

  run_query({"action": "sessions"}, function(res) {
    if(res['ok']['sessions'] !== undefined) {
      for(let i in res['ok']['sessions']) {
        res['ok']['sessions'].sort(function(a,b) {
          return a['duration'] - b['duration'];
        });

        let session = res['ok']['sessions'][i];

        let type = "";
        if(session['auth_method'] !== undefined) {
          type = session['auth_method'];
        };

        let level = "";
        if(session['level'] !== undefined) {
          level = session['level'];
        };

        let log_voucher = "";

        if(session['login'] !== undefined) {
          log_voucher = session['login'];
        } else if(session['voucher'] !== undefined) {
          log_voucher = session['voucher'];
        };

        let start = from_unix_time(session['acct_start'], false, '');
        let duration = wdhm(session['duration']);

        let state = session['state'];
        if(session['next_state'] !== undefined && session['next_state'] !== session['state']) {
          state += "->" + session['next_state'];
        };

        let username_text = "";

        if(session["username"] !== undefined) {
          username_text = session["username"];
        } else if(session["auth_cache"] !== undefined && session["auth_cache"]["username"] !== undefined) {
          username_text = session["auth_cache"]["username"];
        };


        let tr = $(TR)
         .data('session', session)
         .append($(TD)
           .append($(LABEL)
             .title("Полная информация")
             .addClass(["button", "ui-icon", "ui-icon-info"])
             .click(function() {
               let session = $(this).closest("TR").data('session');
               show_dialog(jstr(session));
             })
           )
           .append($(SPAN).addClass("min05em"))
           .append($(LABEL)
             .title("Сброс сеанса")
             .addClass(["button", "ui-icon", "ui-icon-trash"])
             .click(function() {
               let row = $(this).closest("TR");
               let session = row.data('session');
               row.addClass("del_row");
               show_confirm("Подтвердите сброс сеанса.\nПользователь будет вынужден пройти авторизацию заново",
                 function() {
                   row.removeClass("del_row");
                   run_query({"action": "drop", "sess_id": session["sess_id"]}, function() {
                     row.remove();
                   });
                 },
                 {},
                 function() {
                   row.removeClass("del_row");
                 }
               );
             })
           )
         )
         .append($(TD)
           .addClass((session['vendor'] == "Random")?"random_mac":"factory_mac")
           .title(session['vendor'])
           .text(session['sta_id'])
         )
         .append($(TD)
           .text(level)
         )
         .append($(TD)
           .text(type)
         )
         .append($(TD)
           .text(log_voucher)
         )
         .append($(TD)
           .text(username_text)
         )
         .append($(TD)
           .text(start)
         )
         .append($(TD)
           .text(duration)
         )
         .append($(TD)
           .text(state)
         )
        ;

        dt.row.add(tr);
      };

      dt.draw();
    };
  });
};

function login_row(row_data) {
  let allowed = const_allowed_devices;
  let dev_number = 0;
  if(row_data["devs"] !== undefined && row_data["devs"]["allowed"] !== undefined) {
    allowed = row_data["devs"]["allowed"];
  };

  let mac_search = "";

  if(row_data["devs"] !== undefined && row_data["devs"]["devs"] !== undefined) {
    dev_number = keys(row_data["devs"]["devs"]).length;

    for(let mac in row_data["devs"]["devs"]) {
      for(let mfi in mac_formats) {
        mac_search += " " + format_mac(mac, mac_formats[mfi]);
      };
    };
  };


  let tr = $(TR)
   .data("data", row_data)
   .append( $(TD)
     .append( $(LABEL)
       .addClass(["button", "ui-icon", "ui-icon-edit"])
       .addClass("edit_btn")
       .click(function() {
         let tr = $(this).closest("TR");
         let table = tr.closest("TABLE");
         let dt = table.DataTable();
         let row = dt.row(tr);

         let row_data = tr.data("data");

         if(row.child.isShown()) {
           row.child.hide();
           return;
         };

         let allowed_val = "";

         if(row_data["devs"] !== undefined && row_data["devs"]["allowed"] !== undefined) {
           allowed_val = row_data["devs"]["allowed"];
         };

         let child_div = $(DIV)
          .addClass("child")
          .addClass("login_edit")
          .data("tr", tr)
         ;

         if(row_data["enabled"] !== 1) {
           child_div
            .append( $(DIV)
              .append( $(SPAN).text("Доступ отключен. У.з. либо не входит в нужную группу, либо отключена.")
                .addClass("disabled_user")
              )
            )
           ;
         };

         child_div
          .append( $(DIV)
            .append( $(SPAN).text("Лимит устройств: ")
              .title("Оставить поле пустым, для значения по умолчанию")
            )
            .append( tip("Оставить поле пустым, для значения по умолчанию") )
            .append( $(INPUT)
              .val(allowed_val)
              .title("Оставить поле пустым, для значения по умолчанию")
              .addClass("allowed")
              .css({"width": "3em"})
              .prop({"type": "number"})
              .inputStop(const_admin_input_save_timeout)
              .on("input_stop", function() {
                let tr = $(this).closest(".child").data("tr");
                let table = tr.closest("TABLE");
                let row_data = tr.data("data");
                let dt = table.DataTable();
                let row = dt.row(tr);

                let input = $(this);

                let value = input.val();

                if(!/^\d*$/.test(value)) {
                  input.animateHighlight("red", 300);
                  return;
                };

                if(/^\d+$/.test(value)) {
                  value = String(Number(value));
                };

                let dev_number = 0;
                if(row_data["devs"] !== undefined && row_data["devs"]["devs"] !== undefined) {
                  dev_number = keys(row_data["devs"]["devs"]).length;
                };

                run_query({"action": "set_login_allowed", "allowed": value, "login": row_data["login"]},
                function(res) {
                  let new_tr = login_row(res["ok"]["row"]);

                  row.remove();
                  dt.row.add(new_tr);
                  dt.draw();
                  new_tr.find(".edit_btn").trigger("click");
                });

              })
            )
            .append( $(SPAN).text(" (по умолчанию: "+String(const_allowed_devices)+")")
              .title("Оставить поле пустым, для значения по умолчанию")
            )
          )
         ;

         let macs_tbody = $(TBODY)
          .addClass("login_mac_tbody")
         ;

         let levels = keys(const_access_levels);

         levels.sort();

         if(row_data["devs"] !== undefined && row_data["devs"]["devs"] !== undefined &&
           keys(row_data["devs"]["devs"]).length !== 0 &&
         true) {

           let macs_list = keys(row_data["devs"]["devs"]);
           macs_list.sort(function(a, b) { return num_compare(a, b); });

           for(let mi in macs_list) {
             let mac = macs_list[mi];

             let level = "";

             let level_sel = $(SELECT)
              .addClass("mac_level_sel")
              .append(
                $(OPTION).text("По умолч.").val("")
              )
              .on("change", function() {
                let val = $(this).val();
                let tr = $(this).closest(".child").data("tr");
                let row_data = tr.data("data");

                let mac = $(this).closest("TR").data("mac");

                run_query({"action": "set_login_dev_level", "login": row_data["login"], "mac": mac, "level": val},
                function() {})
              })
             ;

             for(let li in levels) {
               let access_level = levels[li];

               level_sel
                .append( $(OPTION)
                  .val(access_level)
                  .text(const_access_levels[access_level]["Name"])
                )
               ;
             };

             if(row_data["devs"]["devs"][mac]["level"] !== undefined) {
               level = row_data["devs"]["devs"][mac]["level"];
             };

             level_sel.val(level);

             let until = "";
             let until_left = "";
             if(row_data["devs"]["devs"][mac]["auth_cache"] !== undefined &&
                row_data["devs"]["devs"][mac]["auth_cache"]["time"] !== undefined &&
                (row_data["devs"]["devs"][mac]["auth_cache"]["time"] + const_reauth_period) > unix_timestamp()
             ) {
               until = from_unix_time(row_data["devs"]["devs"][mac]["auth_cache"]["time"] + const_reauth_period);
               until_left = wdhm((row_data["devs"]["devs"][mac]["auth_cache"]["time"] + const_reauth_period)
                                 - unix_timestamp()
               );
             };

             let swap_after = "Уже разрешена";
             let swap_left = "";

             if((row_data["devs"]["devs"][mac]["swap_from"] + const_min_dev_swap_period) > unix_timestamp()) {
               swap_after = from_unix_time(row_data["devs"]["devs"][mac]["swap_from"] + const_min_dev_swap_period);
               swap_left = wdhm((row_data["devs"]["devs"][mac]["swap_from"] + const_min_dev_swap_period)
                                - unix_timestamp()
               );
             };

             let auth_level_sel = $(SELECT)
              .append( $(OPTION).text("---").val("") )
             ;

             auth_level_sel.val("");

             for(let li in levels) {
               let access_level = levels[li];

               auth_level_sel
                .append( $(OPTION)
                  .val(access_level)
                  .text(const_access_levels[access_level]["Name"])
                )
               ;
             };

             let last_logon = "";
             if(row_data["devs"]["devs"][mac]["last_logon"] !== undefined) {
               last_logon = from_unix_time(row_data["devs"]["devs"][mac]["last_logon"]);
             };

             let dpsk = "";
             if(row_data["devs"]["devs"][mac]["dpsk"] !== undefined) {
               dpsk = row_data["devs"]["devs"][mac]["dpsk"];
             };

             let mac_tr = $(TR)
              .data("data", row_data["devs"]["devs"][mac])
              .data("mac", mac)
              .append( $(TD)
                .append( $(LABEL).addClass(["mac_del_btn", "ui-icon", "ui-icon-trash", "button"])
                  .title("Удалить устройство из списка устройств пользователя. Сеанс будет сброшен")
                  .css({"margin-right": "0.5em"})
                  .click(function() {
                    let tr = $(this).closest(".child").data("tr");
                    let table = tr.closest("TABLE");
                    let row_data = tr.data("data");

                    let dt = table.DataTable();
                    let row = dt.row(tr);

                    let mac_row = $(this).closest("TR");
                    let mac = $(this).closest("TR").data("mac");

                    mac_row.addClass("del_row");

                    show_confirm("Подтвердите удаление устройства.\n"
                                   + "Существующий сеанс будет сброшен, пользователь будет\n"
                                   + "вынужден пройти авторизацию повторно.",
                    function() {
                      run_query({"action": "del_login_dev", "login": row_data["login"], "mac": mac},
                      function(res) {
                        let new_tr = login_row(res["ok"]["row"]);

                        row.remove();
                        dt.row.add(new_tr);
                        dt.rows().invalidate() ;
                        dt.draw();
                        new_tr.find(".edit_btn").trigger("click");
                      });
                    },
                    {},
                    function() {
                        mac_row.removeClass("del_row");
                    });
                  })
                )
                .append( $(SPAN).text(mac)
                  .title( row_data["devs"]["devs"][mac]["vendor"] )
                )
              )
              .append( $(TD)
                .append( level_sel
                )
              )
              .append( $(TD)
                .append( $(SPAN).text(last_logon)
                )
              )
              .append( $(TD)
                .append( (until_left != "")? $(LABEL):$(LABEL)
                  .addClass(["ui-icon", "ui-icon-plus", "button"])
                  .title("Авторизовать принудительно")
                  .css({"margin-right": "0.5em"})
                  .click(function() {
                    let tr = $(this).closest(".child").data("tr");
                    let table = tr.closest("TABLE");
                    let row_data = tr.data("data");

                    let dt = table.DataTable();
                    let row = dt.row(tr);

                    let mac_row = $(this).closest("TR");
                    let mac = $(this).closest("TR").data("mac");

                    let td = $(this).closest("TD");

                    let level = td.find("SELECT").val();

                    if(level == "") {
                      td.find("SELECT").animateHighlight("red", 300);
                      return;
                    };

                    show_confirm("Подтвердите действие\n"
                                 + "Существующий сеанс с этим MAC будет сброшен",
                      function() {
                        run_query({"action": "manual_cache_login_dev", "login": row_data["login"], "mac": mac,
                          "level": level
                          },
                          function(res) {
                            let new_tr = login_row(res["ok"]["row"]);

                            row.remove();
                            dt.row.add(new_tr);
                            dt.rows().invalidate() ;
                            dt.draw();
                            new_tr.find(".edit_btn").trigger("click");
                          }
                        );
                      }
                    );
                  })
                )
                .append( (until_left != "")? $(LABEL): auth_level_sel )
                .append( (until_left == "")? $(LABEL):$(LABEL)
                  .addClass(["ui-icon", "ui-icon-arrow-u", "button"])
                  .title("Продлить авторизацию с текущего момента")
                  .css({"margin-right": "0.5em"})
                  .click(function() {
                    let tr = $(this).closest(".child").data("tr");
                    let table = tr.closest("TABLE");
                    let row_data = tr.data("data");

                    let dt = table.DataTable();
                    let row = dt.row(tr);

                    let mac_row = $(this).closest("TR");
                    let mac = $(this).closest("TR").data("mac");

                    let td = $(this).closest("TD");

                    td.addClass("prolong");

                    show_confirm("Подтвердите действие",
                    function() {
                      run_query({"action": "prolong_cache_login_dev", "login": row_data["login"], "mac": mac},
                      function(res) {
                        let new_tr = login_row(res["ok"]["row"]);

                        row.remove();
                        dt.row.add(new_tr);
                        dt.rows().invalidate() ;
                        dt.draw();
                        new_tr.find(".edit_btn").trigger("click");
                      });
                    },
                    {},
                    function() {
                        td.removeClass("prolong");
                    });
                  })
                )
                .append( (until_left == "")? $(LABEL):$(LABEL)
                  .addClass(["ui-icon", "ui-icon-arrow-d", "button"])
                  .title("Удалить из кеша авторизации")
                  .css({"margin-right": "0.5em"})
                  .click(function() {
                    let tr = $(this).closest(".child").data("tr");
                    let table = tr.closest("TABLE");
                    let row_data = tr.data("data");

                    let dt = table.DataTable();
                    let row = dt.row(tr);

                    let mac_row = $(this).closest("TR");
                    let mac = $(this).closest("TR").data("mac");

                    let td = $(this).closest("TD");

                    td.addClass("del_row");

                    show_confirm("Подтвердите действие.\n"
                                   + "Существующий сеанс будет сброшен, пользователь будет\n"
                                   + "вынужден пройти авторизацию повторно.",
                    function() {
                      run_query({"action": "unauth_login_dev", "login": row_data["login"], "mac": mac},
                      function(res) {
                        let new_tr = login_row(res["ok"]["row"]);

                        row.remove();
                        dt.row.add(new_tr);
                        dt.rows().invalidate() ;
                        dt.draw();
                        new_tr.find(".edit_btn").trigger("click");
                      });
                    },
                    {},
                    function() {
                        td.removeClass("del_row");
                    });
                  })
                )
                .append( $(SPAN).text(until)
                  .title( until_left )
                  .addClass("tooltip")
                )
              )
              .append( $(TD)
                .append( (swap_left == "")? $(LABEL):$(LABEL)
                  .addClass(["mac_allow_swap_btn", "ui-icon", "ui-icon-arrow-u", "button"])
                  .title("Разрешить замену уже сейчас")
                  .css({"margin-right": "0.5em"})
                  .click(function() {
                    let tr = $(this).closest(".child").data("tr");
                    let table = tr.closest("TABLE");
                    let row_data = tr.data("data");

                    let dt = table.DataTable();
                    let row = dt.row(tr);

                    let mac_row = $(this).closest("TR");
                    let mac = $(this).closest("TR").data("mac");

                    let td = $(this).closest("TD");

                    td.addClass("del_row");

                    show_confirm("Подтвердите действие",
                    function() {
                      run_query({"action": "allow_swap_login_dev", "login": row_data["login"], "mac": mac},
                      function(res) {
                        let new_tr = login_row(res["ok"]["row"]);

                        row.remove();
                        dt.row.add(new_tr);
                        dt.rows().invalidate() ;
                        dt.draw();
                        new_tr.find(".edit_btn").trigger("click");
                      });
                    },
                    {},
                    function() {
                        td.removeClass("del_row");
                    });
                  })
                )
                .append( $(SPAN).text(swap_after)
                  .title( swap_left )
                  .addClass("tooltip")
                )
              )
              .append( $(TD)
                .append( $(SPAN).text( dpsk) )
              )
             ;

             macs_tbody.append( mac_tr );
           };

         };

         let new_mac_level_sel = $(SELECT)
          .addClass("level")
          .append( $(OPTION).val("").text("По умолч.") )
         ;
         new_mac_level_sel.val("");

         for(let li in levels) {
           let access_level = levels[li];

           new_mac_level_sel
            .append( $(OPTION)
              .val(access_level)
              .text(const_access_levels[access_level]["Name"])
            )
           ;
         };


         child_div
          .append( $(DIV)
            .append( $(TABLE)
              .append( $(THEAD)
                .append( $(TR)
                  .append( $(TH).text("MAC") )
                  .append( $(TH).text("Доступ")
                    .append( tip("Уровень по умолчанию задается настройками системы и может варьироваться"
                                 + " в зависимости от способа авторизации\n"
                                 + "Если задать для MAC уровень доступа, то он будет установлен принудительно,"
                                 + " вне зависимости от способа авторизации"
                      )
                    )
                  )
                  .append( $(TH).text("Посл. вход") )
                  .append( $(TH).text("До")
                    .append( tip("Дата, после которой потребуется повторная авторизация пользователя") )
                  )
                  .append( $(TH).text("Замена после")
                    .append( tip("Дата, после которой возможна самостоятельная замена"
                                 + " устройства пользователем на другое")
                    )
                  )
                  .append( $(TH).text("PSK")
                    .append( tip("Ключ для подключения к сети " + const_secure_ssid)
                    )
                  )
                )
              )
              .append( macs_tbody )
              .append( $(TFOOT)
                .append( $(TR)
                  .append( $(TD)
                    .append( $(LABEL)
                      .addClass(["button", "ui-icon", "ui-icon-plus"])
                      .title("Добавить устройство вручную")
                      .css({"margin-right": "0.5em"})
                      .click(function() {
                        let mac_tr = $(this).closest("TR");
                        let mac = format_mac(mac_tr.find("INPUT.mac").val(), "l3h", true);
                        if(mac === null) {
                          mac_tr.find("INPUT.mac").animateHighlight("red", 300);
                          return;
                        };

                        let tr = $(this).closest(".child").data("tr");
                        let table = tr.closest("TABLE");
                        let row_data = tr.data("data");

                        let dt = table.DataTable();
                        let row = dt.row(tr);

                        if(row_data["devs"] !== undefined && row_data["devs"]["devs"] !== undefined &&
                          row_data["devs"]["devs"][mac] !== undefined
                        ) {
                          mac_tr.find("INPUT.mac").animateHighlight("red", 300);
                          return;
                        };

                        let level = mac_tr.find("SELECT.level").val();

                        run_query({"action": "add_login_dev", "login": row_data["login"], "mac": mac,
                                  "level": level},
                          function(res) {
                            let new_tr = login_row(res["ok"]["row"]);

                            row.remove();
                            dt.row.add(new_tr);
                            dt.rows().invalidate() ;
                            dt.draw();
                            new_tr.find(".edit_btn").trigger("click");
                          }
                        );

                      })
                    )
                    .append( $(INPUT).addClass("mac")
                      .css({"width": "10em", "font-family": "monospace"})
                      .prop({"placeholder": "xxxx-xxxx-xxxx"})
                    )
                  )
                  .append( $(TD)
                    .append( new_mac_level_sel )
                  )
                  .append( $(TD)
                  )
                  .append( $(TD)
                  )
                  .append( $(TD)
                  )
                )
              )
            )
          )
         ;

         row.child( child_div ).show();
       })
     )
   )
   .append( $(TD).text(row_data["login"]) )
   .append( $(TD).text(row_data["name"]) )
   .append( $(TD).addClass("mac_search").text(mac_search) )
   .append( $(TD).addClass("devs_number").text(String(dev_number) + "/" + String(allowed)) )
  ;

  if(row_data["enabled"] !== 1) {
    tr.addClass("disabled_user");
  };

  return tr;
};

function actionLogins() {
  workarea.empty();
  fixed_div.empty();

  let table = $(TABLE)
   .append( $(THEAD)
     .append( $(TR)
       .append( $(TH).text("") )
       .append( $(TH).text("Логин") )
       .append( $(TH).text("ФИО") )
       .append( $(TH).text("") ) // macs for search, invisible
       .append( $(TH).text("Устройств/из") )
     )
   )
   .appendTo(workarea)
  ;

  let tbody = $(TBODY).appendTo(table);

  let dt = table.DataTable({
    columns: [
      { searchable: false },
      null,
      null,
      { visible: false },
      { searchable: false }
    ],
    order: [
      [ 1, 'asc' ]
    ],
    pageLength: 25
  });

  run_query({"action": "list_logins"}, function(res) {
    for(let i in res["ok"]["logins"]) {
      let row_data = res["ok"]["logins"][i];

      let tr = login_row(row_data);

      dt.row.add(tr);
    };

    dt.draw();
  });
};

function voucherRow(row_data) {
  let level = "По умолч.";
  if(row_data["level"] !== undefined &&
    const_access_levels[row_data["level"]] !== undefined
  ) {
    level = const_access_levels[row_data["level"]]["Name"];
  };

  let status_td = $(TD);

  if(row_data["until"] > (unix_timestamp() + 24*60*60)) {
    if(row_data["mac"] === undefined) {
      status_td
       .append( $(SPAN)
         .text("не активирован")
         .css({"color": "darkgreen"})
       )
      ;
    } else {
      status_td
       .append( $(SPAN)
         .text("активирован")
         .css({"color": "blue"})
       )
       .append( $(BR) )
       .append( $(SPAN).text(from_unix_time(row_data["activated"])) )
      ;
    };
  } else if(row_data["until"] > unix_timestamp()) {
    if(row_data["mac"] === undefined) {
      status_td
       .append( $(SPAN)
         .text("не активирован")
         .css({"color": "darkorange"})
       )
       .append( $(BR) )
       .append( $(SPAN)
         .text("скоро истекает")
         .css({"color": "darkorange"})
       )
      ;
    } else {
      status_td
       .append( $(SPAN)
         .text("активирован (скоро истекает)")
         .css({"color": "darkorange"})
       )
       .append( $(BR) )
       .append( $(SPAN).text(from_unix_time(row_data["activated"]))
         .css({"color": "darkorange"})
       )
      ;
    };
  } else {
    if(row_data["mac"] === undefined) {
      status_td
       .append( $(SPAN)
         .text("не активирован")
         .css({"color": "darkred"})
       )
       .append( $(BR) )
       .append( $(SPAN)
         .text("истек")
         .css({"color": "darkred"})
       )
      ;
    } else {
      status_td
       .append( $(SPAN)
         .text("активирован (истёк)")
         .css({"color": "darkred"})
       )
       .append( $(BR) )
       .append( $(SPAN).text(from_unix_time(row_data["activated"]))
         .css({"color": "darkred"})
       )
      ;
    };
  };

  let mac_search = "";

  if(row_data["mac"] !== undefined) {
    for(let mfi in mac_formats) {
      mac_search += " " + format_mac(row_data["mac"], mac_formats[mfi]);
    };

  };

  let mac_text = format_mac(row_data["mac"], "h3c");

  let dpsk = "";

  if(row_data["dpsk"] !== undefined) {
    dpsk = row_data["dpsk"];
  };

  let ret = $(TR)
   .data("data", row_data)
   .append( $(TD)
     .css({"white-space": "pre"})
     .append( $(INPUT)
       .addClass("select")
       .prop({"type": "checkbox"})
     )
     .append( $(LABEL).addClass("min05em") )
     .append( $(LABEL)
       .addClass(["button", "ui-icon", "ui-icon-edit"])
       .addClass("edit_btn")
       .click(function() {
         let tr = $(this).closest("TR");
         let table = tr.closest("TABLE");
         let dt = table.DataTable();
         let row = dt.row(tr);

         let row_data = tr.data("data");

         if(row.child.isShown()) {
           row.child.hide();
           return;
         };

         let child_div = $(DIV)
          .addClass("child")
          .addClass("login_edit")
          .data("tr", tr)
         ;

         if(row_data["changed"] !== undefined) {
           child_div
            .append( $(DIV)
              .append( $(SPAN).text("Последнее изменение: ") )
              .append( $(SPAN).text(from_unix_time(row_data["changed"])) )
              .append( $(SPAN).text(" " + row_data["changed_by_name"]).title(row_data["changed_by_user"]) )
            )
           ;
         };

         if(row_data["mailed_to"] !== undefined && row_data["mailed_to"] !== "") {
           child_div
            .append( $(DIV)
              .append( $(SPAN).text("Отправлено: ") )
              .append( $(SPAN).text(row_data["mailed_to"]) )
            )
           ;
         };


         let levels = keys(const_access_levels);

         levels.sort();

         let level_sel = $(SELECT)
          .addClass("voucher_level_sel")
          .append(
            $(OPTION).text("По умолч.").val("")
          )
          .on("change", function() {
            let val = $(this).val();
            let tr = $(this).closest(".child").data("tr");
            let table = tr.closest("TABLE");

            let row_data = tr.data("data");

            let voucher = row_data["voucher"];

            let dt = table.DataTable();
            let row = dt.row(tr);


            run_query({"action": "set_voucher_level", "voucher": voucher, "level": val},
            function(res) {
              let new_tr = voucherRow(res["ok"]["voucher"]);

              row.remove();
              dt.row.add(new_tr);
              dt.rows().invalidate() ;
              dt.draw();
              new_tr.find(".edit_btn").trigger("click");
            })
          })
         ;

         for(let li in levels) {
           let access_level = levels[li];

           level_sel
            .append( $(OPTION)
              .val(access_level)
              .text(const_access_levels[access_level]["Name"])
            )
           ;
         };

         if(row_data["level"] != undefined) {
           level_sel.val(row_data["level"]);
         } else {
           level_sel.val("");
         };

         child_div
          .append( $(DIV)
            .append( $(LABEL).text("Уровень доступа: ")
            )
            .append( level_sel )
          )
         ;

         let until_date = new Date(row_data["until"]*1000);

         let picker = $(INPUT)
          .addClass("until")
          .css({"width": "6em"})
          .datepicker({
            dateFormat: "dd.mm.yy",
            firstDay: 1
          })
          .on("change", function() {
            let until_date = $(this).datepicker("getDate");
            if(until_date === null) {
              $(this).animateHighlight("red", 300);
              return;
            };

            until_date.setHours(23);
            until_date.setMinutes(59);
            until_date.setSeconds(59);

            let until = unix_timestamp(until_date);

            let tr = $(this).closest(".child").data("tr");
            let table = tr.closest("TABLE");

            let row_data = tr.data("data");

            let voucher = row_data["voucher"];

            let dt = table.DataTable();
            let row = dt.row(tr);


            run_query({"action": "set_voucher_until", "voucher": voucher, "until": until},
            function(res) {
              let new_tr = voucherRow(res["ok"]["voucher"]);

              row.remove();
              dt.row.add(new_tr);
              dt.rows().invalidate() ;
              dt.draw();
              new_tr.find(".edit_btn").trigger("click");
            })
          })
          .datepicker("setDate", until_date)
         ;

         child_div
          .append( $(DIV)
            .append( $(LABEL).text("Срок действия: ")
            )
            .append( picker )
          )
         ;

         row.child( child_div ).show();
       })
     )
   )
   .append( $(TD)
     .css({"white-space": "pre"})
     .append( $(SPAN).text(row_data["voucher"])
       .addClass("voucher")
     )
     .append( $(LABEL).addClass("min05em") )
     .append( $(LABEL)
       .addClass(["button", "ui-icon", "ui-icon-copy"])
       .click(function() {
         let voucher = $(this).closest("TR").data("data")["voucher"];
         let flash = $(this).closest("TD").find(".voucher");
         try {
           navigator.clipboard.writeText(voucher).then(
             function() {
               /* clipboard successfully set */
               flash.animateHighlight("green", 300);
             },
             function() {
               /* clipboard write failed */
               window.alert('Opps! Your browser does not support the Clipboard API')
             }
           );
         } catch(e) {
           alert(e);
         };
       })
     )
   )
   .append( $(TD)
     .append( $(SPAN).text(level) )
   )
   .append( $(TD)
     .append( $(SPAN).text(from_unix_time(row_data["until"])) )
   )
   .append( status_td
   )
   .append( $(TD).text(mac_search)
   )
   .append( $(TD)
     .append( $(SPAN).text(mac_text) )
   )
   .append( $(TD).text(row_data["added"])
   )
   .append( $(TD)
     .append( $(SPAN).text(from_unix_time(row_data["added"])))
     .append( $(BR) )
     .append( $(SPAN).text(row_data["by_name"]).title(row_data["by_login"]) )
   )
   .append( $(TD)
     .append( $(SPAN)
       .text(dpsk)
       .addClass("dpsk")
     )
     .append( $(LABEL)
       .addClass(["button", "ui-icon", "ui-icon-copy"])
       .css({"margin-left": "0.5em"})
       .click(function() {
         let copytext = $(this).closest("TR").data("data")["dpsk"];
         if(copytext === undefined) {
           return;
         };

         let flash = $(this).closest("TD").find(".dpsk");
         try {
           navigator.clipboard.writeText(copytext).then(
             function() {
               /* clipboard successfully set */
               flash.animateHighlight("green", 300);
             },
             function() {
               /* clipboard write failed */
               window.alert('Opps! Your browser does not support the Clipboard API')
             }
           );
         } catch(e) {
           alert(e);
         };
       })
     )
   )
   .append( $(TD)
     .append( $(SPAN)
       .text(row_data["comment"])
       .title(row_data["comment"])
     )
   )
  ;

  return ret;
};

function actionVouchers() {
  workarea.empty();
  fixed_div.empty();

  fixed_div
   .append( $(LABEL)
     .addClass(["button", "ui-icon", "ui-icon-plus"])
     .title("Создать ваучеры")
     .click(function() {
       let dt = $(".vouchers_table").DataTable();

       add_vouchers_dlg(function(res) {
         for(let voucher in res["ok"]["vouchers"]) {
           let tr = voucherRow(res["ok"]["vouchers"][voucher]);
           dt.row.add(tr);
         };
         dt.draw();
       });
     })
   )
   .append( $(SPAN).text(" Создать ваучеры")
   )
  ;

  let table = $(TABLE)
   .addClass("vouchers_table")
   .append( $(THEAD)
     .append( $(TR)
       .append( $(TH)
         .append( $(LABEL)
           .addClass(["button", "ui-icon", "ui-icon-print"])
           .click(function() {
             let list = [];
             
             let dt = $(this).closest("TABLE").DataTable();
             dt.rows().every(function() {
               let row = this;
               let tr = $(row.node());
               let row_data = tr.data("data");
               let voucher = row_data["voucher"];
               let selected = tr.find("INPUT.select").is(":checked");

               if(selected) {
                 list.push(row_data);
               };
             });

             if(list.length > 0) {
               let print_cont = $(DIV);
               for(let i in list) {
                 let row_data = list[i];
                 print_cont
                  .append( $(DIV)
                    .css({"display": "inline-block", "border": "1px solid black", "margin": "0px", "padding": "1em",
                      "color": "black", "white-space": "pre", "font-size": "9pt"
                    })
                    .append( $(DIV)
                      .css({"text-align": "center", "font-size": "larger"})
                      .text("Ваучер/Voucher: " + row_data["voucher"])
                    )
                    .append( $(DIV)
                      .text("Действителен до/Valid until: " + from_unix_time(row_data["until"]))
                    )
                    .append( $(DIV)
                      .css({"font-size": "smaller"})
                      .text("ВАЖНО! Ваучером можно воспользоваться только с одного\n"
                            + "устройства, после активации использовать его на другом устройстве\n"
                            + "невозможно"
                      )
                    )
                    .append( $(DIV)
                      .css({"font-size": "smaller"})
                      .text("IMPORTANT! Thiser could be used from one device only, you can't use\n"
                            + "it on the other device after."
                      )
                    )
                    .append( $(DIV)
                      .css({"font-size": "smaller"})
                      .text("Создал: " + row_data["by_name"])
                    )
                    .append( $(DIV)
                      .css({"font-size": "smaller"})
                      .text("Поддержка/Support: " + const_support_contact)
                    )
                  )
                 ;
               };

               var tab = window.open('about:blank', '_blank');
               tab.document.write(print_cont.prop('outerHTML'));
               tab.document.close();
               tab.print();
             };
           })
         )
         .append( $(LABEL).addClass("min05em") )
         .append( $(LABEL)
           .addClass(["button", "ui-icon", "ui-icon-trash"])
           .click(function() {
             let list = [];
             let rows = [];
             
             let dt = $(this).closest("TABLE").DataTable();
             dt.rows().every(function() {
               let row = this;
               let tr = $(row.node());
               let row_data = tr.data("data");
               let voucher = row_data["voucher"];
               let selected = tr.find("INPUT.select").is(":checked");

               if(selected) {
                 list.push(voucher);
                 rows.push(row);
               };
             });

             if(list.length > 0) {
               show_confirm_checkbox("Подтвердите удаление выбраных ваучеров.\nВнимание, отмена будет невозможна!",
               function() {
                 run_query({"action": "del_vouchers", "vouchers": list}, function() {
                   for(let i in rows) {
                     rows[i].remove();
                   };
                   dt.rows().invalidate() ;
                   dt.draw();
                 });
               });
             };
           })
         )
       )
       .append( $(TH).text("Ваучер") )
       .append( $(TH).text("Уровень") )
       .append( $(TH).text("Срок действия") )
       .append( $(TH).text("Статус") )
       .append( $(TH).text("") ) // macs for search, invisible
       .append( $(TH).text("MAC") )
       .append( $(TH).text("") ) // create date for search, invisible
       .append( $(TH).text("Создан") )
       .append( $(TH)
         .append( $(SPAN).text("PSK") )
         .append( tip("Ключ для доступа к сети " + const_secure_ssid) )
       )
       .append( $(TH).text("Коментарий") )
     )
   )
   .appendTo(workarea)
  ;

  let tbody = $(TBODY).appendTo(table);

  let dt = table.DataTable({
    columns: [
      { name: "buttons", searchable: false, orderable: false },
      { name: "voucher", orderable: false },
      { name: "level", orderable: false },
      { name: "until", orderable: false },
      { name: "status", orderable: false },
      { name: "mac_search", visible: false, orderable: false },
      { name: "mac", orderable: false },
      { name: "created_sort", visible: false, searchable: false },
      { name: "created", orderable: false },
      { name: "dpsk", orderable: false, searchable: false },
      { name: "comment", orderable: false }
    ],
    order: {
      name: "created_sort",
      dir: 'desc'
    },
    pageLength: 25
  });

  run_query({"action": "get_vouchers"}, function(res) {
    for(let voucher in res["ok"]["vouchers"]) {
      let tr = voucherRow(res["ok"]["vouchers"][voucher]);
      dt.row.add(tr);
    };
    dt.draw();
  });
};

function tip(tip_text) {
  return $(LABEL)
   .addClass("tip")
   .addClass("tooltip")
   .title(tip_text)
   .text("?")
   .data("data", tip_text)
  ;
};

function add_vouchers_dlg(on_done) {
  let levels = keys(const_access_levels);

  levels.sort();

  let level_sel = $(SELECT)
   .addClass("level")
   .append( $(OPTION).text("По умолч.").val("") )
  ;

  level_sel.val("");

  for(let li in levels) {
    let access_level = levels[li];

    level_sel
     .append( $(OPTION)
       .val(access_level)
       .text(const_access_levels[access_level]["Name"])
     )
    ;
  };

  let today = new Date();
  let until_date = today;
  
  until_date.setDate(today.getDate() + const_voucher_days);
  until_date.setHours(23);
  until_date.setMinutes(59);
  until_date.setSeconds(59);

  let date_picker = $(INPUT)
   .addClass("until")
   .css({"width": "6em"})
  ;

  let dialog = $(DIV).addClass("dialog_start")
   .data("donefunc", on_done)
   .title("Добавление ваучеров")
   .append( $(TABLE)
     .append( $(TR)
       .append( $(TD)
         .append( $(SPAN).text("Количество")
         )
       )
       .append( $(TD)
         .append( $(INPUT).addClass("count")
           .prop({"type": "number"})
           .css({"width": "4em"})
           .val("1")
         )
         .append( $(SPAN).text(" " + String(const_max_vouchers_gen) + " max") )
       )
     )
     .append( $(TR)
       .append( $(TD)
         .append( $(SPAN).text("Уровень доступа")
         )
         .append( tip("Уровень по умолчанию задается настройками системы\n"
                      + "Если задать для Ваучера уровень доступа, то он будет установлен принудительно"
           )
         )
       )
       .append( $(TD)
         .append( level_sel
         )
       )
     )
     .append( $(TR)
       .append( $(TD)
         .append( $(SPAN).text("Коментарий")
         )
       )
       .append( $(TD)
         .append( $(INPUT).addClass("comment")
           .css({"width": "30em"})
         )
       )
     )
     .append( $(TR)
       .append( $(TD)
         .append( $(SPAN).text("Срок действия (включительно)")
         )
       )
       .append( $(TD)
         .append( date_picker
         )
       )
     )
     .append( $(TR)
       .append( $(TD)
         .append( $(SPAN).text("Отправить на")
         )
       )
       .append( $(TD)
         .append( $(INPUT).addClass("email")
           .prop({"placeholder": "user@email.dom"})
           .css({"width": "20em"})
           .val(userinfo["email"])
         )
       )
     )
   )
  ;

  let buttons = [];

  buttons.push({
    'text': 'Добавить',
    'click': function() {
      let dlg = $(this);

      let until_date = dlg.find("INPUT.until").datepicker("getDate");
      if(until_date === null) {
        dlg.find("INPUT.until").animateHighlight("red", 300);
        return;
      };

      until_date.setHours(23);
      until_date.setMinutes(59);
      until_date.setSeconds(59);

      let until = unix_timestamp(until_date);

      let count = dlg.find("INPUT.count").val();
      if(!/^\d+$/.test(count) || Number(count) > const_max_vouchers_gen ||
        Number(count) < 1
      ) {
        dlg.find("INPUT.count").animateHighlight("red", 300);
        return;
      };
     

      let email = String(dlg.find("INPUT.email").val()).trim();
      if(email !== "" && !/^[a-zA-Z0-9\_\-\.]+@[a-zA-Z0-9\_\-]+[a-zA-Z0-9\_\-\.]?[a-zA-Z0-9]+$/.test(email)) {
        dlg.find("INPUT.email").animateHighlight("red", 300);
        return;
      };

      let comment = String(dlg.find("INPUT.comment").val()).trim();
      if(comment == "") {
        dlg.find("INPUT.comment").animateHighlight("red", 300);
        return;
      };

      let level = dlg.find("SELECT.level").val();
      let donefunc = dlg.data("donefunc");

      run_query({"action": "gen_vouchers", "count": count, "email": email, "comment": comment, "level": level,
                 "until": until}, function(res) {

        dlg.dialog( "close" );
        if(donefunc !== undefined) {
          donefunc(res);
        };

      });
    }
  });

  buttons.push({
    'text': 'Отмена',
    'click': function() {$(this).dialog( "close" );},
  });

  let dialog_options = {
    modal:true,
    maxHeight:1000,
    maxWidth:1800,
    minWidth:1200,
    width: "auto",
    height: "auto",
    buttons: buttons,
    close: function() {
      $(this).dialog("destroy");
      $(this).remove();
    }
  };

  dialog.appendTo("BODY");
  dialog.dialog( dialog_options );

  dialog.find("INPUT.until")
   .datepicker({
     dateFormat: "dd.mm.yy",
     firstDay: 1,
     minDate: new Date()
   })
   .datepicker("setDate", until_date)
  ;

  dialog.find("INPUT.comment").focus();
};

function actionUserLog() {
  workarea.empty();
  fixed_div.empty();

  let table = $(TABLE)
   .css({"white-space": "pre"})
   .append( $(THEAD)
     .append( $(TR)
       .append( $(TH) ) // (i) button
       .append( $(TH).text("Источник") )
       .append( $(TH).text("Событие") )
       .append( $(TH).text("Состояние") )
       .append( $(TH).text("") ) //date sorting
       .append( $(TH).text("Время") )
       .append( $(TH).text("") ) // sess_id search
       .append( $(TH).text("") ) // mac search
       .append( $(TH).text("MAC") )
       .append( $(TH).text("IP") )
       .append( $(TH).text("Логин/Ваучер") )
       .append( $(TH).text("Пользователь") )
       .append( $(TH).text("Доп. информация") )
     )
   )
   .append( $(TBODY) )
   .appendTo( workarea )
  ;

  let dt = table.DataTable({
    columns: [
      { name: "buttons", searchable: false, orderable: false },
      { name: "source", searchable: false, orderable: false },
      { name: "event", orderable: false },
      { name: "state", orderable: false },
      { name: "timesort", visible: false, orderable: true },
      { name: "time", orderable: false },
      { name: "sess_id_search", visible: false, orderable: false },
      { name: "mac_search", visible: false, orderable: false },
      { name: "mac", orderable: false },
      { name: "ip", orderable: false },
      { name: "login", orderable: false },
      { name: "username", orderable: false },
      { name: "info", orderable: false }
    ],
    order: {
      name: "timesort",
      dir: 'desc'
    },
    pageLength: 25
  });

  run_query({"action": "get_userlog"}, function(res) {
    for(let i in res["ok"]["events"]) {
      let row_data = JSON.parse(res["ok"]["events"][i]);

      let mac_search = "";
      let mac_text = "";

      let sta_id = "";
      let sta_ip = "";

      if(row_data["sta_id"] !== undefined) {
        sta_id  = row_data["sta_id"];
      } else if(row_data["session"] !== undefined) {
        sta_id  = row_data["session"]["sta_id"];
      };

      if(sta_id != "") {
        for(let mfi in mac_formats) {
          mac_search += " " + format_mac(sta_id, mac_formats[mfi]);
        };
        mac_text = format_mac(sta_id, "h3c");
      };

      if(row_data["sta_ip"] !== undefined && row_data["sta_ip"] !== "0.0.0.0") {
        sta_ip = row_data["sta_ip"];
      } else if(row_data["session"] !== undefined && row_data["session"]["sta_ip"] !== undefined &&
         row_data["session"]["sta_ip"] !== "0.0.0.0"
      ) {
        sta_ip = row_data["session"]["sta_ip"];
      };

      let event_text = "";

      if(row_data["log"] == "portal_log") {
        event_text = row_data["event"];
      } else if(row_data["log"] == "radius_log") {
        event_text = row_data["message"];
      };

      let login_text = "";
      let username_text = "";

      if(row_data["session"] !== undefined && row_data["session"]["username"] !== undefined) {
        username_text = row_data["session"]["username"];
      } else if(row_data["auth_cache"] !== undefined && row_data["auth_cache"]["username"] !== undefined) {
        username_text = row_data["auth_cache"]["username"];
      };

      if(row_data["voucher"] !== undefined) {
        login_text = row_data["voucher"];
      } else if(row_data["session"] !== undefined && row_data["session"]["voucher"] !== undefined) {
        login_text = row_data["session"]["voucher"];
      } else if(row_data["auth_cache"] !== undefined && row_data["auth_cache"]["voucher"] !== undefined) {
        login_text = row_data["auth_cache"]["voucher"];
      } else if(row_data["login"] !== undefined) {
        login_text = row_data["login"];
      } else if(row_data["session"] !== undefined && row_data["session"]["login"] !== undefined) {
        login_text = row_data["session"]["login"];
      } else if(row_data["auth_cache"] !== undefined && row_data["auth_cache"]["login"] !== undefined) {
        login_text = row_data["auth_cache"]["login"];
      };

      let state_text = "";

      if(row_data["log"] == "radius_log" && row_data["state"] !== undefined) {
        state_text = row_data["state"];
      } else if(row_data["session"] !== undefined) {
        if(row_data["session"]["state"] != row_data["session"]["next_state"] &&
          row_data["session"]["next_state"] !== undefined
        ) {
          state_text = row_data["session"]["state"] + "->" + row_data["session"]["next_state"];
        } else {
          state_text = row_data["session"]["state"];
        };
      };

      let sess_id = "";
      if(row_data["sess_id"] !== undefined) {
        sess_id = row_data["sess_id"];
      } else if(row_data["session"] !== undefined) {
        sess_id = row_data["session"]["sess_id"];
      };

      let tr = $(TR)
       .data("data", row_data)
       .append( $(TD) //buttons
         .append( $(LABEL)
           .addClass(["button", "ui-icon", "ui-icon-info"])
           .click(function() {
             let tr = $(this).closest("TR");
             let row_data = tr.data("data");
             show_dialog(jstr(row_data));
           })
         )
         .append( $(LABEL).addClass("min05em") )
         .append( $(LABEL)
           .addClass(["button", "ui-icon", "ui-icon-search"])
           .title("Все события сеанса")
           .click(function() {
             let tr = $(this).closest("TR");
             let row_data = tr.data("data");
             let sess_id = "";
             if(row_data["sess_id"] !== undefined) {
               sess_id = row_data["sess_id"];
             } else if(row_data["session"] !== undefined) {
               sess_id = row_data["session"]["sess_id"];
             };

             if(sess_id != "") {
               let table = $(this).closest("TABLE");
               let dt = table.DataTable();

               dt.search(sess_id);
               dt.draw();

             };

           })
         )
       )
       .append( $(TD) //source
         .append( $(LABEL).text(row_data["log"]) )
       )
       .append( $(TD) //event
         .text(event_text)
       )
       .append( $(TD) //state
         .text(state_text)
       )
       .append( $(TD) //time sort
         .text(row_data["time_sort"])
       )
       .append( $(TD) //time
         .text(from_unix_time(row_data["time"]))
       )
       .append( $(TD) //sess_id search
         .text(sess_id)
       )
       .append( $(TD) //mac search
         .text(mac_search)
       )
       .append( $(TD) //mac
         .append( $(LABEL)
           .addClass(["button", "ui-icon", "ui-icon-search"])
           .title("События этого MAC")
           .click(function() {
             let tr = $(this).closest("TR");
             let row_data = tr.data("data");
             let search_str = "";
             if(row_data["sta_id"] !== undefined) {
               search_str = row_data["sta_id"];
             } else if(row_data["session"] !== undefined) {
               search_str = row_data["session"]["sta_id"];
             };

             if(search_str != "") {
               let table = $(this).closest("TABLE");
               let dt = table.DataTable();

               dt.search(search_str);
               dt.draw();

             };

           })
         )
         .append( $(SPAN)
           .css({"font-family": "monospace", "padding-left": "0.5em"})
           .text(mac_text)
         )
       )
       .append( $(TD) //ip
         .text(sta_ip)
       )
       .append( $(TD) //login/voucher
         .append( $(LABEL)
           .addClass(["button", "ui-icon", "ui-icon-search"])
           .title("События этого логина/ваучера")
           .click(function() {
             let tr = $(this).closest("TR");
             let row_data = tr.data("data");
             let search_str = "";
             if(row_data["login"] !== undefined) {
               search_str = row_data["login"];
             } else if(row_data["session"] !== undefined && row_data["session"]["login"] !== undefined) {
               search_str = row_data["session"]["login"];
             } else if(row_data["auth_cache"] !== undefined && row_data["auth_cache"]["login"] !== undefined) {
               search_str = row_data["auth_cache"]["login"];
             } else if(row_data["voucher"] !== undefined) {
               search_str = row_data["voucher"];
             } else if(row_data["auth_cache"] !== undefined && row_data["auth_cache"]["voucher"] !== undefined) {
               search_str = row_data["auth_cache"]["voucher"];
             } else if(row_data["session"] !== undefined && row_data["session"]["voucher"] !== undefined) {
               search_str = row_data["session"]["voucher"];
             };


             if(search_str != "") {
               let table = $(this).closest("TABLE");
               let dt = table.DataTable();

               dt.search(search_str);
               dt.draw();

             };

           })
         )
         .append( $(SPAN)
           .css({"padding-left": "0.5em"})
           .text(login_text)
         )
       )
       .append( $(TD) //username
         .text(username_text)
       )
       .append( $(TD) //info
       )
      ;

      dt.row.add(tr);
    };
    dt.draw();
  });

};

function actionAuditLog() {
  workarea.empty();
  fixed_div.empty();

  let table = $(TABLE)
   .css({"white-space": "pre"})
   .append( $(THEAD)
     .append( $(TR)
       .append( $(TH) ) // (i) button
       .append( $(TH).text("Действие") )
       .append( $(TH).text("") ) //date sorting
       .append( $(TH).text("Время") )
       .append( $(TH).text("IP") )
       .append( $(TH).text("Логин") )
       .append( $(TH).text("Пользователь") )
       .append( $(TH).text("Доп. информация") )
     )
   )
   .append( $(TBODY) )
   .appendTo( workarea )
  ;

  let dt = table.DataTable({
    columns: [
      { name: "buttons", searchable: false, orderable: false },
      { name: "event", orderable: false },
      { name: "timesort", visible: false, orderable: true },
      { name: "time", orderable: false },
      { name: "ip", orderable: false },
      { name: "login", orderable: false },
      { name: "username", orderable: false },
      { name: "info", orderable: false }
    ],
    order: {
      name: "timesort",
      dir: 'desc'
    },
    pageLength: 25
  });

  run_query({"action": "get_auditlog"}, function(res) {
    for(let i in res["ok"]["events"]) {
      let row_data = JSON.parse(res["ok"]["events"][i]);

      let tr = $(TR)
       .data("data", row_data)
       .append( $(TD) //buttons
         .append( $(LABEL)
           .addClass(["button", "ui-icon", "ui-icon-info"])
           .click(function() {
             let tr = $(this).closest("TR");
             let row_data = tr.data("data");
             show_dialog(jstr(row_data));
           })
         )
       )
       .append( $(TD) //event
         .text(row_data["action"])
       )
       .append( $(TD) //time sort
         .text(row_data["time_sort"])
       )
       .append( $(TD) //time
         .text(from_unix_time(row_data["time"]))
       )
       .append( $(TD) //ip
         .text(row_data["user_ip"])
       )
       .append( $(TD) //login
         .append( $(LABEL)
           .addClass(["button", "ui-icon", "ui-icon-search"])
           .title("События этого логина")
           .click(function() {
             let tr = $(this).closest("TR");
             let row_data = tr.data("data");
             let search_str = row_data["user_login"];
             if(search_str != "") {
               let table = $(this).closest("TABLE");
               let dt = table.DataTable();

               dt.search(search_str);
               dt.draw();
             };
           })
         )
         .append( $(SPAN)
           .css({"padding-left": "0.5em"})
           .text(row_data["user_login"])
         )
       )
       .append( $(TD) //username
         .text(row_data["user_name"])
       )
       .append( $(TD) //info
       )
      ;

      dt.row.add(tr);
    };
    dt.draw();
  });

};
