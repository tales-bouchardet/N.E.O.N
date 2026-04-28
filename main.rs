#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod functions;
use crate::functions::*;
use web_view::*;
use serde_json::json;

static HTML: &str = include_str!("assets/main.html");
static CSS: &str = include_str!("assets/main.css");
static JS: &str = include_str!("assets/main.js");
#[tokio::main]
async fn main() {

    let mut webview = web_view::builder()
        .title("N.E.O.N.")
        .content(Content::Html(HTML))
        .size(420, 590)
        .resizable(false)
        .debug(false)
        .user_data(())
        .invoke_handler(|webview, arg| {
            match arg {
                "refresh" => {
                    let data = json!({
                        "now": get_now(),
                        "date": get_date(),
                        "manufacturer": get_manufacturer(),
                        "os": format!("{} [{}]", get_os(), std::env::consts::ARCH),
                        "user": get_active_user().map(|u| u.username).unwrap_or_else(|| "Desconhecido".to_string()),
                        "hostname": get_hostname(),
                        "cpu": get_cpu_info(),
                        "cpu_usage": get_cpu_usage(),
                        "memory": get_memory_info(),
                        "firewall": if is_firewall_enabled() { "Ativado" } else { "Desativado" },
                        "proxy": if is_proxy_enabled() { "<green>PROXY ATIVO</green>" } else { "<red>PROXY INATIVO</red>" },
                        "join": fulldomain(),     
                        "uptime": get_uptime(),
                        "telemetria": if has_fgt_name() { "✅" } else { "❌" },
                        "forticlient": get_file_version("C:\\Program Files\\Fortinet\\FortiClient\\FortiClient.exe").unwrap_or_else(|_| "Não Instalado".to_string()),
                        "crowd": get_file_version("C:\\Program Files\\CrowdStrike\\CSFalconService.exe").unwrap_or_else(|_| "Não Instalado".to_string()),
                        "kace": get_file_version("C:\\Program Files (x86)\\Quest\\KACE\\AMPTools.exe").unwrap_or_else(|_| "Não Instalado".to_string()),
                        "netskope": get_file_version("C:\\Program Files\\Netskope\\EPDLP\\EPDLP.exe").unwrap_or_else(|_| "Não Instalado".to_string()),
                        "lumu": get_file_version("C:\\Program Files (x86)\\Lumu\\Agent\\lumu-windows-agent.exe").unwrap_or_else(|_| "Não Instalado".to_string()),
                        "Windows App": get_windowsapp_version().unwrap_or_else(|_| "Não Instalado".to_string()),
                        "ping": if ping() { "ACESSO A REDE INTERNA" } else { "SEM ACESSO A REDE INTERNA" },
                    });
                    let js_code = format!("data = {};", data.to_string());
                    webview.eval(&js_code).unwrap();
                    Ok(())
                }
                 _ => Ok(()),
            }
        })
        .build()
        .unwrap();

    webview.inject_css(CSS).unwrap();
    webview.eval(JS).unwrap();

    webview.run().unwrap();
}