use std::sync::{Arc, Mutex};
use tauri::Manager;
use tokio::sync::mpsc;
use ssh2::Session;
use std::net::TcpStream;

struct SshSession {
    session: Option<Session>,
    channel: Option<ssh2::Channel>,
}

impl Default for SshSession {
    fn default() -> Self {
        Self {
            session: None,
            channel: None,
        }
    }
}

#[tauri::command]
async fn connect(
    host: String,
    port: u16,
    username: String,
    password: String,
    private_key: String,
) -> Result<String, String> {
    let address = format!("{}:{}", host, port);
    
    // 创建TCP连接
    let tcp = TcpStream::connect(&address)
        .map_err(|e| format!("连接到 {} 失败: {}", address, e))?;
    
    // 创建SSH会话
    let mut session = Session::new()
        .map_err(|e| format!("创建SSH会话失败: {}", e))?;
    
    // 设置TCP流
    session.set_tcp_stream(tcp);
    session.handshake()
        .map_err(|e| format!("SSH握手失败: {}", e))?;
    
    // 认证
    if !private_key.is_empty() {
        session.userauth_pubkey_memory(
            &username,
            None,
            private_key.as_bytes(),
            Some(password.as_bytes()),
        )
        .map_err(|e| format!("使用私钥认证失败: {}", e))?;
    } else if !password.is_empty() {
        session.userauth_password(&username, &password)
            .map_err(|e| format!("使用密码认证失败: {}", e))?;
    } else {
        return Err("请提供密码或私钥进行认证".to_string());
    }
    
    // 创建一个执行命令的通道
    let mut channel = session.channel_session()
        .map_err(|e| format!("创建会话通道失败: {}", e))?;
    
    // 设置Pty以便获得交互式终端
    channel.request_pty("xterm", None, None)
        .map_err(|e| format!("请求PTY失败: {}", e))?;
    
    // 启动shell
    channel.shell()
        .map_err(|e| format!("启动shell失败: {}", e))?;
    
    // 读取欢迎信息
    let mut welcome = String::new();
    channel.read_to_string(&mut welcome)
        .map_err(|e| format!("读取欢迎信息失败: {}", e))?;
    
    // 存储会话和通道
    let state = tauri::State::<Arc<Mutex<SshSession>>>::from(
        &tauri::AppHandle::global()
    );
    
    let mut state = state.lock().unwrap();
    state.session = Some(session);
    state.channel = Some(channel);
    
    Ok(welcome)
}

#[tauri::command]
async fn execute_command(command: String) -> Result<String, String> {
    let state = tauri::State::<Arc<Mutex<SshSession>>>::from(
        &tauri::AppHandle::global()
    );
    
    let mut state = state.lock().unwrap();
    
    // 检查是否有活动会话
    let channel = state.channel.as_mut()
        .ok_or_else(|| "没有活动的SSH连接".to_string())?;
    
    // 写入命令
    channel.write_all(command.as_bytes())
        .map_err(|e| format!("写入命令失败: {}", e))?;
    
    // 写入换行符执行命令
    channel.write_all(b"\n")
        .map_err(|e| format!("写入换行符失败: {}", e))?;
    
    // 读取命令输出
    let mut output = String::new();
    channel.read_to_string(&mut output)
        .map_err(|e| format!("读取命令输出失败: {}", e))?;
    
    Ok(output)
}

#[tauri::command]
async fn disconnect() -> Result<String, String> {
    let state = tauri::State::<Arc<Mutex<SshSession>>>::from(
        &tauri::AppHandle::global()
    );
    
    let mut state = state.lock().unwrap();
    
    // 关闭通道
    if let Some(mut channel) = state.channel.take() {
        channel.close()
            .map_err(|e| format!("关闭通道失败: {}", e))?;
        
        // 等待通道关闭
        channel.wait_close()
            .map_err(|e| format!("等待通道关闭失败: {}", e))?;
    }
    
    // 清除会话
    state.session = None;
    
    Ok("已断开连接".to_string())
}

fn main() {
    tauri::Builder::default()
        .manage(Arc::new(Mutex::new(SshSession::default())))
        .invoke_handler(tauri::generate_handler![connect, execute_command, disconnect])
        .run(tauri::generate_context!())
        .expect("启动应用失败");
}    