use tao::dpi::{LogicalSize, Size};
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoop, EventLoopBuilder, EventLoopWindowTarget};
use tao::platform::run_return::EventLoopExtRunReturn;
use tao::window::{Window, WindowBuilder};
use wry::http::{HeaderMap, HeaderValue};
use wry::{PageLoadEvent, WebContext, WebView, WebViewBuilder};
use xodus::models::live::{DAProperty, HostBridgeMessage};

type HandlerResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionId(u64);

pub enum HandlerControl<T> {
    Continue,
    Complete(T),
}

pub trait SessionHandler {
    type Output: std::fmt::Debug;

    fn bootstrap(&mut self, runtime: &mut RuntimeCommands) -> HandlerResult<()>;

    fn on_token(
        &mut self,
        session_id: SessionId,
        data: DAProperty,
        runtime: &mut RuntimeCommands,
    ) -> HandlerResult<HandlerControl<Self::Output>>;

    fn on_closed(
        &mut self,
        _session_id: SessionId,
        _runtime: &mut RuntimeCommands,
    ) -> HandlerResult<HandlerControl<Self::Output>> {
        Ok(HandlerControl::Continue)
    }
}

pub struct WebviewRequest {
    title: String,
    url: String,
    headers: HeaderMap,
}

pub struct RuntimeCommands {
    next_session_id: u64,
    actions: Vec<RuntimeAction>,
}

enum RuntimeAction {
    OpenSession {
        session_id: SessionId,
        request: WebviewRequest,
    },
    CloseSession(SessionId),
}

enum CustomEvent {
    OpenSession {
        session_id: SessionId,
        request: WebviewRequest,
    },
    HostGetContext(SessionId, String),
    Finish(SessionId),
    IpcCallback(SessionId, DAProperty),
}

struct RuntimeState<T: SessionHandler> {
    handler: T,
    next_session_id: u64,
    window: Option<Window>,
    active_session: Option<SessionId>,
    active_webview: Option<WebView>,
    result: Option<T::Output>,
    error: Option<String>,
    web_context: WebContext,
    // One isolated browser store per login process, shared across MFA pages.
    // Drop views/context before removing their temporary cookies.
    _browser_data: tempfile::TempDir,
}

impl RuntimeCommands {
    fn new(next_session_id: u64) -> Self {
        Self {
            next_session_id,
            actions: Vec::new(),
        }
    }

    pub fn open_session(&mut self, request: WebviewRequest) -> SessionId {
        let session_id = SessionId(self.next_session_id);
        self.next_session_id += 1;
        self.actions.push(RuntimeAction::OpenSession {
            session_id,
            request,
        });
        session_id
    }

    pub fn close_session(&mut self, session_id: SessionId) {
        self.actions.push(RuntimeAction::CloseSession(session_id));
    }
}

impl WebviewRequest {
    fn new(title: impl Into<String>, url: String, headers: HeaderMap) -> Self {
        Self {
            title: title.into(),
            url,
            headers,
        }
    }
}

pub fn login_request(client_id: String, market: String) -> WebviewRequest {
    let uid = uuid::Uuid::new_v4();
    let url = format!(
        "https://login.live.com/ppsecure/InlineLogin.srf?id=80604&scid=3&mkt={market}&Platform=Windows10&clientid={client_id}&hosted=1"
    );

    let mut headers = HeaderMap::new();
    headers.insert("cxh-capabilities", HeaderValue::from_static(r#"{"PrivatePropertyBag":1,"PasswordlessConnect":1,"PreferAssociate":1,"ChromelessUI":0}"#));
    headers.insert(
        "cxh-correlationId",
        HeaderValue::from_str(&format!("{uid}")).unwrap(),
    );
    headers.insert("cxh-msaBinaryVersion", HeaderValue::from_static(r#"55"#));
    headers.insert(
        "cxh-identityClientBinaryVersion",
        HeaderValue::from_static(r#"3"#),
    );
    headers.insert(
        "cxh-osVersionInfo",
        HeaderValue::from_static(
            r#"{"platformId":2,"majorVersion":10,"minorVersion":0,"buildNumber":26100}"#,
        ),
    );
    headers.insert(
        "cxh-platform",
        HeaderValue::from_static(r#"CloudExperienceHost.Platform.DESKTOP"#),
    );
    headers.insert("cxh-protocol", HeaderValue::from_static(r#"TokenBroker"#));
    headers.insert("cxh-source", HeaderValue::from_static(r#"TokenBroker"#));
    headers.insert(
        "hostApp",
        HeaderValue::from_static(r#"CloudExperienceHost"#),
    );

    WebviewRequest::new("Xodus login", url, headers)
}

pub fn finalize_request(url: String) -> WebviewRequest {
    WebviewRequest::new("Xodus login", url, HeaderMap::new())
}

/// Origins whose pages may talk to the sign-in host. The IPC bridge hands
/// over the account's tokens, so a page from anywhere else -- an ad, a help
/// link, a redirect the sign-in flow did not intend -- must not reach it.
const IPC_ORIGINS: [&str; 2] = ["login.live.com", "login.microsoftonline.com"];

/// Domains the sign-in window may navigate to: Microsoft account pages, their
/// CDNs, and the challenge provider the sign-in pages embed. Nothing else, and
/// nothing but https, so the window cannot be turned into a general browser
/// that still holds the bridge.
const NAVIGATION_DOMAINS: [&str; 8] = [
    "live.com",
    "microsoftonline.com",
    "microsoft.com",
    "msauth.net",
    "msftauth.net",
    "live.net",
    "xboxlive.com",
    "arkoselabs.com",
];

fn https_host(url: &str) -> Option<String> {
    let uri: wry::http::Uri = url.parse().ok()?;
    if uri.scheme_str() != Some("https") {
        return None;
    }
    let authority = uri.authority()?;
    if authority.as_str().contains('@') || authority.port().is_some_and(|p| p.as_u16() != 443) {
        return None;
    }
    Some(authority.host().to_ascii_lowercase())
}

/// Whether a bridge message came from a Microsoft sign-in page.
fn trusted_ipc_origin(url: &str) -> bool {
    https_host(url).is_some_and(|host| IPC_ORIGINS.contains(&host.as_str()))
}

/// Whether the sign-in window may load `url`.
fn allowed_navigation(url: &str) -> bool {
    if matches!(url, "about:blank" | "about:srcdoc") {
        return true;
    }
    https_host(url).is_some_and(|host| {
        NAVIGATION_DOMAINS.iter().any(|domain| {
            host == *domain
                || host
                    .strip_suffix(domain)
                    .is_some_and(|rest| rest.ends_with('.'))
        })
    })
}

/// The script that answers the bridge's getContext call. `context` comes from
/// the page, so it is embedded as a JSON value, never spliced into the source.
fn host_context_script(context: &str) -> String {
    let message = serde_json::json!({
        "type": "callback",
        "value": {
            "name": "CloudExperienceHost.getContext",
            "args": [
                "CloudExperienceHost",
                "TokenBroker",
                "TokenBroker",
                r#"{"PrivatePropertyBag":1,"PasswordlessConnect":1,"PreferAssociate":1,"ChromelessUI":0}"#
            ],
            "context": context,
        }
    });
    // The JSON text of the message is itself passed as a string, as the bridge
    // expects. U+2028 and U+2029 are valid in JSON but end a line in older
    // JavaScript, so they are escaped too.
    let argument = serde_json::to_string(&message.to_string())
        .unwrap_or_default()
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    format!(r#"window["CloudExperienceHost.Bridge.dispatchMessage"]({argument})"#)
}

pub fn run_sessions<T>(handler: T) -> HandlerResult<Option<T::Output>>
where
    T: SessionHandler,
{
    let mut event_loop: EventLoop<CustomEvent> = EventLoopBuilder::with_user_event().build();
    let proxy = event_loop.create_proxy();
    let browser_data = tempfile::Builder::new().prefix("xodus-signin-").tempdir()?;
    let web_context = WebContext::new(Some(browser_data.path().to_path_buf()));
    let mut state = RuntimeState {
        handler,
        next_session_id: 1,
        window: None,
        active_session: None,
        active_webview: None,
        result: None,
        error: None,
        web_context,
        _browser_data: browser_data,
    };

    let mut commands = RuntimeCommands::new(state.next_session_id);
    state.handler.bootstrap(&mut commands)?;
    state.next_session_id = commands.next_session_id;
    dispatch_actions(&proxy, commands.actions)?;
    event_loop.run_return(|event, target, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::UserEvent(CustomEvent::OpenSession {
                session_id,
                request,
            }) => {
                if let Err(err) =
                    create_session(target, proxy.clone(), &mut state, session_id, request)
                {
                    state.error = Some(err.to_string());
                }
            }
            Event::UserEvent(CustomEvent::Finish(session_id)) => {
                if state.active_session == Some(session_id)
                    && let Some(webview) = state.active_webview.as_ref()
                {
                    let _ = webview
                        .evaluate_script("window.ipc.postMessage(JSON.stringify(ServerData))");
                }
            }
            Event::UserEvent(CustomEvent::HostGetContext(session_id, ctx)) => {
                if state.active_session == Some(session_id)
                    && let Some(webview) = state.active_webview.as_ref()
                {
                    let _ = webview.evaluate_script(&host_context_script(&ctx));
                }
            }
            Event::UserEvent(CustomEvent::IpcCallback(session_id, data)) => {
                apply_handler_result(&proxy, target, &mut state, move |handler, runtime| {
                    handler.on_token(session_id, data, runtime)
                });
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                if let Some(session_id) = state.active_session {
                    remove_session(&mut state, session_id);
                    apply_handler_result(&proxy, target, &mut state, move |handler, runtime| {
                        handler.on_closed(session_id, runtime)
                    });
                }
            }
            _ => {}
        }

        if state.error.is_some() || state.result.is_some() {
            *control_flow = ControlFlow::Exit;
        }
    });

    if let Some(error) = state.error {
        return Err(std::io::Error::other(error).into());
    }

    Ok(state.result)
}

fn dispatch_actions(
    proxy: &tao::event_loop::EventLoopProxy<CustomEvent>,
    actions: Vec<RuntimeAction>,
) -> HandlerResult<()> {
    for action in actions {
        match action {
            RuntimeAction::OpenSession {
                session_id,
                request,
            } => proxy
                .send_event(CustomEvent::OpenSession {
                    session_id,
                    request,
                })
                .map_err(|_| std::io::Error::other("failed to open session"))?,
            RuntimeAction::CloseSession(session_id) => {
                let _ = session_id;
            }
        }
    }

    Ok(())
}

fn apply_handler_result<T, F>(
    proxy: &tao::event_loop::EventLoopProxy<CustomEvent>,
    target: &EventLoopWindowTarget<CustomEvent>,
    state: &mut RuntimeState<T>,
    callback: F,
) where
    T: SessionHandler,
    F: FnOnce(&mut T, &mut RuntimeCommands) -> HandlerResult<HandlerControl<T::Output>>,
{
    let mut commands = RuntimeCommands::new(state.next_session_id);
    match callback(&mut state.handler, &mut commands) {
        Ok(HandlerControl::Continue) => {}
        Ok(HandlerControl::Complete(result)) => state.result = Some(result),
        Err(err) => state.error = Some(err.to_string()),
    }

    state.next_session_id = commands.next_session_id;
    apply_actions(proxy, target, state, commands.actions);
}

fn apply_actions<T>(
    proxy: &tao::event_loop::EventLoopProxy<CustomEvent>,
    target: &EventLoopWindowTarget<CustomEvent>,
    state: &mut RuntimeState<T>,
    actions: Vec<RuntimeAction>,
) where
    T: SessionHandler,
{
    for action in actions {
        match action {
            RuntimeAction::OpenSession {
                session_id,
                request,
            } => {
                if let Err(err) = create_session(target, proxy.clone(), state, session_id, request)
                {
                    state.error = Some(err.to_string());
                    break;
                }
            }
            RuntimeAction::CloseSession(session_id) => {
                remove_session(state, session_id);
                let _ = proxy;
            }
        }
    }
}

fn create_session<T: SessionHandler>(
    target: &EventLoopWindowTarget<CustomEvent>,
    proxy: tao::event_loop::EventLoopProxy<CustomEvent>,
    state: &mut RuntimeState<T>,
    session_id: SessionId,
    request: WebviewRequest,
) -> HandlerResult<()> {
    if state.window.is_none() {
        let window = WindowBuilder::new()
            .with_resizable(false)
            .with_title(&request.title)
            .with_inner_size(Size::Logical(LogicalSize::new(500.0, 700.0)))
            .build(target)?;
        state.window = Some(window);
    }

    let window = state
        .window
        .as_ref()
        .ok_or_else(|| std::io::Error::other("window was not initialized"))?;
    window.set_title(&request.title);

    let proxy_ipc = proxy.clone();
    let builder = WebViewBuilder::new_with_web_context(&mut state.web_context)
            .with_url(&request.url)
            .with_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; MSAppHost/3.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.26100")
            .with_headers(request.headers)
            .with_initialization_script("window.external = {notify: window.ipc.postMessage }")
            .with_navigation_handler(|url| {
                let allowed = allowed_navigation(&url);
                if !allowed {
                    eprintln!("Sign-in window: blocked navigation away from Microsoft sign-in");
                }
                allowed
            })
            .with_ipc_handler(move |request| {
                if !trusted_ipc_origin(&request.uri().to_string()) {
                    eprintln!("Ignoring a sign-in bridge message from outside Microsoft sign-in");
                    return;
                }
                let body = request.body();
                let payload = serde_json::from_str::<DAProperty>(body);
                if let Ok(data) = payload {
                    if proxy_ipc
                        .send_event(CustomEvent::IpcCallback(session_id, data))
                        .is_err()
                    {
                        eprintln!("Failed to dispatch IPC token callback event");
                    }
                } else {
                    match serde_json::from_str::<HostBridgeMessage>(body) {
                        Ok(message) => {
                            if let Some(ctx) = message.get_context_invoke()
                                && proxy_ipc
                                    .send_event(CustomEvent::HostGetContext(
                                        session_id,
                                        ctx.to_string(),
                                    ))
                                    .is_err()
                            {
                                eprintln!("Failed to dispatch host context event");
                            }
                        }
                        Err(_) => {
                            eprintln!("Ignoring unsupported IPC payload");
                        }
                    }
                }
            })
            .with_on_page_load_handler(move |event, url| {
                if matches!(event, PageLoadEvent::Finished)
                    && https_host(&url).as_deref() == Some("login.live.com")
                    && url.starts_with("https://login.live.com/ppsecure/post.srf")
                {
                    proxy.send_event(CustomEvent::Finish(session_id)).ok();
                }
            });

    #[cfg(target_os = "linux")]
    let webview = {
        use tao::platform::unix::WindowExtUnix;
        use wry::WebViewBuilderExtUnix;
        builder.build_gtk(window.default_vbox().unwrap()).unwrap()
    };
    #[cfg(not(target_os = "linux"))]
    let webview = builder.build(&window).unwrap();

    state.active_session = Some(session_id);
    state.active_webview = Some(webview);
    Ok(())
}

fn remove_session<T: SessionHandler>(state: &mut RuntimeState<T>, session_id: SessionId) {
    if state.active_session == Some(session_id) {
        state.active_session = None;
        state.active_webview = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_microsoft_sign_in_pages_reach_the_bridge() {
        assert!(trusted_ipc_origin(
            "https://login.live.com/ppsecure/post.srf?x=1"
        ));
        assert!(trusted_ipc_origin(
            "https://LOGIN.microsoftonline.com/common"
        ));
        for url in [
            "http://login.live.com/",
            "https://login.live.com.example.test/",
            "https://login.live.com@example.test/",
            "https://evil-login.live.com/",
            "https://account.live.com/",
            "https://login.live.com:8443/",
            "file:///login.live.com",
            "",
        ] {
            assert!(!trusted_ipc_origin(url), "{url}");
        }
    }

    #[test]
    fn navigation_stays_on_microsoft_sign_in_domains() {
        for url in [
            "https://login.live.com/oauth20_authorize.srf",
            "https://account.live.com/proofs/Add",
            "https://logincdn.msauth.net/shared/1.0/content/js/x.js",
            "https://client-api.arkoselabs.com/fc/gt2/",
            "about:blank",
        ] {
            assert!(allowed_navigation(url), "{url}");
        }
        for url in [
            "http://login.live.com/",
            "https://example.test/",
            "https://notlive.com/",
            "https://live.com.example.test/",
            "javascript:alert(1)",
            "data:text/html,x",
        ] {
            assert!(!allowed_navigation(url), "{url}");
        }
    }

    #[test]
    fn a_page_supplied_context_cannot_escape_its_string() {
        let hostile = "x\"}}));alert(1);//\u{2028}";
        let script = host_context_script(hostile);
        let prefix = r#"window["CloudExperienceHost.Bridge.dispatchMessage"]("#;
        let argument = script
            .strip_prefix(prefix)
            .and_then(|s| s.strip_suffix(')'))
            .unwrap();
        // The argument is one JSON string literal, which decodes to the
        // message, whose context is the page's value unchanged.
        let text: String = serde_json::from_str(argument).unwrap();
        let message: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(message["value"]["context"], hostile);
        assert_eq!(message["value"]["name"], "CloudExperienceHost.getContext");
        assert!(!script.contains('\u{2028}'));
    }
}
