use crate::reload_config;

/// JS script containing a function that takes in the address and connects to the websocket.
const WEBSOCKET_FUNCTION: &str = include_str!("./templates/websocket.js");

/// JS script to inject to the HTML on reload so the client
/// knows it's a successful reload.
const RELOAD_PAYLOAD: &str = include_str!("./templates/reload.js");

/// Inject the address into the websocket script and wrap it in a script tag
pub fn format_script() -> String {
    let hard = if reload_config().HARD_RELOAD {
        "true"
    } else {
        "false"
    };
    format!(
        r#"<script>
        {RELOAD_PAYLOAD}
        {WEBSOCKET_FUNCTION}
        liveReload({hard})
    </script>"#
    )
}
