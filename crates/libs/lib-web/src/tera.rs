#![allow(dead_code)]

use axum::response::Html;
use std::sync::OnceLock;
use tera::{Context, Tera};

use crate::{
    error::{Error, Result},
    web_config,
};

fn tera_instance() -> &'static Tera {
    static INSTANCE: OnceLock<Tera> = OnceLock::new();

    INSTANCE.get_or_init(|| {
        let mut tera = match Tera::new(&format!(
            "{}/**/*",
            web_config().TEMPLATE_FOLDER
        )) {
            Ok(t) => t,
            Err(e) => {
                println!("Parsing error(s): {e}");
                ::std::process::exit(1);
            }
        };
        tera.autoescape_on(vec![".html", ".sql"]);
        tera
    })
}

#[cfg(feature = "hot_reload")]
use std::sync::RwLock;

#[cfg(feature = "hot_reload")]
fn tera_instance_hot_reload() -> &'static RwLock<Tera> {
    static INSTANCE: OnceLock<RwLock<Tera>> = OnceLock::new();

    INSTANCE.get_or_init(|| {
        let mut tera = match Tera::new(&format!(
            "{}/**/*",
            web_config().TEMPLATE_FOLDER
        )) {
            Ok(t) => t,
            Err(e) => {
                println!("Parsing error(s): {e}");
                ::std::process::exit(1);
            }
        };
        tera.autoescape_on(vec![".html", ".sql"]);
        RwLock::new(tera)
    })
}

pub fn render(template_name: &str, context: &Context) -> Result<Html<String>> {
    #[cfg(not(feature = "hot_reload"))]
    let t = tera_instance()
        .render(template_name, context)
        .map(Html)
        .map_err(Error::TeraRender);

    #[cfg(feature = "hot_reload")]
    let t = tera_instance_hot_reload()
        .read()
        .unwrap()
        .render(template_name, context)
        .map(|v| format!("{v}{}", lib_hotreload::format_script()))
        .map(Html)
        .map_err(Error::TeraRender);

    t
}

pub fn render_fragmant(
    template_name: &str,
    context: &Context,
) -> Result<Html<String>> {
    tera_instance()
        .render(template_name, context)
        .map(Html)
        .map_err(Error::TeraRender)
}

#[cfg(feature = "hot_reload")]
pub fn reload_tera() -> std::result::Result<(), tera::Error> {
    tera_instance_hot_reload().write().unwrap().full_reload()
}
