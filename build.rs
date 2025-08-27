use std::ffi::OsStr;

fn main() {
    embed_resource::compile("app.rc", std::iter::empty::<&OsStr>());
}
