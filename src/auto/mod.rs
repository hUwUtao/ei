// This is a module to pull remote IP list and allows to resolve into IP rule.
// Configuring one is not very convenient.

mod cloudflare;
mod iplist;
mod resolver;

pub use iplist::IpListManager;
pub use resolver::IpListResolver;
