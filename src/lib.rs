pub extern crate rustls;

extern crate postgres;
extern crate webpki;

use std::error::Error;
use std::fmt;
use std::io::{self, Read, Write};
use std::sync::Arc;

use postgres::tls::{Stream, TlsHandshake, TlsStream};

pub struct Rustls {
    config: Arc<rustls::ClientConfig>
}

impl fmt::Debug for Rustls {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Rustls").finish()
    }
}

impl Rustls {
    pub fn new() -> Rustls {
        Rustls { config: Arc::new(rustls::ClientConfig::new()) }
    }

    pub fn with_config(config: rustls::ClientConfig) -> Rustls {
        Rustls { config: Arc::new(config) }
    }
}

impl TlsHandshake for Rustls {
    fn tls_handshake(&self, domain: &str, underlying_stream: Stream) -> Result<Box<TlsStream>, Box<Error + Sync + Send>> {
        let dns_name = webpki::DNSNameRef::try_from_ascii_str(domain)
                                          .map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to parse hostname"))?;
        let tls_session = rustls::ClientSession::new(&self.config, dns_name);
        Ok(Box::new(RustlsStream::new(tls_session, underlying_stream)))
    }
}

struct RustlsStream<S: rustls::Session + Sized, T: Read + Write + Send + ?Sized>  {
    tls_session: S,
    underlying_stream: T
}

impl<S, T> RustlsStream<S, T> where S: rustls::Session + Sized, T: Read + Write + Send {
    fn new(tls_session: S, underlying_stream: T) -> Self {
        RustlsStream { tls_session, underlying_stream }
    }

    fn complete_prior_io(&mut self) -> io::Result<()> {
        if self.tls_session.is_handshaking() {
            self.tls_session.complete_io(&mut self.underlying_stream)?;
        }
        if self.tls_session.wants_write() {
            self.tls_session.complete_io(&mut self.underlying_stream)?;
        }
        Ok(())
    }
}

impl<S, T> fmt::Debug for RustlsStream<S, T> where S: rustls::Session + Sized, T: Read + Write + Send {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("RustlsStream").finish()
    }
}

impl<S, T> Read for RustlsStream<S, T> where S: rustls::Session + Sized, T: Read + Write + Send {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.complete_prior_io()?;
        while self.tls_session.wants_read() && self.tls_session.complete_io(&mut self.underlying_stream)?.0 != 0 {}
        self.tls_session.read(buf)
    }
}

impl<S, T> Write for RustlsStream<S, T> where S: rustls::Session + Sized, T: Read + Write + Send {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.complete_prior_io()?;
        let len = self.tls_session.write(buf)?;
        self.tls_session.complete_io(&mut self.underlying_stream)?;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.complete_prior_io()?;
        self.tls_session.flush()?;
        if self.tls_session.wants_write() {
            self.tls_session.complete_io(&mut self.underlying_stream)?;
        }
        Ok(())
    }
}

impl<S> TlsStream for RustlsStream<S, Stream> where S: rustls::Session + Sized {
    fn get_ref(&self) -> &Stream {
        &self.underlying_stream
    }

    fn get_mut(&mut self) -> &mut Stream {
        &mut self.underlying_stream
    }
}
