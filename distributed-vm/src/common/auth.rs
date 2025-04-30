use clap::ValueEnum;
use tonic::{Request, Status};

#[derive(Debug, Clone, ValueEnum)]
pub enum AuthMethod {
    None,
    Bearer,
}

pub trait AuthConfig {
    fn auth_method(&self) -> &AuthMethod;

    fn bearer_token(&self) -> Option<&String>;

    fn validate_auth(&self) -> Result<(), String> {
        match self.auth_method() {
            AuthMethod::None => Ok(()),
            AuthMethod::Bearer => {
                if self.bearer_token().is_none() {
                    Err("Bearer token must be provided when auth_method is 'bearer'.".to_string())
                } else {
                    Ok(())
                }
            }
        }
    }

    // Server-side authentication check.
    fn server_auth_interceptor(
        &self,
    ) -> impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static {
        let auth_method = self.auth_method().clone();
        let bearer_token = self.bearer_token().cloned();

        move |req: Request<()>| match auth_method {
            AuthMethod::None => Ok(req),
            AuthMethod::Bearer => {
                let expected = bearer_token
                    .as_ref()
                    .ok_or_else(|| Status::unauthenticated("Bearer token not configured"))?;
                let expected_token: tonic::metadata::MetadataValue<_> =
                    format!("Bearer {}", expected)
                        .parse()
                        .map_err(|_| Status::unauthenticated("Invalid token format"))?;

                match req.metadata().get("authorization") {
                    Some(t) if t == expected_token => Ok(req),
                    _ => Err(Status::unauthenticated("Invalid or missing auth token")),
                }
            }
        }
    }

    // Client-side interceptor that injects auth header.
    fn client_auth_interceptor(
        &self,
    ) -> impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static {
        let auth_method = self.auth_method().clone();
        let bearer_token = self.bearer_token().cloned();

        move |mut req: Request<()>| match auth_method {
            AuthMethod::None => Ok(req),
            AuthMethod::Bearer => {
                let token = bearer_token
                    .as_ref()
                    .ok_or_else(|| Status::unauthenticated("Bearer token not configured"))?;
                let header: tonic::metadata::MetadataValue<_> = format!("Bearer {}", token)
                    .parse()
                    .map_err(|_| Status::unauthenticated("Invalid token format"))?;

                req.metadata_mut().insert("authorization", header);
                Ok(req)
            }
        }
    }
}

#[macro_export]
macro_rules! impl_auth_config {
    ($config:ty) => {
        impl $crate::common::auth::AuthConfig for $config {
            fn auth_method(&self) -> &AuthMethod {
                &self.auth_method
            }

            fn bearer_token(&self) -> Option<&String> {
                self.bearer_token.as_ref()
            }
        }
    };
}
