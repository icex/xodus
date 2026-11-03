use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use xodus::models::secrets::LegacyToken;
use xodus::tokens::TokenManager;

use crate::simple_context::SimpleContext;

pub async fn route(
    socket: tokio::net::UnixStream,
    token: CancellationToken,
    device_token: LegacyToken,
    tokens: Arc<TokenManager>,
    store_tokens: Arc<TokenManager>,
    entitlement: Option<Arc<crate::entitlement::Entitlement>>,
) {
    let cred = socket.peer_cred().ok().and_then(|cred| cred.pid());
    tracing::debug!("Connection from pid {cred:?}");

    let mut context = SimpleContext::with_roles(device_token, store_tokens, tokens);
    context.entitlement = entitlement;
    route_context(socket, token, context).await;
}

async fn route_context(
    mut socket: tokio::net::UnixStream,
    token: CancellationToken,
    mut context: SimpleContext,
) {
    loop {
        let mut read_magic = [0; 4];
        if token.is_cancelled() {
            return;
        }
        let read = socket.read_exact(&mut read_magic).await;
        if let Err(err) = read {
            tracing::error!("Failed to read magic: {err:?}");
            return;
        }

        let magic = u32::from_le_bytes(read_magic);
        let res = match magic {
            crate::XML_MAGIC => super::xml::handle(&mut socket, &mut context).await,
            0x58445345 => {
                let mut header = [0; 8];
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    socket.read_exact(&mut header),
                )
                .await
                {
                    Ok(Ok(_))
                        if u32::from_le_bytes(header[..4].try_into().unwrap()) == 1
                            && u32::from_le_bytes(header[4..].try_into().unwrap()) == 12 => {}
                    _ => return,
                }
                let mut product = [0; 12];
                if !matches!(
                    tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        socket.read_exact(&mut product)
                    )
                    .await,
                    Ok(Ok(_))
                ) {
                    return;
                }
                let valid = match (std::str::from_utf8(&product), &context.entitlement) {
                    (Ok(product), Some(binding)) => {
                        binding
                            .valid(product, &context.client, context.store_context().tokens())
                            .await
                    }
                    _ => false,
                };
                let bytes: Vec<u8> = [1u32, valid as u32]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect();
                socket.write_all(&bytes).await.map_err(|e| e.into())
            }
            0x58445341 => {
                let mut version = [0; 4];
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    socket.read_exact(&mut version),
                )
                .await
                {
                    Ok(Ok(_)) if u32::from_le_bytes(version) == 1 => {
                        let bytes: Vec<u8> = context
                            .account_roles()
                            .into_iter()
                            .flat_map(u32::to_le_bytes)
                            .collect();
                        socket.write_all(&bytes).await.map_err(|e| e.into())
                    }
                    _ => return,
                }
            }
            0x58445343 => super::catalog::handle(&mut socket).await,
            crate::PROTO_MAGIC => super::proto::handle(&mut socket, &mut context).await,
            _ => {
                tracing::error!("Unknown magic");
                return;
            }
        };

        if let Err(err) = res {
            tracing::error!("There was an error handling the message: {err}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wire_reports_roles_and_refuses_unbound_or_wrong_version_grants() {
        let context = crate::simple_context::tests::context("owner-wire", "player-wire");
        let owner = context.store_context().tokens().clone();
        let (mut client, server) = tokio::net::UnixStream::pair().unwrap();
        let task = tokio::spawn(route_context(server, CancellationToken::new(), context));
        client
            .write_all(
                &[0x58445341u32, 1]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect::<Vec<_>>(),
            )
            .await
            .unwrap();
        let mut response = [0; 16];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(
            response,
            [1u32, 1, 1, 0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>()
                .as_slice()
        );
        owner.remove_user().unwrap();
        client
            .write_all(
                &[0x58445341u32, 1]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect::<Vec<_>>(),
            )
            .await
            .unwrap();
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(
            response,
            [1u32, 0, 1, 0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>()
                .as_slice()
        );
        let mut request = [0x58445345u32, 1, 12]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        request.extend(b"9TESTROLE0ID");
        client.write_all(&request).await.unwrap();
        let mut grant = [0; 8];
        client.read_exact(&mut grant).await.unwrap();
        assert_eq!(
            grant,
            [1u32, 0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>()
                .as_slice()
        );
        client
            .write_all(
                &[0x58445341u32, 2]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect::<Vec<_>>(),
            )
            .await
            .unwrap();
        assert_eq!(client.read(&mut grant).await.unwrap(), 0);
        task.await.unwrap();
    }
}
