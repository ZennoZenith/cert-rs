// use std::sync::OnceLock;

// use cert_rs::{
//     AcmeApi,
//     account::AccountCreate,
//     challenge::{ChallengeResponder, ChallengeType},
//     directory::AcmeDirectory,
//     order::OrderStatus,
// };
// use color_eyre::Result;
// use fake::{
//     Fake,
//     faker::{
//         internet::en::{DomainSuffix, SafeEmail},
//         name::en::LastName,
//     },
// };
// use tracing_subscriber::EnvFilter;

// use url::Url;

// fn initialize_eyre_and_tracing() {
//     static INSTANCE: OnceLock<()> = OnceLock::new();

//     INSTANCE.get_or_init(|| {
//         color_eyre::install().expect("Unable to initialize color_eyre");

//         tracing_subscriber::fmt()
//             .without_time() // For early local development.
//             .with_target(false)
//             .with_env_filter(EnvFilter::from_default_env())
//             .init();
//     });
// }

// struct TestData {
//     acme_uri: Url,
//     domains: Vec<String>,
//     wildcard_domains: Vec<String>,
//     mixed_domains: Vec<String>,
//     account_create: AccountCreate,
// }

// fn initialize_test() -> Result<TestData> {
//     initialize_eyre_and_tracing();

//     let acme_uri: Url = std::env::var("TEST_ACME_DIR")
//         .unwrap_or(String::from("https://localhost:24000/dir"))
//         .parse()?;

//     let domains: Vec<String> = (0..5)
//         .map(|_| {
//             let domain_suffix: String = DomainSuffix().fake();
//             let name: String = LastName().fake::<String>().to_lowercase();

//             format!("{name}.{domain_suffix}")
//         })
//         .collect();

//     let wildcard_domains: Vec<String> = (0..5)
//         .map(|_| {
//             let domain_suffix: String = DomainSuffix().fake();
//             let name: String = LastName().fake::<String>().to_lowercase();

//             format!("*.{name}.{domain_suffix}")
//         })
//         .collect();

//     let emails: Vec<String> =
//         (0..5).map(|_| SafeEmail().fake::<String>()).collect();

//     let account_create = AccountCreate {
//         terms_of_service_agreed: Some(true),
//         contacts: Some(emails),
//         ..Default::default()
//     };

//     let mixed_domains: Vec<String> = (0..3)
//         .map(|_| {
//             let domain_suffix: String = DomainSuffix().fake();
//             let name: String = LastName().fake::<String>().to_lowercase();

//             format!("{name}.{domain_suffix}")
//         })
//         .chain((0..2).map(|_| {
//             let domain_suffix: String = DomainSuffix().fake();
//             let name: String = LastName().fake::<String>().to_lowercase();

//             format!("*.{name}.{domain_suffix}")
//         }))
//         .collect();

//     Ok(TestData {
//         acme_uri,
//         domains,
//         wildcard_domains,
//         mixed_domains,
//         account_create,
//     })
// }

// #[tokio::test]
// async fn register_account_ok() -> Result<()> {
//     let TestData {
//         acme_uri,
//         account_create,
//         ..
//     } = initialize_test()?;
//     let acme_dir = AcmeDirectory::new_from_url(acme_uri).await?;

//     let acme_api_unregistered = AcmeApi::new(acme_dir).await?;

//     acme_api_unregistered.register_account(account_create).await?;

//     Ok(())
// }

// #[tokio::test]
// async fn fetch_account_ok() -> Result<()> {
//     let TestData {
//         acme_uri,
//         account_create,
//         ..
//     } = initialize_test()?;
//     let acme_dir = AcmeDirectory::new_from_url(acme_uri.clone()).await?;

//     let acme_api_unregistered = AcmeApi::new(acme_dir).await?;

//     let acme_api_registered =
//         acme_api_unregistered.register_account(account_create).await?;

//     let register_account = acme_api_registered.registered_account();

//     let acme_dir = AcmeDirectory::new_from_url(acme_uri).await?;
//     let acme_api_unregistered = AcmeApi::new(acme_dir).await?;

//     acme_api_unregistered
//         .fetch_account(register_account.private_key().clone())
//         .await?;

//     Ok(())
// }

// #[tokio::test]
// async fn fetch_account_fail() -> Result<()> {
//     let TestData { acme_uri, .. } = initialize_test()?;
//     let acme_dir = AcmeDirectory::new_from_url(acme_uri.clone()).await?;

//     let acme_api_unregistered = AcmeApi::new(acme_dir).await?;

//     let private_key = Rsa::generate(4096)?;

//     let registered_account =
//         acme_api_unregistered.fetch_account(private_key).await;

//     assert!(registered_account.is_err());

//     Ok(())
// }

// #[tokio::test]
// async fn create_order() -> Result<()> {
//     let TestData {
//         acme_uri,
//         account_create,
//         mixed_domains,
//         ..
//     } = initialize_test()?;
//     let acme_dir = AcmeDirectory::new_from_url(acme_uri.clone()).await?;

//     let acme_api_unregistered = AcmeApi::new(acme_dir).await?;

//     let acme_api_registered =
//         acme_api_unregistered.register_account(account_create).await?;

//     let (_order_url, _order) =
//         acme_api_registered.create_order(mixed_domains).await?;

//     Ok(())
// }

// #[tokio::test]
// async fn order_status() -> Result<()> {
//     let TestData {
//         acme_uri,
//         account_create,
//         mixed_domains,
//         ..
//     } = initialize_test()?;
//     let acme_dir = AcmeDirectory::new_from_url(acme_uri.clone()).await?;

//     let acme_api_unregistered = AcmeApi::new(acme_dir).await?;

//     let acme_api_registered =
//         acme_api_unregistered.register_account(account_create).await?;

//     let (order_url, _order) =
//         acme_api_registered.create_order(mixed_domains).await?;

//     let _order_status = acme_api_registered.order_status(&order_url).await?;

//     Ok(())
// }

// #[tokio::test]
// async fn authorization_with_url() -> Result<()> {
//     let TestData {
//         acme_uri,
//         account_create,
//         mixed_domains,
//         ..
//     } = initialize_test()?;
//     let acme_dir = AcmeDirectory::new_from_url(acme_uri.clone()).await?;

//     let acme_api_unregistered = AcmeApi::new(acme_dir).await?;

//     let acme_api_registered =
//         acme_api_unregistered.register_account(account_create).await?;

//     let (order_url, _order) =
//         acme_api_registered.create_order(mixed_domains).await?;

//     let order_status = acme_api_registered.order_status(&order_url).await?;

//     let _authorization_with_urls =
//         acme_api_registered.challenges(&order_status).await?;

//     Ok(())
// }

// #[tokio::test]
// async fn challenge_responders() -> Result<()> {
//     let TestData {
//         acme_uri,
//         account_create,
//         mixed_domains,
//         ..
//     } = initialize_test()?;
//     let acme_dir = AcmeDirectory::new_from_url(acme_uri.clone()).await?;

//     let acme_api_unregistered = AcmeApi::new(acme_dir).await?;

//     let acme_api_registered =
//         acme_api_unregistered.register_account(account_create).await?;

//     let (order_url, _order) =
//         acme_api_registered.create_order(mixed_domains).await?;

//     let order_status = acme_api_registered.order_status(&order_url).await?;

//     let authorization_with_urls =
//         acme_api_registered.challenges(&order_status).await?;

//     let _challenge_responders =
//         acme_api_registered.clean_challenges(&authorization_with_urls).await?;

//     Ok(())
// }

// #[tokio::test]
// async fn respond_to_only_http_01_challenges() -> Result<()> {
//     let TestData {
//         acme_uri,
//         account_create,
//         domains,
//         ..
//     } = initialize_test()?;
//     let acme_dir = AcmeDirectory::new_from_url(acme_uri.clone()).await?;

//     let acme_api_unregistered = AcmeApi::new(acme_dir).await?;

//     let acme_api_registered =
//         acme_api_unregistered.register_account(account_create).await?;

//     let (order_url, _order) = acme_api_registered.create_order(domains).await?;

//     let order_status = acme_api_registered.order_status(&order_url).await?;

//     let authorization_with_urls =
//         acme_api_registered.challenges(&order_status).await?;

//     let challenge_responders =
//         acme_api_registered.clean_challenges(&authorization_with_urls).await?;

//     handle_http_01_challenge(&challenge_responders).await?;

//     let _authorization_with_urls = acme_api_registered
//         .respond_to_challenges(&authorization_with_urls)
//         .await?;

//     let order = loop {
//         tokio::time::sleep(std::time::Duration::from_secs(2)).await;
//         let order = acme_api_registered.order_status(&order_url).await?;

//         match order.status {
//             OrderStatus::Pending | OrderStatus::Processing => continue,
//             _ => break order,
//         }
//     };

//     assert_eq!(order.status, OrderStatus::Ready);

//     Ok(())
// }

// #[tokio::test]
// async fn respond_to_only_dns_01_challenges() -> Result<()> {
//     let TestData {
//         acme_uri,
//         account_create,
//         wildcard_domains,
//         ..
//     } = initialize_test()?;
//     let acme_dir = AcmeDirectory::new_from_url(acme_uri.clone()).await?;

//     let acme_api_unregistered = AcmeApi::new(acme_dir).await?;

//     let acme_api_registered =
//         acme_api_unregistered.register_account(account_create).await?;

//     let (order_url, _order) =
//         acme_api_registered.create_order(wildcard_domains).await?;

//     let order_status = acme_api_registered.order_status(&order_url).await?;

//     let authorization_with_urls =
//         acme_api_registered.challenges(&order_status).await?;

//     let challenge_responders =
//         acme_api_registered.clean_challenges(&authorization_with_urls).await?;

//     handle_dns_01_challenge(&challenge_responders).await?;

//     let _authorization_with_urls = acme_api_registered
//         .respond_to_challenges(&authorization_with_urls)
//         .await?;

//     let order = loop {
//         tokio::time::sleep(std::time::Duration::from_secs(2)).await;
//         let order = acme_api_registered.order_status(&order_url).await?;

//         match order.status {
//             OrderStatus::Pending | OrderStatus::Processing => continue,
//             _ => break order,
//         }
//     };

//     assert_eq!(order.status, OrderStatus::Ready);

//     Ok(())
// }

// #[tokio::test]
// async fn respond_to_http_01_and_dns_01_challenges() -> Result<()> {
//     let TestData {
//         acme_uri,
//         account_create,
//         mixed_domains,
//         ..
//     } = initialize_test()?;
//     let acme_dir = AcmeDirectory::new_from_url(acme_uri.clone()).await?;

//     let acme_api_unregistered = AcmeApi::new(acme_dir).await?;

//     let acme_api_registered =
//         acme_api_unregistered.register_account(account_create).await?;

//     let (order_url, _order) =
//         acme_api_registered.create_order(mixed_domains).await?;

//     let order_status = acme_api_registered.order_status(&order_url).await?;

//     let authorization_with_urls =
//         acme_api_registered.challenges(&order_status).await?;

//     let challenge_responders =
//         acme_api_registered.clean_challenges(&authorization_with_urls).await?;

//     handle_http_01_challenge(&challenge_responders).await?;
//     handle_dns_01_challenge(&challenge_responders).await?;

//     let _authorization_with_urls = acme_api_registered
//         .respond_to_challenges(&authorization_with_urls)
//         .await?;

//     let order = loop {
//         tokio::time::sleep(std::time::Duration::from_secs(2)).await;
//         let order = acme_api_registered.order_status(&order_url).await?;

//         match order.status {
//             OrderStatus::Pending | OrderStatus::Processing => continue,
//             _ => break order,
//         }
//     };

//     assert_eq!(order.status, OrderStatus::Ready);

//     Ok(())
// }

// #[tokio::test]
// async fn finalize_order() -> Result<()> {
//     let TestData {
//         acme_uri,
//         account_create,
//         mixed_domains,
//         ..
//     } = initialize_test()?;
//     let acme_dir = AcmeDirectory::new_from_url(acme_uri.clone()).await?;

//     let acme_api_unregistered = AcmeApi::new(acme_dir).await?;

//     let acme_api_registered =
//         acme_api_unregistered.register_account(account_create).await?;

//     let (order_url, _order) =
//         acme_api_registered.create_order(mixed_domains).await?;

//     let order_status = acme_api_registered.order_status(&order_url).await?;

//     let authorization_with_urls =
//         acme_api_registered.challenges(&order_status).await?;

//     let challenge_responders =
//         acme_api_registered.clean_challenges(&authorization_with_urls).await?;

//     handle_http_01_challenge(&challenge_responders).await?;
//     handle_dns_01_challenge(&challenge_responders).await?;

//     let _authorization_with_urls = acme_api_registered
//         .respond_to_challenges(&authorization_with_urls)
//         .await?;

//     let order = loop {
//         tokio::time::sleep(std::time::Duration::from_secs(2)).await;
//         let order = acme_api_registered.order_status(&order_url).await?;

//         match order.status {
//             OrderStatus::Pending | OrderStatus::Processing => continue,
//             _ => break order,
//         }
//     };

//     assert_eq!(order.status, OrderStatus::Ready);

//     acme_api_registered.finalize_order(&order_status).await?;

//     let order = loop {
//         tokio::time::sleep(std::time::Duration::from_secs(2)).await;
//         let order = acme_api_registered.order_status(&order_url).await?;

//         match order.status {
//             OrderStatus::Pending | OrderStatus::Processing => continue,
//             _ => break order,
//         }
//     };
//     assert_eq!(order.status, OrderStatus::Valid);

//     Ok(())
// }

// async fn handle_http_01_challenge(
//     challenge_responders: &[ChallengeResponder],
// ) -> Result<()> {
//     let chall_test_srv: Url = std::env::var("TEST_CHALL_TEST_SRV")
//         .unwrap_or(String::from("http://localhost:8055"))
//         .parse()?;
//     let http_01_url = chall_test_srv.join("add-http01").unwrap().to_string();
//     let clear_http_01 = chall_test_srv.join("del-http01").unwrap().to_string();

//     // http_01 challenges
//     for challenge_token in challenge_responders
//         .iter()
//         .filter(|v| v.r#type == ChallengeType::Http01)
//     {
//         // clear http_01 challenges
//         reqwest::Client::new()
//             .post(&clear_http_01)
//             .json(&serde_json::json!({
//                 "token": challenge_token.token
//             }))
//             .send()
//             .await?;

//         reqwest::Client::new()
//             .post(&http_01_url)
//             .json(&serde_json::json!({
//                 "token": challenge_token.token,
//                 "content": challenge_token.keyauth
//             }))
//             .send()
//             .await?;
//     }

//     Ok(())
// }

// async fn handle_dns_01_challenge(
//     challenge_responders: &[ChallengeResponder],
// ) -> Result<()> {
//     let chall_test_srv: Url = std::env::var("TEST_CHALL_TEST_SRV")
//         .unwrap_or(String::from("http://localhost:8055"))
//         .parse()?;

//     let dns_01_url = chall_test_srv.join("set-txt").unwrap().to_string();
//     let clear_dns_01 = chall_test_srv.join("clear-txt").unwrap().to_string();

//     // dns_01 challenges
//     for challenge_token in challenge_responders
//         .iter()
//         .filter(|v| v.r#type == ChallengeType::Dns01)
//     {
//         // clear dns_01 challenges
//         let host = format!("_acme-challenge.{}.", challenge_token.domain);
//         reqwest::Client::new()
//             .post(&clear_dns_01)
//             .json(&serde_json::json!({
//                 "host": host
//             }))
//             .send()
//             .await?;

//         let host = format!("_acme-challenge.{}.", challenge_token.domain);
//         reqwest::Client::new()
//             .post(&dns_01_url)
//             .json(&serde_json::json!({
//                 "host": host,
//                 "value": challenge_token.sha_256_keyauth
//             }))
//             .send()
//             .await?;
//     }
//     Ok(())
// }
