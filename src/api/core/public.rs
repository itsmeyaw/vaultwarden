use std::collections::HashSet;

use chrono::Utc;
use rocket::{
    Request, Route,
    request::{FromRequest, Outcome},
    serde::json::Json,
};

use crate::{
    CONFIG,
    api::EmptyResult,
    auth,
    db::{
        DbConn,
        models::{
            Group, GroupUser, Invitation, Membership, MembershipStatus, MembershipType, OrgPolicy, Organization,
            OrganizationApiKey, OrganizationId, User,
        },
    },
    mail,
};

pub fn routes() -> Vec<Route> {
    routes![ldap_import]
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgImportGroupData {
    name: String,
    external_id: String,
    member_external_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgImportUserData {
    email: String,
    external_id: String,
    deleted: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgImportData {
    groups: Vec<OrgImportGroupData>,
    members: Vec<OrgImportUserData>,
    overwrite_existing: bool,
    // Only used to skip group pruning; upstream's 2000 users/groups limit is not enforced.
    #[serde(default)]
    large_import: bool,
}

// A group that came from the directory (has an external_id) but is no longer in the import is stale.
fn is_stale_import_group(group_external_id: Option<&str>, imported_ext_ids: &HashSet<&str>) -> bool {
    group_external_id.is_some_and(|id| !imported_ext_ids.contains(id))
}

// Directory Connector sends no groups when group sync is off, and splits large imports across requests.
fn should_prune_groups(data: &OrgImportData) -> bool {
    !data.groups.is_empty() && !data.large_import
}

#[post("/public/organization/import", data = "<data>")]
async fn ldap_import(data: Json<OrgImportData>, token: PublicToken, conn: DbConn) -> EmptyResult {
    // Most of the logic for this function can be found here
    // https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Core/AdminConsole/Services/Implementations/OrganizationService.cs#L1203

    let org_id = token.0;
    let data = data.into_inner();

    // Like upstream, the import never removes Owners, so it doesn't revoke or restore them either.
    for user_data in &data.members {
        let mut user_created: bool = false;
        if user_data.deleted {
            // If user is marked for deletion and it exists, revoke it
            if let Some(mut member) = Membership::find_by_email_and_org(&user_data.email, &org_id, &conn).await {
                let revoked = member.atype != MembershipType::Owner && member.revoke();
                let ext_modified = member.set_external_id(Some(user_data.external_id.clone()));
                if revoked || ext_modified {
                    member.save(&conn).await?;
                }
            }
        // If user is part of the organization, restore it
        } else if let Some(mut member) = Membership::find_by_email_and_org(&user_data.email, &org_id, &conn).await {
            let mut restored = member.atype != MembershipType::Owner && member.restore();
            let ext_modified = member.set_external_id(Some(user_data.external_id.clone()));
            // Enforce org policies as every other restore path does.
            // If the user is not allowed, we revoke again and continue so the external_id is still updated.
            if restored && let Err(e) = OrgPolicy::check_user_allowed(&member, "restore", &conn).await {
                warn!("Not restoring {}: {e:?}", user_data.email);
                member.revoke();
                restored = false;
            }
            if restored || ext_modified {
                member.save(&conn).await?;
            }
        } else {
            // If user is not part of the organization
            let user = if let Some(user) = User::find_by_mail(&user_data.email, &conn).await {
                user
            } else {
                // User does not exist yet
                let mut new_user = User::new(&user_data.email, None);
                new_user.save(&conn).await?;

                if !CONFIG.mail_enabled() {
                    Invitation::new(&new_user.email).save(&conn).await?;
                }
                user_created = true;
                new_user
            };
            let member_status = if CONFIG.mail_enabled() || user.password_hash.is_empty() {
                MembershipStatus::Invited as i32
            } else {
                MembershipStatus::Accepted as i32 // Automatically mark user as accepted if no email invites
            };

            let (org_name, org_email) = if let Some(org) = Organization::find_by_uuid(&org_id, &conn).await {
                (org.name, org.billing_email)
            } else {
                err!("Error looking up organization")
            };

            let mut new_member = Membership::new(user.uuid.clone(), org_id.clone(), Some(org_email.clone()));
            new_member.set_external_id(Some(user_data.external_id.clone()));
            new_member.access_all = false;
            new_member.atype = MembershipType::User as i32;
            new_member.status = member_status;

            new_member.save(&conn).await?;

            if CONFIG.mail_enabled()
                && let Err(e) =
                    mail::send_invite(&user, org_id.clone(), new_member.uuid.clone(), &org_name, Some(org_email)).await
            {
                // Upon error delete the user, invite and org member records when needed
                if user_created {
                    user.delete(&conn).await?;
                } else {
                    new_member.delete(&conn).await?;
                }

                err!(format!("Error sending invite: {e:?} "));
            }
        }
    }

    if CONFIG.org_groups_enabled() {
        for group_data in &data.groups {
            let group_uuid = if let Some(mut group) =
                Group::find_by_external_id_and_org(&group_data.external_id, &org_id, &conn).await
            {
                if group.name != group_data.name {
                    group.name = group_data.name.clone();
                    group.save(&conn).await?;
                }
                group.uuid
            } else {
                let mut group =
                    Group::new(org_id.clone(), group_data.name.clone(), false, Some(group_data.external_id.clone()));
                group.save(&conn).await?;
                group.uuid
            };

            GroupUser::delete_all_by_group(&group_uuid, &org_id, &conn).await?;

            for ext_id in &group_data.member_external_ids {
                if let Some(member) = Membership::find_by_external_id_and_org(ext_id, &org_id, &conn).await {
                    let mut group_user = GroupUser::new(group_uuid.clone(), member.uuid.clone());
                    group_user.save(&conn).await?;
                }
            }
        }

        if should_prune_groups(&data) {
            let imported_ext_ids: HashSet<&str> = data.groups.iter().map(|g| g.external_id.as_str()).collect();
            for group in Group::find_by_organization(&org_id, &conn).await {
                if is_stale_import_group(group.external_id.as_deref(), &imported_ext_ids) {
                    group.delete(&org_id, &conn).await?;
                }
            }
        }
    } else {
        warn!("Group support is disabled, groups will not be imported!");
    }

    // If this flag is enabled, any user that isn't provided in the Users list will be removed (by default they will be kept unless they have Deleted == true)
    if data.overwrite_existing {
        // Generate a HashSet to quickly verify if a member is listed or not.
        let sync_members: HashSet<String> = data.members.into_iter().map(|m| m.external_id).collect();
        for member in Membership::find_by_org(&org_id, &conn).await {
            if let Some(ref user_external_id) = member.external_id
                && !sync_members.contains(user_external_id)
                && member.atype != MembershipType::Owner
            {
                member.delete(&conn).await?;
            }
        }
    }

    Ok(())
}

pub struct PublicToken(OrganizationId);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for PublicToken {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = request.headers();
        // Get access_token
        let access_token: &str = if let Some(a) = headers.get_one("Authorization") {
            if let Some(split) = a.rsplit("Bearer ").next() {
                split
            } else {
                err_handler!("No access token provided")
            }
        } else {
            err_handler!("No access token provided")
        };
        // Check JWT token is valid and get device and user from it
        let Ok(claims) = auth::decode_api_org(access_token) else {
            err_handler!("Invalid claim")
        };
        // Check if time is between claims.nbf and claims.exp
        let time_now = Utc::now().timestamp();
        if time_now < claims.nbf {
            err_handler!("Token issued in the future");
        }
        if time_now > claims.exp {
            err_handler!("Token expired");
        }
        // Check if claims.iss is domain|claims.scope[0]
        let complete_host = format!("{}|{}", CONFIG.domain_origin(), claims.scope[0]);
        if complete_host != claims.iss {
            err_handler!("Token not issued by this server");
        }

        // Check if claims.sub is org_api_key.uuid
        // Check if claims.client_sub is org_api_key.org_uuid
        let Outcome::Success(conn) = DbConn::from_request(request).await else {
            err_handler!("Error getting DB")
        };
        let Some(org_id) = claims.client_id.strip_prefix("organization.") else {
            err_handler!("Malformed client_id")
        };
        let org_id: OrganizationId = org_id.to_owned().into();
        let Some(org_api_key) = OrganizationApiKey::find_by_org_uuid(&org_id, &conn).await else {
            err_handler!("Invalid client_id")
        };
        if org_api_key.org_uuid != claims.client_sub {
            err_handler!("Token not issued for this org");
        }
        if org_api_key.uuid != claims.sub {
            err_handler!("Token not issued for this client");
        }

        Outcome::Success(PublicToken(claims.client_sub))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn import_data(extra: serde_json::Value) -> OrgImportData {
        let mut data = json!({
            "groups": [{"name": "Group", "externalId": "ext-1", "memberExternalIds": []}],
            "members": [],
            "overwriteExisting": false
        });
        data.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        serde_json::from_value(data).unwrap()
    }

    #[test]
    fn group_missing_from_import_is_stale() {
        let imported = HashSet::from(["ext-1"]);
        assert!(is_stale_import_group(Some("ext-2"), &imported));
    }

    #[test]
    fn group_present_in_import_is_not_stale() {
        let imported = HashSet::from(["ext-1"]);
        assert!(!is_stale_import_group(Some("ext-1"), &imported));
    }

    #[test]
    fn manual_group_without_external_id_is_not_stale() {
        let imported = HashSet::from(["ext-1"]);
        assert!(!is_stale_import_group(None, &imported));
    }

    #[test]
    fn prune_allowed_for_regular_import() {
        assert!(should_prune_groups(&import_data(json!({}))));
    }

    #[test]
    fn prune_skipped_when_payload_has_no_groups() {
        assert!(!should_prune_groups(&import_data(json!({"groups": []}))));
    }

    #[test]
    fn prune_skipped_for_large_import() {
        assert!(!should_prune_groups(&import_data(json!({"largeImport": true}))));
    }

    #[test]
    fn large_import_defaults_to_false() {
        assert!(!import_data(json!({})).large_import);
    }

    #[test]
    fn large_import_deserializes_when_set() {
        assert!(import_data(json!({"largeImport": true})).large_import);
    }
}
