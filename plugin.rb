# frozen_string_literal: true

# name: discourse-orcid-connect
# about: Allows users to login to your forum using an ORCid Connect provider as authentication.
# version: 1.0
# authors: Can Bekcan
# url: https://github.com/canbekcan/discourse-orcid-connect

enabled_site_setting :orcid_connect_enabled

register_svg_icon "id-badge"

require_relative "lib/orcid_connect_faraday_formatter"
require_relative "lib/omniauth_orc_id_connect"
require_relative "lib/orcid_connect_authenticator"

GlobalSetting.add_default :orcid_connect_request_timeout_seconds, 10

register_site_setting_area("orcid")
register_admin_config_login_route("orcid")

# RP-initiated logout
# https://openid.net/specs/orcid-connect-rpinitiated-1_0.html
on(:before_session_destroy) do |data|
  next if !SiteSetting.orcid_connect_rp_initiated_logout

  authenticator = OrcidConnectAuthenticator.new

  orcid_record = data[:user]&.user_associated_accounts&.find_by(provider_name: "orcid")
  if !orcid_record
    authenticator.orcid_log "Logout: No oidc user_associated_account record for user"
    next
  end

  token = orcid_record.extra["id_token"]
  if !token
    authenticator.orcid_log "Logout: No oidc id_token in user_associated_account record"
    next
  end

  end_session_endpoint = authenticator.discovery_document["end_session_endpoint"].presence
  if !end_session_endpoint
    authenticator.orcid_log "Logout: No end_session_endpoint found in discovery document",
                           error: true
    next
  end

  begin
    uri = URI.parse(end_session_endpoint)
  rescue URI::Error
    authenticator.orcid_log "Logout: unable to parse end_session_endpoint #{end_session_endpoint}",
                           error: true
  end

  authenticator.orcid_log "Logout: Redirecting user_id=#{data[:user].id} to end_session_endpoint"

  params = URI.decode_www_form(String(uri.query))

  params << ["id_token_hint", token]

  if SiteSetting.orcid_connect_rp_initiated_logout_include_client_id &&
       SiteSetting.orcid_connect_client_id.present?
    params << ["client_id", SiteSetting.orcid_connect_client_id]
  end

  post_logout_redirect = SiteSetting.orcid_connect_rp_initiated_logout_redirect.presence
  params << ["post_logout_redirect_uri", post_logout_redirect] if post_logout_redirect

  uri.query = URI.encode_www_form(params)
  data[:redirect_url] = uri.to_s
end

auth_provider authenticator: OrcidConnectAuthenticator.new
