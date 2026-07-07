# frozen_string_literal: true
require "base64"
require "openssl"

class OrcidConnectAuthenticator < Auth::ManagedAuthenticator
  def name
    "orcid"
  end

  def can_revoke?
    SiteSetting.orcid_connect_allow_association_change
  end

  def can_connect_existing_user?
    SiteSetting.orcid_connect_allow_association_change
  end

  def enabled?
    SiteSetting.orcid_connect_enabled
  end

  def primary_email_verified?(auth)
    supplied_verified_boolean = auth["extra"]["raw_info"]["email_verified"]
    # If the payload includes the email_verified boolean, use it. Otherwise assume true
    if supplied_verified_boolean.nil?
      true
    else
      # Many providers violate the spec, and send this as a string rather than a boolean
      supplied_verified_boolean == true ||
        (supplied_verified_boolean.is_a?(String) && supplied_verified_boolean.downcase == "true")
    end
  end

  def provides_groups?
    SiteSetting.orcid_connect_groups_claim.present?
  end

  def after_authenticate(auth_token, existing_account: nil)
    result = super

    if provides_groups?
      claim = SiteSetting.orcid_connect_groups_claim
      result.associated_groups = []
      groups =
        auth_token.extra&.dig(:raw_info, claim) || auth_token.extra&.dig(:id_token_info, claim)

      if groups.is_a?(Array)
        result.associated_groups = groups.map { |group_name| { id: group_name, name: group_name } }
      elsif groups.present?
        orcid_log("groups claim '#{claim}' is not an array: #{groups.class}", error: true)
      else
        orcid_log("groups claim '#{claim}' not found in auth token")
      end
    end

    result.user_field_values = user_field_values_from(auth_token)

    result
  end

  def user_field_values_from(auth_token)
    mappings = JSON.parse(SiteSetting.orcid_connect_user_field_mappings.presence || "[]")
    return {} if mappings.blank?

    raw_info = auth_token.extra&.[](:raw_info)
    id_token_info = auth_token.extra&.[](:id_token_info)

    mappings.each_with_object({}) do |mapping, hash|
      claim = mapping["claim"].to_s
      field_id = mapping["user_field_id"]
      next if claim.blank? || field_id.blank?

      source =
        if raw_info&.key?(claim)
          raw_info
        elsif id_token_info&.key?(claim)
          id_token_info
        end
      next if source.nil?

      value = source[claim]
      hash[field_id.to_s] = value.is_a?(Array) ? value.join(",") : value.to_s
    end
  rescue JSON::ParserError
    {}
  end

  def always_update_user_email?
    SiteSetting.orcid_connect_overrides_email
  end

  def match_by_email
    SiteSetting.orcid_connect_match_by_email
  end

  def discovery_document
    document_url = SiteSetting.orcid_connect_discovery_document.presence
    if !document_url
      orcid_log("No discovery document URL specified", error: true)
      return
    end

    from_cache = true
    result =
      Discourse
        .cache
        .fetch("orcid-connect-discovery-#{document_url}", expires_in: 10.minutes) do
          from_cache = false
          orcid_log("Fetching discovery document from #{document_url}")
          connection =
            Faraday.new(request: { timeout: request_timeout_seconds }) do |c|
              c.use Faraday::Response::RaiseError
              c.adapter FinalDestination::FaradayAdapter
            end
          JSON.parse(connection.get(document_url).body)
        rescue Faraday::Error, JSON::ParserError => e
          orcid_log("Fetching discovery document raised error #{e.class} #{e.message}", error: true)
          nil
        end

    orcid_log("Discovery document loaded from cache") if from_cache
    orcid_log("Discovery document is\n\n#{result.to_yaml}")

    result
  end

  def orcid_log(message, error: false)
    if error
      Rails.logger.error("ORCID Log: #{message}")
    elsif SiteSetting.orcid_connect_verbose_logging
      Rails.logger.warn("ORCID Log: #{message}")
    end
  end

  def register_middleware(omniauth)
    omniauth.provider :orcid_connect,
                      name: :oidc,
                      error_handler:
                        lambda { |error, message|
                          handlers = SiteSetting.orcid_connect_error_redirects.split("\n")
                          handlers.each do |row|
                            parts = row.split("|")
                            return parts[1] if message.include? parts[0]
                          end
                          nil
                        },
                      verbose_logger: lambda { |message| orcid_log(message) },
                      setup:
                        lambda { |env|
                          opts = env["omniauth.strategy"].options

                          token_params = {}
                          token_params[
                            :scope
                          ] = SiteSetting.orcid_connect_token_scope if SiteSetting.orcid_connect_token_scope.present?

                          opts.deep_merge!(
                            client_id: SiteSetting.orcid_connect_client_id,
                            client_secret: SiteSetting.orcid_connect_client_secret,
                            discovery_document: discovery_document,
                            scope: SiteSetting.orcid_connect_authorize_scope,
                            token_params: token_params,
                            passthrough_authorize_options:
                              SiteSetting.orcid_connect_authorize_parameters.split("|"),
                            claims: SiteSetting.orcid_connect_claims,
                            pkce: SiteSetting.orcid_connect_use_pkce,
                            pkce_options: {
                              code_verifier: -> { generate_code_verifier },
                              code_challenge: ->(code_verifier) do
                                generate_code_challenge(code_verifier)
                              end,
                              code_challenge_method: "S256",
                            },
                          )

                          opts[:client_options][:connection_opts] = {
                            request: {
                              timeout: request_timeout_seconds,
                            },
                          }

                          opts[:client_options][:connection_build] = lambda do |builder|
                            if SiteSetting.orcid_connect_verbose_logging
                              builder.response :logger,
                                               Rails.logger,
                                               { bodies: true, formatter: ORCIDFaradayFormatter }
                            end

                            builder.request :url_encoded # form-encode POST params
                            builder.adapter FinalDestination::FaradayAdapter # make requests with FinalDestination::HTTP
                          end
                        }
  end

  def generate_code_verifier
    Base64.urlsafe_encode64(OpenSSL::Random.random_bytes(32)).tr("=", "")
  end

  def generate_code_challenge(code_verifier)
    Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier)).tr("+/", "-_").tr("=", "")
  end

  def request_timeout_seconds
    GlobalSetting.orcid_connect_request_timeout_seconds
  end
end
