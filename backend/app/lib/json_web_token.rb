require 'net/http'
require 'uri'

class JsonWebToken
  def self.verify(token)
    auth0_issuer = normalize_domain(ENV['AUTH0_DOMAIN'])
    
    # Auth0 tokens have trailing slash in issuer, so we need to accept both
    JWT.decode(token, nil,
              true, # Verify the signature of this token
              algorithms: 'RS256',
              iss: [auth0_issuer, "#{auth0_issuer}/"],
              verify_iss: true,
              aud: ENV['AUTH0_API_IDENTIFIER'],
              verify_aud: true) do |header|
      jwks_hash[header['kid']]
    end
  end

  def self.jwks_hash
    jwks_url = "#{normalize_domain(ENV['AUTH0_DOMAIN'])}/.well-known/jwks.json"
    uri = URI(jwks_url)
    
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    # In development, skip SSL verification to avoid certificate issues
    http.verify_mode = Rails.env.production? ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
    
    request = Net::HTTP::Get.new(uri.request_uri)
    response = http.request(request)
    
    jwks_raw = response.body
    jwks_keys = Array(JSON.parse(jwks_raw)['keys'])
    Hash[
      jwks_keys
      .map do |k|
        [
          k['kid'],
          OpenSSL::X509::Certificate.new(
            Base64.decode64(k['x5c'].first)
          ).public_key
        ]
      end
    ]
  end

  private

  def self.normalize_domain(domain)
    return nil if domain.nil? || domain.empty?
    # Ensure domain starts with https://
    domain = "https://#{domain}" unless domain.start_with?('http://', 'https://')
    # Remove trailing slash
    domain.chomp('/')
  end
end