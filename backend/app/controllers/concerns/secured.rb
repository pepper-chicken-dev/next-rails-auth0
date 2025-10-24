module Secured
  extend ActiveSupport::Concern

  included do
    before_action :authenticate_request!
  end

  private

  def authenticate_request!
    auth_token
  rescue JWT::VerificationError, JWT::DecodeError => e
    Rails.logger.error "JWT Verification failed: #{e.class} - #{e.message}"
    Rails.logger.error "Token: #{http_token&.first(50)}..." if http_token
    Rails.logger.error "AUTH0_DOMAIN: #{ENV['AUTH0_DOMAIN']}"
    Rails.logger.error "AUTH0_API_IDENTIFIER: #{ENV['AUTH0_API_IDENTIFIER']}"
    render json: { errors: ['Not Authenticated'], details: e.message }, status: :unauthorized
  end

  def http_token
    if request.headers['Authorization'].present?
      request.headers['Authorization'].split(' ').last
    end
  end

  def auth_token
    JsonWebToken.verify(http_token)
  end
end