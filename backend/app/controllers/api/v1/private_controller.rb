class Api::V1::PrivateController < ApplicationController
  include Secured

  def index
    render json: { message: 'Hello from a private endpoint! You need to be authenticated to see this.' }
  end
end