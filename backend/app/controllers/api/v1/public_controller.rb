class Api::V1::PublicController < ApplicationController
  def index
    render json: { message: 'Hello from a public endpoint! You don\'t need to be authenticated to see this.' }
  end
end