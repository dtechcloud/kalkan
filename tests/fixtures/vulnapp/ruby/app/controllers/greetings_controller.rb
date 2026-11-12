# frozen_string_literal: true

# Greeting pages of the vulnapp Rails admin.
class GreetingsController < ApplicationController
  RETURN_PAGES = { "cart" => "/cart", "orders" => "/orders" }.freeze

  def show
    render html: "<p>Hello #{params[:name]}</p>".html_safe
  end

  def show_v2
    render html: "<p>Hello #{ERB::Util.html_escape(params[:name])}</p>".html_safe
  end

  def continue
    redirect_to params[:return_to], allow_other_host: true
  end

  def continue_v2
    redirect_to RETURN_PAGES.fetch(params[:page], "/")
  end
end
