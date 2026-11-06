# frozen_string_literal: true

require "base64"
require "bcrypt"
require "digest"
require "erb"
require "json"
require "jwt"
require "mongo"
require "net/http"
require "nokogiri"
require "openssl"
require "sinatra/base"
require "sqlite3"

# Storefront API of the vulnapp fixture.
class StorefrontApp < Sinatra::Base
  REPORT_DIR = File.expand_path("reports", __dir__)
  JWT_KEY = ENV.fetch("VULNAPP_JWT_KEY", "")
  CARD_KEY = [ENV.fetch("VULNAPP_CARD_KEY", "")].pack("H*")
  NOTE_TEMPLATE = "<p>Note for <%= ERB::Util.html_escape(name) %></p>"
  FORMULAS = { "net" => "100 * 0.8", "gross" => "100 * 1.2" }.freeze
  STATUS_FEEDS = {
    "payments" => "https://status.payments.vulnapp.internal/feed.json",
    "shipping" => "https://status.shipping.vulnapp.internal/feed.json"
  }.freeze

  def db
    @db ||= SQLite3::Database.new(ENV.fetch("VULNAPP_DB", "vulnapp.sqlite3"))
  end

  def mongo
    @mongo ||= Mongo::Client.new(ENV.fetch("VULNAPP_MONGO_URL", "mongodb://localhost:27017/vulnapp"))
  end

  def hash_password(password)
    Digest::MD5.hexdigest(password)
  end

  def hash_password_v2(password)
    BCrypt::Password.create(password).to_s
  end

  def seal_card(number)
    cipher = OpenSSL::Cipher.new("aes-256-ecb")
    cipher.encrypt
    cipher.key = CARD_KEY
    Base64.strict_encode64(cipher.update(number) + cipher.final)
  end

  def seal_card_v2(number)
    cipher = OpenSSL::Cipher.new("aes-256-gcm")
    cipher.encrypt
    cipher.key = CARD_KEY
    iv = cipher.random_iv
    sealed = cipher.update(number) + cipher.final
    Base64.strict_encode64(iv + cipher.auth_tag + sealed)
  end

  before "/partner/*" do
    response.headers["Access-Control-Allow-Origin"] = request.env["HTTP_ORIGIN"]
    response.headers["Access-Control-Allow-Credentials"] = "true"
  end

  before "/store/*" do
    response.headers["Access-Control-Allow-Origin"] = "https://shop.vulnapp.internal"
    response.headers["Access-Control-Allow-Credentials"] = "true"
  end

  get "/items/search" do
    rows = db.execute("SELECT id, name FROM items WHERE name = '#{params[:name]}'")
    JSON.generate(rows)
  end

  get "/items/filter" do
    rows = db.execute("SELECT id, name FROM items WHERE name = ?", [params[:name]])
    JSON.generate(rows)
  end

  get "/tools/ping" do
    reachable = system("ping -c 1 #{params[:host]}")
    reachable ? "reachable" : "unreachable"
  end

  get "/tools/ping/v2" do
    reachable = system("ping", "-c", "1", "--", params[:host].to_s)
    reachable ? "reachable" : "unreachable"
  end

  get "/tools/calc" do
    JSON.generate(result: eval(params[:expr]))
  end

  get "/tools/calc/v2" do
    JSON.generate(result: eval(FORMULAS.fetch(params[:formula], "0")))
  end

  post "/notes/preview" do
    ERB.new(params[:template]).result_with_hash(name: params[:name])
  end

  post "/notes/preview/v2" do
    ERB.new(NOTE_TEMPLATE).result_with_hash(name: params[:name])
  end

  get "/tools/fetch" do
    Net::HTTP.get(URI(params[:url]))
  end

  get "/tools/feed" do
    Net::HTTP.get(URI(STATUS_FEEDS.fetch(params[:feed], STATUS_FEEDS["payments"])))
  end

  get "/reports" do
    send_file File.join(REPORT_DIR, params[:name])
  end

  get "/reports/summary" do
    send_file File.join(REPORT_DIR, File.basename(params[:name].to_s))
  end

  post "/cart/restore" do
    cart = Marshal.load(Base64.decode64(params[:state]))
    JSON.generate(items: cart.size)
  end

  post "/cart/load" do
    cart = JSON.parse(Base64.decode64(params[:state]))
    JSON.generate(items: cart.size)
  end

  post "/import" do
    doc = Nokogiri::XML(request.body.read) { |config| config.noent.dtdload }
    JSON.generate(root: doc.root&.name)
  end

  post "/import/v2" do
    doc = Nokogiri::XML(request.body.read) { |config| config.nonet }
    JSON.generate(root: doc.root&.name)
  end

  post "/users/lookup" do
    user = mongo[:users].find(username: params[:username]).first
    JSON.generate(found: !user.nil?)
  end

  post "/users/exists" do
    user = mongo[:users].find(username: params[:username].to_s).first
    JSON.generate(found: !user.nil?)
  end

  get "/account" do
    token = request.env["HTTP_AUTHORIZATION"].to_s.delete_prefix("Bearer ")
    claims, = JWT.decode(token, nil, false)
    JSON.generate(user: claims["sub"])
  end

  get "/account/v2" do
    token = request.env["HTTP_AUTHORIZATION"].to_s.delete_prefix("Bearer ")
    claims, = JWT.decode(token, JWT_KEY, true, algorithm: "HS256")
    JSON.generate(user: claims["sub"])
  end

  post "/register" do
    db.execute("INSERT INTO users (name, pw) VALUES (?, ?)", [params[:name], hash_password(params[:password])])
    status 201
  end

  post "/password" do
    db.execute("UPDATE users SET pw = ? WHERE id = ?", [hash_password_v2(params[:password]), 1])
    status 204
  end

  post "/cards" do
    JSON.generate(token: seal_card(params[:number].to_s))
  end

  post "/cards/v2" do
    JSON.generate(token: seal_card_v2(params[:number].to_s))
  end
end
