require "spec"
require "io"
require "json"
require "../src/kemal-session-redis"

Kemal::Session.config.secret = "super-awesome-secret"
Kemal::Session.config.engine = Kemal::Session::RedisEngine.new

REDIS      = Redis::PooledClient.new
SESSION_ID = Random::Secure.hex(12)

Spec.before_each do
  REDIS.flushall
end

def create_context(session_id : String)
  response = HTTP::Server::Response.new(IO::Memory.new)
  headers = HTTP::Headers.new

  unless session_id == ""
    cookies = HTTP::Cookies.new
    encoded = Kemal::Session.encode(session_id)
    cookies << HTTP::Cookie.new(Kemal::Session.config.cookie_name, encoded)
    cookies.add_request_headers(headers)
  end

  request = HTTP::Request.new("GET", "/", headers)
  return HTTP::Server::Context.new(request, response)
end

class UserJsonSerializer
  include JSON::Serializable

  property id : Int32
  property name : String

  include Kemal::Session::StorableObject

  def initialize(@id : Int32, @name : String); end
end