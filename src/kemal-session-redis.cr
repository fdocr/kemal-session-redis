require "uri"
require "json"
require "redis"
require "kemal-session"

module Kemal
  class Session
    class RedisEngine < Engine
      class StorageInstance
        include JSON::Serializable

        macro define_storage(vars)
          {% for name, type in vars %}
            @[JSON::Field(key: "{{name.id}}s")]
            getter {{name.id}}s : Hash(String, {{type}})

            def {{name.id}}(k : String) : {{type}}
              return @{{name.id}}s[k]
            end

            def {{name.id}}?(k : String) : {{type}}?
              return @{{name.id}}s[k]?
            end

            def {{name.id}}(k : String, v : {{type}})
              @{{name.id}}s[k] = v
            end

            def delete_{{name.id}}(k : String)
              if @{{name.id}}s[k]?
                @{{name.id}}s.delete(k)
              end
            end
          {% end %}

          def initialize
            {% for name, type in vars %}
              @{{name.id}}s = Hash(String, {{type}}).new
            {% end %}
          end
        end

        define_storage({
          int: Int32,
          bigint: Int64,
          string: String,
          float: Float64,
          bool: Bool,
          object: Session::StorableObject::StorableObjectContainer
        })
      end

      @redis  : Redis::PooledClient
      @cache : StorageInstance
      @cached_session_id : String

      def initialize(host = "localhost", port = 6379, password = nil, database = 0, capacity = 20, timeout = 2.0, unixsocket = nil, pool = nil, key_prefix = "kemal:session:")
        @redis = uninitialized Redis::PooledClient

        if pool.nil?
          @redis = Redis::PooledClient.new(
            host: host,
            port: port,
            database: database,
            unixsocket: unixsocket,
            password: password,
            pool_size: capacity,
            pool_timeout: timeout
          )
        else
          @redis = pool
        end

        @cache = StorageInstance.new
        @key_prefix = key_prefix
        @cached_session_id = ""
      end

      def run_gc
        # Do Nothing. All the sessions should be set with the
        # expiration option on the keys. So long as the redis instance
        # hasn't been set up with maxmemory policy of noeviction
        # then this should be fine. `noeviction` will cause the redis
        # instance to fill up and keys will not expire from the instance
      end

      def prefix_session(session_id : String)
        "#{@key_prefix}#{session_id}"
      end

      def parse_session_id(key : String)
        key.sub(@key_prefix, "")
      end

      def load_into_cache(session_id)
        @cached_session_id = session_id

        @redis.pool.connection do |conn|
          value = conn.get(prefix_session(session_id))
          if !value.nil?
            @cache = StorageInstance.from_json(value)
          else
            @cache = StorageInstance.new
            conn.set(
              prefix_session(session_id),
              @cache.to_json,
              ex: Session.config.timeout.total_seconds.to_i
            )
          end
        end

        @cache
      end

      def save_cache
        @redis.pool.connection do |conn|
          conn.set(
            prefix_session(@cached_session_id),
            @cache.to_json,
            ex: Session.config.timeout.total_seconds.to_i
          )
        end
      end

      def is_in_cache?(session_id)
        return session_id == @cached_session_id
      end

      def create_session(session_id : String)
        load_into_cache(session_id)
      end

      def get_session(session_id : String) : Session?
        @redis.pool.connection do |conn|
          value = conn.get(prefix_session(session_id))
          return Session.new(session_id) if value
        end
      end

      def destroy_session(session_id : String)
        @redis.pool.connection do |conn|
          conn.del(prefix_session(session_id))
        end
      end

      def destroy_all_sessions
        @redis.pool.connection do |conn|
          cursor = 0
          loop do
            cursor, keys = conn.scan(cursor, "#{@key_prefix}*")
            keys = keys.as(Array(Redis::RedisValue)).map(&.to_s)
            keys.each do |key|
              conn.del(key)
            end
            break if cursor == "0"
          end
        end
      end

      def all_sessions : Array(Session)
        arr = [] of Session

        each_session do |session|
          arr << session
        end

        return arr
      end

      def each_session
        @redis.pool.connection do |conn|
          cursor = 0
          loop do
            cursor, keys = conn.scan(cursor, "#{@key_prefix}*")
            keys = keys.as(Array(Redis::RedisValue)).map(&.to_s)
            keys.each do |key|
              yield Session.new(parse_session_id(key.as(String)))
            end
            break if cursor == "0"
          end
        end
      end

      macro define_delegators(vars)
        {% for name, type in vars %}
          def {{name.id}}(session_id : String, k : String) : {{type}}
            load_into_cache(session_id) unless is_in_cache?(session_id)
            return @cache.{{name.id}}(k)
          end

          def {{name.id}}?(session_id : String, k : String) : {{type}}?
            load_into_cache(session_id) unless is_in_cache?(session_id)
            return @cache.{{name.id}}?(k)
          end

          def {{name.id}}(session_id : String, k : String, v : {{type}})
            load_into_cache(session_id) unless is_in_cache?(session_id)
            @cache.{{name.id}}(k, v)
            save_cache
          end

          def {{name.id}}s(session_id : String) : Hash(String, {{type}})
            load_into_cache(session_id) unless is_in_cache?(session_id)
            return @cache.{{name.id}}s
          end
        {% end %}
      end

      define_delegators({
        int: Int32,
        bigint: Int64,
        string: String,
        float: Float64,
        bool: Bool,
        object: Session::StorableObject::StorableObjectContainer,
      })
    end
  end
end