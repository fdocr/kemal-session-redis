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
            @[JSON::Field(key: {{name.id}})]
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
          object: Kemal::Session::StorableObject::StorableObjectContainer
        })
      end

      @redis : Redis::Client
      @cache : StorageInstance
      @cached_session_id : String

      def initialize(key_prefix = "kemal:session:")
        redis_url = ENV.fetch("REDIS_URL", "redis://localhost:6379/0")
        @redis = Redis::Client.new(URI.parse(redis_url))
        @cache = Kemal::Session::RedisEngine::StorageInstance.new
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
        value = @redis.get(prefix_session(session_id))
        if !value.nil?
          @cache = Kemal::Session::RedisEngine::StorageInstance.from_json(value)
        else
          @cache = StorageInstance.new
          @redis.set(
            prefix_session(session_id),
            @cache.to_json,
            ex: Kemal::Session.config.timeout.total_seconds.to_i
          )
        end
        return @cache
      end

      def save_cache
        @redis.set(
          prefix_session(@cached_session_id),
          @cache.to_json,
          ex: Kemal::Session.config.timeout.total_seconds.to_i
        )
      end

      def is_in_cache?(session_id)
        return session_id == @cached_session_id
      end

      def create_session(session_id : String)
        load_into_cache(session_id)
      end

      def get_session(session_id : String) : (Kemal::Session | Nil)
        value = @redis.get(prefix_session(session_id))

        return Kemal::Session.new(session_id) if value
        nil
      end

      def destroy_session(session_id : String)
        @redis.del(prefix_session(session_id))
      end

      def destroy_all_sessions
        cursor = ""
        until cursor == "0"
          response = @redis.scan(cursor, match: "#{@key_prefix}*")
          cursor, results = response.as(Array)
          cursor = cursor.as(String)
          results.as(Array).each do |key|
            @redis.del(key.as(String))
          end
        end
      end

      def all_sessions : Array(Kemal::Session)
        arr = [] of Kemal::Session

        each_session do |session|
          arr << session
        end

        return arr
      end

      def each_session
        cursor = ""
        until cursor == "0"
          response = @redis.scan(cursor, match: "#{@key_prefix}*")
          cursor, results = response.as(Array)
          cursor = cursor.as(String)
          results.as(Array).each do |key|
            yield Kemal::Session.new(parse_session_id(key.as(String)))
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
        object: Kemal::Session::StorableObject::StorableObjectContainer,
      })
    end
  end
end
