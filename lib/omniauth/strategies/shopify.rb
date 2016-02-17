require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class Shopify < OmniAuth::Strategies::OAuth2
      # Available scopes: content themes products customers orders script_tags shipping
      # read_*  or write_*
      DEFAULT_SCOPE = 'read_products'
      MINUTE = 60
      CODE_EXPIRES_AFTER = 10 * MINUTE

      option :client_options, {
        :authorize_url => '/admin/oauth/authorize',
        :token_url => '/admin/oauth/access_token'
      }

      option :callback_url
      option :myshopify_domain, 'myshopify.com'

      option :setup, proc { |env|
        request = Rack::Request.new(env)
        env['omniauth.strategy'].options[:client_options][:site] = "https://#{request.GET['shop']}"
      }

      uid { URI.parse(options[:client_options][:site]).host }

      def valid_site?
        puts "valid site: domain: #{options[:myshopify_domain]}, site: #{options[:client_options][:site]}"
        !!(/\A(https|http)\:\/\/[a-zA-Z0-9][a-zA-Z0-9\-]*\.#{Regexp.quote(options[:myshopify_domain])}[\/]?\z/ =~ options[:client_options][:site])
      end

      def valid_signature?

        puts "request: #{request.inspect}"
        return false unless request.POST.empty?

        params = request.GET
        puts "GET: #{params.inspect}"
        signature = params['hmac']
        timestamp = params['timestamp']
        puts "Signature: '#{signature}', timestamp: #{timestamp}"
        return false unless signature && timestamp

        puts "Starting timestamp calculations..."
        return false unless timestamp.to_i > Time.now.to_i - CODE_EXPIRES_AFTER
        puts "Passed the timestamp calculations..."
        calculated_signature = self.class.hmac_sign(self.class.encoded_params_for_signature(params), options.client_secret)
        puts "Calculated signature... #{calculated_signature}"
        Rack::Utils.secure_compare(calculated_signature, signature)
      end

      def self.encoded_params_for_signature(params)
        puts "encoded params: #{params.inspect}"
        params = params.dup
        params.delete('hmac')
        params.delete('signature') # deprecated signature
        params.map{|k,v| "#{URI.escape(k.to_s, '&=%')}=#{URI.escape(v.to_s, '&%')}"}.sort.join('&')
      end

      def self.hmac_sign(encoded_params, secret)
        OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, secret, encoded_params)
      end

      def fix_https
        options[:client_options][:site].gsub!(/\Ahttp\:/, 'https:')
      end

      def setup_phase
        super
        fix_https
      end

      def request_phase
        puts "Request Phase: #{request.inspect}"
        if valid_site?
          super
        else
          puts "Failed in the request phase as an invalid site..."
          fail!(:invalid_site)
        end
      end

      def callback_phase
        puts "Callback Phase: #{request.inspect}"
        return fail!(:invalid_site) unless valid_site?
        return fail!(:invalid_signature) unless valid_signature?
        super
      end

      def authorize_params
        super.tap do |params|
          params[:scope] ||= DEFAULT_SCOPE
        end
      end

      def callback_url
        options[:callback_url] || full_host + script_name + callback_path
      end
    end
  end
end
