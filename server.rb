require 'sinatra'
require 'octokit'
require 'dotenv/load' # Manages environment variables
require 'json'
require 'openssl'     # Verifies the webhook signature
require 'jwt'         # Authenticates a GitHub App
require 'time'        # Gets ISO 8601 representation of a Time object
require 'logger'      # Logs debug statements

set :port, 3000
set :bind, '0.0.0.0'


## The base code for this application derives from: ##
## https://github.com/github-developer/using-the-github-api-in-your-app ##

class GHAapp < Sinatra::Application

  # Expects that the private key in PEM format. Converts the newlines
  PRIVATE_KEY = OpenSSL::PKey::RSA.new(ENV['GITHUB_PRIVATE_KEY'].gsub('\n', "\n"))

  # Your registered app must have a secret set. The secret is used to verify
  # that webhooks are sent by GitHub.
  WEBHOOK_SECRET = ENV['GITHUB_WEBHOOK_SECRET']

  # The GitHub App's identifier (type integer) set when registering an app.
  APP_IDENTIFIER = ENV['GITHUB_APP_IDENTIFIER']

  # Turn on Sinatra's verbose logging during development
  configure :development do
    set :logging, Logger::DEBUG
  end

  # Before each request to the `/event_handler` route
  before '/event_handler' do
    get_payload_request(request)
    verify_webhook_signature
    authenticate_app
    authenticate_installation(@payload)
  end


  post '/event_handler' do

    case request.env['HTTP_X_GITHUB_EVENT']
    when 'repository'
      if @payload['action'] === 'created'
      handle_repository_created_event(@payload)
      end
    end

    200 # success status
  end


  helpers do

    def handle_repository_created_event(payload)
      logger.debug 'A repository was created!  Now we should protect it!!'
      ##Get Repo Details for the updates##
      repo_fullname = payload['repository']['full_name']
      repo_url = payload['repository']['url']
      default_branch = payload['repository']['default_branch']
      
      ##Set Branch Protection Options##
      options = {
        ##Octokit branch protection is in preview mode -- ensure request headers are accurate to avoid issues##
        accept: 'application/vnd.github.html+json',
        ##Provide Branch Protection Rules -- Organizational Defaults are here, but others can be provided as necessary##
        required_pull_request_reviews: {dismiss_stale_reviews: false, require_code_owner_reviews: true, required_approving_review_count: 1}, 
        enforce_admins: true, 
        allow_force_pushes: false
      }

      ##Let us protect it!#
      @installation_client.protect_branch(repo_fullname, default_branch, options)

      ##Create an Issue to let us know the branch is protected##
      current_user = payload['sender']['login']
      issue_title = 'The Default Branch of ' + repo_fullname + ' is now protected!'
      issue_body = '@' + current_user + ' Protection has been enabled for ' + repo_fullname + '.
      The protections added are: 
      All commits must be made to a non-protected branch and submitted via a pull request before they can be merged.
      1 Code review and approval required to merge changes. 
      Administrators must follow these rules too!' 
      @installation_client.create_issue(repo_fullname, issue_title, issue_body)

    end

    # Saves the raw payload and converts the payload to JSON format
    def get_payload_request(request)
      # request.body is an IO or StringIO object
      # Rewind in case someone already read it
      request.body.rewind
      # The raw text of the body is required for webhook signature verification
      @payload_raw = request.body.read
      begin
        @payload = JSON.parse @payload_raw
      rescue => e
        fail  "Invalid JSON (#{e}): #{@payload_raw}"
      end
    end

    # Instantiate an Octokit client authenticated as a GitHub App.
    # GitHub App authentication requires that you construct a
    # JWT (https://jwt.io/introduction/) signed with the app's private key,
    # so GitHub can be sure that it came from the app an not altererd by
    # a malicious third party.
    def authenticate_app
      payload = {
          # The time that this JWT was issued, _i.e._ now.
          iat: Time.now.to_i,

          # JWT expiration time (10 minute maximum)
          exp: Time.now.to_i + (10 * 60),

          # Your GitHub App's identifier number
          iss: APP_IDENTIFIER
      }

      # Cryptographically sign the JWT.
      jwt = JWT.encode(payload, PRIVATE_KEY, 'RS256')

      # Create the Octokit client, using the JWT as the auth token.
      @app_client ||= Octokit::Client.new(bearer_token: jwt)
    end

    # Instantiate an Octokit client, authenticated as an installation of a
    # GitHub App, to run API operations.
    def authenticate_installation(payload)
      @installation_id = payload['installation']['id']
      @installation_token = @app_client.create_app_installation_access_token(@installation_id)[:token]
      @installation_client = Octokit::Client.new(bearer_token: @installation_token)
    end

    # Check X-Hub-Signature-256 to confirm that this webhook was generated by
    # GitHub, and not a malicious third party.
    #
    # GitHub uses the WEBHOOK_SECRET, registered to the GitHub App, to
    # create the hash signature sent in the `X-HUB-Signature-256` header of each
    # webhook. This code computes the expected hash signature and compares it to
    # the signature sent in the `X-HUB-Signature-256` header. If they don't match,
    # this request is an attack, and you should reject it. GitHub uses the HMAC
    # hexdigest to compute the signature. The `X-HUB-Signature-256` looks something
    # like this: "sha256=123456".
    # See https://docs.github.com/en/developers/webhooks-and-events/webhooks/securing-your-webhooks for details.
    def verify_webhook_signature
      their_signature_header = request.env['HTTP_X_HUB_SIGNATURE_256'] || 'sha256='
      method, their_digest = their_signature_header.split('=')
      our_digest = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'), WEBHOOK_SECRET, @payload_raw)
      halt 401 unless Rack::Utils.secure_compare(their_digest, our_digest)

      # The X-GITHUB-EVENT header provides the name of the event.
      # The action value indicates the which action triggered the event.
      logger.debug "---- received event #{request.env['HTTP_X_GITHUB_EVENT']}"
      logger.debug "----    action #{@payload['action']}" unless @payload['action'].nil?
    end
  end

  # Finally some logic to let us run this server directly from the command line,
  # or with Rack. Don't worry too much about this code. But, for the curious:
  # $0 is the executed file
  # __FILE__ is the current file
  # If they are the same—that is, we are running this file directly, call the
  # Sinatra run method
  run! if __FILE__ == $0
end
