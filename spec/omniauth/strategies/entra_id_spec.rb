require 'spec_helper'
require 'omniauth/entra_id'

RSpec.describe OmniAuth::Strategies::EntraId do
  let(:request) { double('Request', :params => {}, :cookies => {}, :env => {}) }
  let(:app) {
    lambda do
      [200, {}, ["Hello."]]
    end
  }

  before do
    OmniAuth.config.test_mode = true
  end

  after do
    OmniAuth.config.test_mode = false
  end

  describe 'static configuration' do
    let(:options) { @options || {} }
    subject do
      OmniAuth::Strategies::EntraId.new(app, {client_id: 'id', client_secret: 'secret', tenant_id: 'tenant'}.merge(options))
    end

    describe '#client' do
      it 'has correct authorize url' do
        allow(subject).to receive(:request) { request }
        expect(subject.client.options[:authorize_url]).to eql('https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize')
      end

      it 'has correct authorize params' do
        allow(subject).to receive(:request) { request }
        subject.client
        expect(subject.authorize_params[:domain_hint]).to be_nil
      end

      it 'has correct token url' do
        allow(subject).to receive(:request) { request }
        expect(subject.client.options[:token_url]).to eql('https://login.microsoftonline.com/tenant/oauth2/v2.0/token')
      end

      context 'when a custom policy and tenant name are present' do
        it 'generates the B2C URL' do
          @options = { custom_policy: 'my_policy', tenant_name: 'my_tenant' }
          allow(subject).to receive(:request) { request }
          expect(subject.client.options[:token_url]).to eql('https://my_tenant.b2clogin.com/my_tenant.onmicrosoft.com/my_policy/oauth2/v2.0/token')
        end
      end # "context 'when a custom policy and tenant name are present' do"

      it 'supports authorization_params' do
        @options = { authorize_params: {prompt: 'select_account'} }
        allow(subject).to receive(:request) { request }
        subject.client
        expect(subject.authorize_params[:prompt]).to eql('select_account')
      end

      it 'supports custom redirect uri' do
        @options = { redirect_uri: 'https://foo.bar' }
        allow(subject).to receive(:request) { request }
        subject.client
        expect(subject.authorize_params[:redirect_uri]).to eql('https://foo.bar')
      end

      context 'using client secret flow without client secret' do
        subject do
          OmniAuth::Strategies::EntraId.new(app, { client_id: 'id', tenant_id: 'tenant' }.merge(options))
        end

        it 'raises exception' do
          expect { subject.client }.to raise_error(ArgumentError, "You must provide either client_secret or certificate_path and tenant_id")
        end
      end # "context 'using client secret flow without client secret' do"

      context 'using client assertion flow' do
        subject do
          OmniAuth::Strategies::EntraId.new(app, options)
        end

        it 'raises exception when tenant id is not given' do
          @options = { client_id: 'id', certificate_path: 'path/to/cert.p12' }
          expect { subject.client }.to raise_error(ArgumentError, "You must provide either client_secret or certificate_path and tenant_id")
        end

        it 'raises exception when certificate_path is not given' do
          @options = { client_id: 'id', tenant_id: 'tenant' }
          expect { subject.client }.to raise_error(ArgumentError, "You must provide either client_secret or certificate_path and tenant_id")
        end

        context '#token_params with correctly formatted request' do
          let(:key) { OpenSSL::PKey::RSA.new(2048) }
          let(:cert) { OpenSSL::X509::Certificate.new.tap { |cert|
            cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=test")
            cert.not_before = Time.now
            cert.not_after = Time.now + 365 * 24 * 60 * 60
            cert.public_key = key.public_key
            cert.serial = 0x0
            cert.version = 2
            cert.sign(key, OpenSSL::Digest::SHA256.new)
          } }

          before do
            @options = {
              client_id: 'id',
              tenant_id: 'tenant',
              certificate_path: 'path/to/cert.p12'
            }

            allow(File).to receive(:read)
            allow(OpenSSL::PKCS12).to receive(:new).and_return(OpenSSL::PKCS12.create('pass', 'name', key, cert))
            allow(SecureRandom).to receive(:uuid).and_return('unique-jti')

            allow(subject).to receive(:request) { request }
            subject.client
          end

          it 'has correct tenant id' do
            expect(subject.options.token_params[:tenant]).to eql('tenant')
          end

          it 'has correct client id' do
            expect(subject.options.token_params[:client_id]).to eql('id')
          end

          it 'has correct client_assertion_type' do
            expect(subject.options.token_params[:client_assertion_type]).to eql('urn:ietf:params:oauth:client-assertion-type:jwt-bearer')
          end

          context 'client assertion' do
            it 'has correct claims' do
              jwt = subject.options.token_params[:client_assertion]
              decoded_jwt = JWT.decode(jwt, nil, false).first

              expect(decoded_jwt['aud']).to eql('https://login.microsoftonline.com/tenant/oauth2/v2.0/token')
              expect(decoded_jwt['exp']).to be_within(5).of(Time.now.to_i + 300)
              expect(decoded_jwt['iss']).to eql('id')
              expect(decoded_jwt['jti']).to eql('unique-jti')
              expect(decoded_jwt['nbf']).to be_within(5).of(Time.now.to_i)
              expect(decoded_jwt['sub']).to eql('id')
            end

            it 'contains x5c and x5t headers' do
              jwt = subject.options.token_params[:client_assertion]
              headers = JWT.decode(jwt, nil, false).last

              expect(headers['x5c']).to be_an_instance_of(Array)
              expect(headers['x5t']).to be_a(String)
            end
          end # "context 'client assertion' do"
        end # "context '#token_params with correctly formatted request' do"
      end # "context 'using client assertion flow' do"

      describe "overrides" do
        it 'should override domain_hint' do
          @options = {domain_hint: 'hint'}
          allow(subject).to receive(:request) { request }
          subject.client
          expect(subject.authorize_params[:domain_hint]).to eql('hint')
        end

        it 'overrides prompt via query parameter' do
          @options = { authorize_params: {prompt: 'select_account'} }
          override_request = double('Request', :params => {'prompt'.to_s => 'consent'}, :cookies => {}, :env => {})
          allow(subject).to receive(:request) { override_request }
          subject.client
          expect(subject.authorize_params[:prompt]).to eql('consent')
        end
      end # "describe "overrides" do"
    end # "describe '#client' do"
  end # "describe 'static configuration' do"

  describe 'static configuration - german' do
    let(:options) { @options || {} }
    subject do
      OmniAuth::Strategies::EntraId.new(app, {client_id: 'id', client_secret: 'secret', tenant_id: 'tenant', base_url: 'https://login.microsoftonline.de'}.merge(options))
    end

    describe '#client' do
      it 'has correct authorize url' do
        allow(subject).to receive(:request) { request }
        expect(subject.client.options[:authorize_url]).to eql('https://login.microsoftonline.de/tenant/oauth2/v2.0/authorize')
      end

      it 'has correct authorize params' do
        allow(subject).to receive(:request) { request }
        subject.client
        expect(subject.authorize_params[:domain_hint]).to be_nil
      end

      it 'has correct token url' do
        allow(subject).to receive(:request) { request }
        expect(subject.client.options[:token_url]).to eql('https://login.microsoftonline.de/tenant/oauth2/v2.0/token')
      end

      it 'has correct authorize_params' do
        allow(subject).to receive(:request) { request }
        subject.client
        expect(subject.authorize_params[:scope]).to eql('openid profile email')
      end

      context 'when a custom policy and tenant name are present' do
        it 'generates the B2C URL (which does not include locale)' do
          @options = { custom_policy: 'my_policy', tenant_name: 'my_tenant' }
          allow(subject).to receive(:request) { request }
          expect(subject.client.options[:token_url]).to eql('https://my_tenant.b2clogin.com/my_tenant.onmicrosoft.com/my_policy/oauth2/v2.0/token')
        end
      end # "context 'when a custom policy and tenant name are present' do"

      describe "overrides" do
        it 'should override domain_hint' do
          @options = {domain_hint: 'hint'}
          allow(subject).to receive(:request) { request }
          subject.client
          expect(subject.authorize_params[:domain_hint]).to eql('hint')
        end
      end # "describe "overrides" do"
    end # "describe '#client' do"
  end # "describe 'static configuration - german' do"

  describe 'static common configuration' do
    let(:options) { @options || {} }
    subject do
      OmniAuth::Strategies::EntraId.new(app, {client_id: 'id', client_secret: 'secret'}.merge(options))
    end

    before do
      allow(subject).to receive(:request) { request }
    end

    describe '#client' do
      it 'has correct authorize url' do
        expect(subject.client.options[:authorize_url]).to eql('https://login.microsoftonline.com/common/oauth2/v2.0/authorize')
      end

      it 'has correct token url' do
        expect(subject.client.options[:token_url]).to eql('https://login.microsoftonline.com/common/oauth2/v2.0/token')
      end
    end # "describe '#client' do"
  end # "describe 'static common configuration' do"

  describe 'static configuration with on premise AD FS' do
    let(:options) { @options || {} }

    subject do
      OmniAuth::Strategies::EntraId.new(
        app,
        {
          client_id:     'id',
          client_secret: 'secret',
          tenant_id:     'adfs',
          base_url:      'https://login.contoso.com'
        }.merge(options) # 'adfs' or 'adfs?' is set here, by defining @options
      )
    end

    shared_examples 'an integration aware of AD FS' do
      describe 'wherein #client' do
        it 'has correct authorize url' do
          allow(subject).to receive(:request) { request }
          expect(subject.client.options[:authorize_url]).to eql('https://login.contoso.com/adfs/oauth2/authorize')
        end

        it 'has correct token url' do
          allow(subject).to receive(:request) { request }
          expect(subject.client.options[:token_url]).to eql('https://login.contoso.com/adfs/oauth2/token')
        end
      end # "describe 'wherein #client' do"
    end # "shared_examples 'an integration aware of AD FS wherein' do"

    context ':adfs option variant' do
      before :each do
        @options = { adfs: true }
      end

      it_behaves_like 'an integration aware of AD FS'
    end # "context ':adfs option variant' do"

    context ':adfs? option variant' do
      before :each do
        @options = { adfs?: true }
      end

      it_behaves_like 'an integration aware of AD FS'
    end # "context ':adfs? option variant' do"
  end # "describe 'static configuration with on premise AD FS' do"

  describe 'dynamic configuration' do
    let(:provider_klass) {
      Class.new {
        def initialize(strategy)
        end

        def client_id
          'id'
        end

        def client_secret
          'secret'
        end

        def tenant_id
          'tenant'
        end

        def authorize_params
          { custom_option: 'value' }
        end
      }
    }

    subject do
      OmniAuth::Strategies::EntraId.new(app, provider_klass)
    end

    before do
      allow(subject).to receive(:request) { request }
    end

    describe '#client' do
      it 'has correct authorize url' do
        expect(subject.client.options[:authorize_url]).to eql('https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize')
      end

      it 'has correct authorize params' do
        subject.client
        expect(subject.authorize_params[:domain_hint]).to be_nil
        expect(subject.authorize_params[:custom_option]).to eql('value')
      end

      it 'has correct token url' do
        expect(subject.client.options[:token_url]).to eql('https://login.microsoftonline.com/tenant/oauth2/v2.0/token')
      end

      it 'has correct authorize_params' do
        subject.client
        expect(subject.authorize_params[:scope]).to eql('openid profile email')
      end

      # todo: how to get this working?
      # describe "overrides" do
      #   it 'should override domain_hint' do
      #     provider_klass.domain_hint = 'hint'
      #     subject.client
      #     expect(subject.authorize_params[:domain_hint]).to eql('hint')
      #   end
      # end
    end # "describe '#client' do"
  end # "describe 'dynamic configuration' do"

  describe 'dynamic configuration - german' do
    let(:provider_klass) {
      Class.new {
        def initialize(strategy)
        end

        def client_id
          'id'
        end

        def client_secret
          'secret'
        end

        def tenant_id
          'tenant'
        end

        def base_url
          'https://login.microsoftonline.de'
        end

        def scope
          'Calendars.ReadWrite email offline_access User.Read'
        end
      }
    }

    subject do
      OmniAuth::Strategies::EntraId.new(app, provider_klass)
    end

    before do
      allow(subject).to receive(:request) { request }
    end

    describe '#client' do
      it 'has correct authorize url' do
        expect(subject.client.options[:authorize_url]).to eql('https://login.microsoftonline.de/tenant/oauth2/v2.0/authorize')
      end

      it 'has correct authorize params' do
        subject.client
        expect(subject.authorize_params[:domain_hint]).to be_nil
      end

      it 'has correct token url' do
        expect(subject.client.options[:token_url]).to eql('https://login.microsoftonline.de/tenant/oauth2/v2.0/token')
      end

      it 'has correct scope' do
        subject.client
        expect(subject.authorize_params[:scope]).to eql('Calendars.ReadWrite email offline_access User.Read')
      end

      # todo: how to get this working?
      # describe "overrides" do
      #   it 'should override domain_hint' do
      #     provider_klass.domain_hint = 'hint'
      #     subject.client
      #     expect(subject.authorize_params[:domain_hint]).to eql('hint')
      #   end
      # end
    end # "describe '#client' do"
  end # "describe 'dynamic configuration - german' do"

  describe 'dynamic common configuration' do
    let(:provider_klass) {
      Class.new {
        def initialize(strategy)
        end

        def client_id
          'id'
        end

        def client_secret
          'secret'
        end
      }
    }

    subject do
      OmniAuth::Strategies::EntraId.new(app, provider_klass)
    end

    before do
      allow(subject).to receive(:request) { request }
    end

    describe '#client' do
      it 'has correct authorize url' do
        expect(subject.client.options[:authorize_url]).to eql('https://login.microsoftonline.com/common/oauth2/v2.0/authorize')
      end

      it 'has correct token url' do
        expect(subject.client.options[:token_url]).to eql('https://login.microsoftonline.com/common/oauth2/v2.0/token')
      end

      it 'has correct scope from request params' do
        request.params['scope'] = 'openid email offline_access Calendars.Read'
        subject.client
        expect(subject.authorize_params[:scope]).to eql('openid email offline_access Calendars.Read')
      end
    end # "describe '#client' do"
  end # "describe 'dynamic common configuration' do"

  describe 'dynamic configuration with on premise AD FS' do
    let(:provider_klass) {
      Class.new {
        def initialize(strategy)
        end

        def client_id
          'id'
        end

        def client_secret
          'secret'
        end

        def tenant_id
          'adfs'
        end

        def base_url
          'https://login.contoso.com'
        end

        def adfs?
          true
        end
      }
    }

    subject do
      OmniAuth::Strategies::EntraId.new(app, provider_klass)
    end

    before do
      allow(subject).to receive(:request) { request }
    end

    describe '#client' do
      it 'has correct authorize url' do
        expect(subject.client.options[:authorize_url]).to eql('https://login.contoso.com/adfs/oauth2/authorize')
      end

      it 'has correct token url' do
        expect(subject.client.options[:token_url]).to eql('https://login.contoso.com/adfs/oauth2/token')
      end
    end # "describe '#client' do"
  end # "describe 'dynamic configuration with on premise AD FS' do"

  describe 'raw_info and validation' do
    let(:issued_at ) {  Time.now.utc.to_i         }
    let(:expires_at) { (Time.now.utc + 3600).to_i }
    let(:id_token_info) do
      {
        ver:                '2.0',
        iss:                'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0',
        sub:                'sdfkjllAkdkWkeiidkcXKfjjsl',
        aud:                'id',
        exp:                expires_at(),
        iat:                issued_at(),
        nbf:                issued_at(),
        name:               'Bob Doe',
        preferred_username: 'bob@doe.com',
        oid:                'my_id',
        email:              'bob@doe.com',
        tid:                '9188040d-6c67-4c5b-b112-36a304b66dad',
        aio:                'KSslldiwDkfjjsoeiruosKD',
        unique_name:        'bobby'
      }
    end

    let(:id_token) do
      JWT.encode(id_token_info, 'secret')
    end

    let(:access_token) do
      double(:token => SecureRandom.uuid, :params => {'id_token' => id_token})
    end

    # Override or add construction options entries by setting @options in a
    # "before :context" hook - that is BEFORE CONTEXT, since that runs before
    # the "before :each" hooks a few lines below here which cause 'subject' to
    # be evaluated. Ignored if @provider_klass is set (see below).
    #
    let(:options) do
      @options || {}
    end

    # Override options hash with provider class by setting @provider_klass in a
    # "before :context" hook - that is BEFORE CONTEXT, since that runs before
    # the "before :each" hooks a few lines below here which cause 'subject' to
    # be evaluated. If set, @options is ignored (see above).
    #
    let(:provider_klass) do
      @provider_klass || nil
    end

    subject do
      if provider_klass.nil?
        OmniAuth::Strategies::EntraId.new(
          app,
          { client_id: 'id', client_secret: 'secret' }.merge(options)
        )
      else
        OmniAuth::Strategies::EntraId.new(
          app,
          provider_klass
        )
      end
    end

    before :each do
      allow(subject).to receive(:access_token) { access_token }
      allow(subject).to receive(:request)      { request      }
    end

    context 'with information only in the ID token' do
      it 'returns correct info' do
        expect(subject.info).to eq({
                                     name:      'Bob Doe',
                                     email:     'bob@doe.com',
                                     nickname:  'bobby',
                                     first_name: nil,
                                     last_name:  nil
                                   })
      end

      it 'returns correct "uid"' do
        expect(subject.uid).to eq('9188040d-6c67-4c5b-b112-36a304b66dadmy_id')
      end

      it 'returns correct "oid" for V2 or earlier lazy migrations' do
        expect(subject.raw_info['oid']).to eq('my_id')
      end
    end # "context 'with information only in the ID token' do"

    context 'with a TID which is' do
      context 'missing' do
        let(:id_token_info) do
          info = super()
          info.delete(:tid)
          info
        end

        it 'returns a UID comprising of the OID only' do
          expect(subject.uid).to eq('my_id')
        end
      end # "context'"missing' do"

      context 'blank' do
        let(:id_token_info) do
          info = super()
          info[:tid] = ''
          info
        end

        it 'returns a UID comprising of the OID only' do
          expect(subject.uid).to eq('my_id')
        end
      end # "context 'blank' do"
    end # "context 'with a TID which is' do"

    context 'when configured to ignore the TID' do
      context 'using the :ignore_tid option variant' do
        before :context do
          @options = { ignore_tid: true }
        end

        it 'returns a UID comprising of the OID only' do
          expect(subject.uid).to eq('my_id')
        end
      end # "context 'using the :ignore_tid option variant' do"

      context 'using the :ignore_tid? option variant' do
        before :context do
          @options = { ignore_tid?: true }
        end

        it 'returns a UID comprising of the OID only' do
          expect(subject.uid).to eq('my_id')
        end
      end # "context 'using the :ignore_tid? option variant' do"

      context 'using a custom provider class' do
        before :context do
          @provider_klass = Class.new {
            def initialize(strategy)
            end

            def client_id
              'id'
            end

            def client_secret
              'secret'
            end

            def ignore_tid?
              true
            end
          }
        end

        it 'returns a UID comprising of the OID only' do
          subject.client
          expect(subject.uid).to eq('my_id')
        end
      end # "context 'using a custom provider class' do"
    end # "context 'when configured to ignore the TID' do"

    context 'with extra information in the auth token' do
      let(:auth_token_info) do
        {
          ver:                '2.0',
          iss:                'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0',
          sub:                'sdfkjllAkdkWkeiidkcXKfjjsl',
          aud:                'id',
          exp:                expires_at(),
          iat:                issued_at(),
          nbf:                issued_at(),
          preferred_username: 'bob@doe.com',
          oid:                'overridden_id', # (overrides ID token)
          email:              'bob@doe.com',
          tid:                '9188040d-6c67-4c5b-b112-36a304b66dad',
          aio:                'KSslldiwDkfjjsoeiruosKD',
          unique_name:        'Bobby Definitely Doe', # (overrides ID token)
          given_name:         'Bob',
          family_name:        'Doe'
        }
      end

      let(:auth_token) do
        JWT.encode(auth_token_info, 'secret')
      end

      let(:access_token) do
        double(:token => auth_token, :params => {'id_token' => id_token})
      end

      it 'returns correct info' do
        expect(subject.info).to eq(
          {
            name:       'Bob Doe',
            email:      'bob@doe.com',
            nickname:   'Bobby Definitely Doe',
            first_name: 'Bob',
            last_name:  'Doe'
          }
        )
      end

      it 'returns correct "uid"' do
        expect(subject.uid).to eq('9188040d-6c67-4c5b-b112-36a304b66dadoverridden_id')
      end

      it 'returns correct "oid" for V2 or earlier lazy migrations' do
        expect(subject.raw_info['oid']).to eq('overridden_id')
      end
    end # "context 'with extra information in the auth token' do"

    context 'with an invalid audience' do
      let(:id_token_info) do
        {
          ver:                '2.0',
          iss:                'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0',
          sub:                'sdfkjllAkdkWkeiidkcXKfjjsl',
          aud:                'other-id',
          exp:                expires_at(),
          iat:                issued_at(),
          nbf:                issued_at(),
          name:               'Bob Doe',
          preferred_username: 'bob@doe.com',
          oid:                'my_id',
          email:              'bob@doe.com',
          tid:                '9188040d-6c67-4c5b-b112-36a304b66dad',
          aio:                'KSslldiwDkfjjsoeiruosKD',
          unique_name:        'bobby'
        }
      end

      it 'fails validation' do
        expect { subject.info }.to raise_error(JWT::InvalidAudError)
      end
    end # "context 'with an invalid audience' do"

    context 'issuers' do
      context 'when valid' do
        subject do
          OmniAuth::Strategies::EntraId.new(app, {client_id: 'id', client_secret: 'secret', tenant_id: '9188040d-6c67-4c5b-b112-36a304b66dad'})
        end

        it 'passes validation' do
          expect { subject.info }.to_not raise_error()
        end
      end # "context 'when valid' do"

      context 'when invalid' do
        subject do
          OmniAuth::Strategies::EntraId.new(app, {client_id: 'id', client_secret: 'secret', tenant_id: 'a-mismatched-tenant-id'})
        end

        it 'fails validation' do
          expect { subject.info }.to raise_error(JWT::InvalidIssuerError)
        end
      end # "context 'when invalid' do"

      context 'multi-tenant, AD FS' do
        let(:id_token_info) do
          hash = super()
          hash['iss'] = 'invalid issuer that should be ignored'
          hash
        end

        context 'no tenant specified' do
          subject do
            OmniAuth::Strategies::EntraId.new(app, {client_id: 'id', client_secret: 'secret', tenant_id: nil})
          end

          it 'skips issuer validation since tenant ID is unknown' do
            expect { subject.info }.to_not raise_error()
          end
        end # "context 'no tenant specified' do"

        context '"common" tenant specified' do
          subject do
            OmniAuth::Strategies::EntraId.new(app, {client_id: 'id', client_secret: 'secret', tenant_id: OmniAuth::Strategies::EntraId::COMMON_TENANT_ID})
          end

          it 'skips issuer validation since tenant ID is unknown' do
            expect { subject.info }.to_not raise_error()
          end
        end # "context '"common" tenant specified' do"

        context '"adfs" tenant specified' do
          subject do
            OmniAuth::Strategies::EntraId.new(app, {client_id: 'id', client_secret: 'secret', tenant_id: OmniAuth::Strategies::EntraId::AD_FS_TENANT_ID})
          end

          it 'skips issuer validation since tenant ID is unknown' do
            expect { subject.info }.to_not raise_error()
          end
        end # "context '"common" tenant specified' do"

        context '"consumers" tenant specified' do
          subject do
            OmniAuth::Strategies::EntraId.new(app, {client_id: 'id', client_secret: 'secret', tenant_id: OmniAuth::Strategies::EntraId::CONSUMERS_TENANT_ID})
          end

          it 'raises an error as the issuer *is* checked' do
            expect { subject.info }.to raise_error(JWT::InvalidIssuerError)
          end

          context 'with the "magic" tenant ID' do
            let(:id_token_info) do
              hash = super()
              hash['iss'] = 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0'
              hash
            end

            it 'raises no error' do
              expect { subject.info }.to_not raise_error()
            end
          end # "context 'with the "magic" tenant ID' do"
        end # "context '"consumers" tenant specified' do"
      end # "context 'multi-tenant, AD FS' do"
    end # "context 'issuers' do"

    context 'with an invalid not_before' do
      let(:issued_at) { (Time.now.utc + 70).to_i } # Invalid because leeway is 60 seconds

      let(:id_token_info) do
        {
          ver:                '2.0',
          iss:                'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0',
          sub:                'sdfkjllAkdkWkeiidkcXKfjjsl',
          aud:                'id',
          exp:                expires_at(),
          iat:                issued_at(),
          nbf:                issued_at(),
          name:               'Bob Doe',
          preferred_username: 'bob@doe.com',
          oid:                'my_id',
          email:              'bob@doe.com',
          tid:                '9188040d-6c67-4c5b-b112-36a304b66dad',
          aio:                'KSslldiwDkfjjsoeiruosKD',
          unique_name:        'bobby'
        }
      end

      it 'fails validation' do
        expect { subject.info }.to raise_error(JWT::ImmatureSignature)
      end
    end # "context 'with an invalid not_before' do"

    context 'with an expired token' do
      let(:issued_at ) { (Time.now.utc - 3600).to_i }
      let(:expires_at) { (Time.now.utc - 70  ).to_i } # Invalid because leeway is 60 seconds

      let(:id_token_info) do
        {
          ver:                '2.0',
          iss:                'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0',
          sub:                'sdfkjllAkdkWkeiidkcXKfjjsl',
          aud:                'id',
          exp:                expires_at(),
          iat:                issued_at(),
          nbf:                issued_at(),
          name:               'Bob Doe',
          preferred_username: 'bob@doe.com',
          oid:                'my_id',
          email:              'bob@doe.com',
          tid:                '9188040d-6c67-4c5b-b112-36a304b66dad',
          aio:                'KSslldiwDkfjjsoeiruosKD',
          unique_name:        'bobby'
        }
      end

      it 'fails validation' do
        expect { subject.info }.to raise_error(JWT::ExpiredSignature)
      end
    end # "context 'with an expired token' do"
  end # "describe 'raw_info and validation' do"

  describe 'callback_url' do
    subject do
      OmniAuth::Strategies::EntraId.new(app, { client_id: 'id', client_secret: 'secret', tenant_id: 'tenant' })
    end

    let(:base_url) { 'https://example.com' }

    it 'has the correct default callback path' do
      allow(subject).to receive(:full_host) { base_url }
      allow(subject).to receive(:script_name) { '' }
      expect(subject.callback_url).to eq(base_url + '/auth/entra_id/callback')
    end

    it 'should set the callback path with script_name if present' do
      allow(subject).to receive(:full_host) { base_url }
      allow(subject).to receive(:script_name) { '/v1' }
      expect(subject.callback_url).to eq(base_url + '/v1/auth/entra_id/callback')
    end
  end
end
