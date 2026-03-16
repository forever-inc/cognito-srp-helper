# frozen_string_literal: true

require "base64"
require "openssl"
require "securerandom"

module CognitoSrpHelper
  class SignSrpSessionError < StandardError; end
  class MissingChallengeResponsesError < SignSrpSessionError; end
  class MissingSaltError < SignSrpSessionError; end
  class MissingSecretError < SignSrpSessionError; end
  class MissingLargeBError < SignSrpSessionError; end
  class MissingUserIdForSrpError < SignSrpSessionError; end
  class MissingDeviceKeyError < SignSrpSessionError; end

  class AbortOnZeroSrpError < StandardError; end
  class AbortOnZeroASrpError < AbortOnZeroSrpError; end
  class AbortOnZeroBSrpError < AbortOnZeroSrpError; end
  class AbortOnZeroUSrpError < AbortOnZeroSrpError; end

  INFO_BITS = "Caldera Derived Key".b
  G = 2
  N = Integer(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" \
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" \
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" \
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" \
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" \
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" \
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" \
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" \
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
    16
  )

  module_function

  def k
    @k ||= Integer(hex_hash("#{pad_hex(N)}#{pad_hex(G)}"), 16)
  end

  def hash(buf)
    OpenSSL::Digest::SHA256.hexdigest(buf)
  end

  def hex_hash(hex_str)
    hash(get_bytes_from_hex(hex_str))
  end

  def pad_hex(big_int)
    raise ArgumentError, "Not an Integer" unless big_int.is_a?(Integer)

    is_negative = big_int.negative?
    hex_str = big_int.abs.to_s(16)
    hex_str = "0#{hex_str}" if hex_str.length.odd?
    hex_str = "00#{hex_str}" if hex_str.match?(/\A[89a-f]/i)

    if is_negative
      inverted_nibbles = hex_str.each_char.map do |char|
        inverted_nibble = (~Integer(char, 16)) & 0xF
        "0123456789ABCDEF"[inverted_nibble]
      end.join

      hex_str = (Integer(inverted_nibbles, 16) + 1).to_s(16)
      hex_str = hex_str[2..] if hex_str.upcase.start_with?("FF8")
    end

    hex_str
  end

  def random_bytes(n_bytes)
    SecureRandom.random_bytes(n_bytes)
  end

  def get_bytes_from_hex(encoded)
    raise ArgumentError, "Hex encoded strings must have an even number length" if encoded.length.odd?
    raise ArgumentError, "Cannot decode unrecognized hex sequence" unless encoded.match?(/\A[0-9a-fA-F]*\z/)

    [encoded].pack("H*")
  end

  def create_secret_hash(user_id, client_id, secret_id)
    Base64.strict_encode64(OpenSSL::HMAC.digest("sha256", secret_id, "#{user_id}#{client_id}"))
  end

  def create_password_hash(user_id, password, pool_id)
    pool_id_abbr = pool_id.split("_", 2).last
    hash("#{pool_id_abbr}#{user_id}:#{password}")
  end

  def create_device_verifier(device_key, device_group_key)
    password_random = Base64.strict_encode64(random_bytes(40))
    device_hash = create_device_hash(device_key, password_random, device_group_key)

    salt = random_bytes(16).unpack1("H*")
    salt_hash = pad_hex(Integer(salt, 16))
    salt_base64 = Base64.strict_encode64(get_bytes_from_hex(salt_hash))

    password_salted = hex_hash("#{salt_hash}#{device_hash}")
    password_verifier = mod_pow(G, Integer(password_salted, 16), N)
    password_verifier_base64 = Base64.strict_encode64(get_bytes_from_hex(pad_hex(password_verifier)))

    {
      device_random_password: password_random,
      device_secret_verifier_config: {
        password_verifier: password_verifier_base64,
        salt: salt_base64
      }
    }
  end

  def create_srp_session(username, password, pool_id, is_hashed = true)
    pool_id_abbr = pool_id.split("_", 2).last
    timestamp = create_timestamp
    small_a = generate_small_a
    large_a = calculate_large_a(small_a)

    {
      username: username,
      password: password,
      is_hashed: is_hashed,
      pool_id: pool_id,
      pool_id_abbr: pool_id_abbr,
      timestamp: timestamp,
      small_a: small_a.to_s(16),
      large_a: large_a.to_s(16)
    }
  end

  def sign_srp_session(session, response)
    challenge = read_key(response, :ChallengeParameters)
    raise MissingChallengeResponsesError, "Missing ChallengeParameters" unless challenge

    salt = read_key(challenge, :SALT)
    secret = read_key(challenge, :SECRET_BLOCK)
    large_b = read_key(challenge, :SRP_B)
    user_id_for_srp = read_key(challenge, :USER_ID_FOR_SRP)

    raise MissingSaltError, "Missing SALT in ChallengeParameters" unless salt
    raise MissingSecretError, "Missing SECRET_BLOCK in ChallengeParameters" unless secret
    raise MissingLargeBError, "Missing SRP_B in ChallengeParameters" unless large_b
    raise MissingUserIdForSrpError, "Missing USER_ID_FOR_SRP in ChallengeParameters" unless user_id_for_srp

    sign_common_session(
      session,
      salt: salt,
      secret: secret,
      large_b: large_b,
      hash_seed: session_password_hash(session, user_id_for_srp),
      key_prefix: session_value(session, :pool_id_abbr),
      key_user: user_id_for_srp
    )
  end

  def sign_srp_session_with_device(session, response, device_group_key, device_random_password)
    challenge = read_key(response, :ChallengeParameters)
    raise MissingChallengeResponsesError, "Missing ChallengeParameters" unless challenge

    salt = read_key(challenge, :SALT)
    secret = read_key(challenge, :SECRET_BLOCK)
    large_b = read_key(challenge, :SRP_B)
    device_key = read_key(challenge, :DEVICE_KEY)

    raise MissingSaltError, "Missing SALT in ChallengeParameters" unless salt
    raise MissingSecretError, "Missing SECRET_BLOCK in ChallengeParameters" unless secret
    raise MissingLargeBError, "Missing SRP_B in ChallengeParameters" unless large_b
    raise MissingDeviceKeyError, "Missing DEVICE_KEY in ChallengeParameters" unless device_key

    sign_common_session(
      session,
      salt: salt,
      secret: secret,
      large_b: large_b,
      hash_seed: create_device_hash(device_key, device_random_password, device_group_key),
      key_prefix: device_group_key,
      key_user: device_key
    )
  end

  def wrap_initiate_auth(session, request)
    wrapped = request.dup
    auth_parameters = (read_key(wrapped, :AuthParameters) || {}).dup
    auth_parameters[write_key(auth_parameters, :SRP_A)] = session_value(session, :large_a)
    wrapped[write_key(wrapped, :AuthParameters)] = auth_parameters
    wrapped
  end

  def wrap_auth_challenge(session, request)
    wrapped = request.dup
    challenge_responses = (read_key(wrapped, :ChallengeResponses) || {}).dup
    challenge_responses[write_key(challenge_responses, :PASSWORD_CLAIM_SECRET_BLOCK)] = session_value(session, :secret)
    challenge_responses[write_key(challenge_responses, :PASSWORD_CLAIM_SIGNATURE)] = session_value(session, :password_signature)
    challenge_responses[write_key(challenge_responses, :SRP_A)] = session_value(session, :large_a)
    challenge_responses[write_key(challenge_responses, :TIMESTAMP)] = session_value(session, :timestamp)
    wrapped[write_key(wrapped, :ChallengeResponses)] = challenge_responses
    wrapped
  end

  class << self
    alias createSecretHash create_secret_hash
    alias createPasswordHash create_password_hash
    alias createDeviceVerifier create_device_verifier
    alias createSrpSession create_srp_session
    alias signSrpSession sign_srp_session
    alias signSrpSessionWithDevice sign_srp_session_with_device
    alias wrapInitiateAuth wrap_initiate_auth
    alias wrapAuthChallenge wrap_auth_challenge
  end

  def generate_small_a
    Integer(random_bytes(128).unpack1("H*"), 16)
  end

  def calculate_large_a(small_a)
    large_a = mod_pow(G, small_a, N)
    raise AbortOnZeroASrpError, "Aborting SRP due to 0 value received for client public key (A)" if large_a.zero?

    large_a
  end

  def compute_hkdf(ikm, salt)
    prk = OpenSSL::HMAC.digest("sha256", salt, ikm)
    OpenSSL::HMAC.digest("sha256", prk, INFO_BITS + "\x01").byteslice(0, 16)
  end

  def calculate_u(large_a, large_b)
    u = Integer(hex_hash("#{pad_hex(large_a)}#{pad_hex(large_b)}"), 16)
    raise AbortOnZeroUSrpError, "Aborting SRP due to 0 value received for public key hash (u)" if u.zero?

    u
  end

  def calculate_s(x, large_b, small_a, u)
    g_to_x_mod_n = mod_pow(G, x, N)
    adjusted_large_b = large_b - (k * g_to_x_mod_n)
    mod_pow(adjusted_large_b, small_a + (u * x), N)
  end

  def calculate_x(salt, username_password_hash)
    Integer(hex_hash("#{pad_hex(salt)}#{username_password_hash}"), 16)
  end

  def create_timestamp
    Time.now.utc.strftime("%a %b %-d %H:%M:%S UTC %Y")
  end

  def create_device_hash(device_key, password, device_group_key)
    hash("#{device_group_key}#{device_key}:#{password}")
  end

  def mod_pow(base, exponent, modulus)
    base.pow(exponent, modulus)
  end

  def read_key(hash, key)
    return nil unless hash.respond_to?(:[])

    return hash[key] if hash.respond_to?(:key?) && hash.key?(key)

    key_str = key.to_s
    return hash[key_str] if hash.respond_to?(:key?) && hash.key?(key_str)

    key_sym = key_str.to_sym
    return hash[key_sym] if hash.respond_to?(:key?) && hash.key?(key_sym)

    hash[key] || hash[key_str] || hash[key_sym]
  end

  def write_key(hash, key)
    return key unless hash.respond_to?(:keys)

    return key if hash.keys.any? { |k| k == key }

    key_str = key.to_s
    return key_str if hash.keys.any? { |k| k == key_str }

    key_sym = key_str.to_sym
    return key_sym if hash.keys.any? { |k| k == key_sym }

    hash.keys.any? { |k| k.is_a?(Symbol) } ? key_sym : key_str
  end

  def session_value(session, key)
    read_key(session, key) || read_key(session, key.to_s.gsub(/_([a-z])/) { Regexp.last_match(1).upcase })
  end

  def session_password_hash(session, user_id_for_srp)
    is_hashed = session_value(session, :is_hashed)
    password = session_value(session, :password)

    return password if is_hashed

    create_password_hash(user_id_for_srp, password, session_value(session, :pool_id))
  end

  def sign_common_session(session, salt:, secret:, large_b:, hash_seed:, key_prefix:, key_user:)
    raise AbortOnZeroBSrpError, "Aborting SRP due to 0 value received for server public key (B)" if large_b.gsub(/^0+/, "").empty?

    u = calculate_u(Integer(session_value(session, :large_a), 16), Integer(large_b, 16))
    x = calculate_x(Integer(salt, 16), hash_seed)
    s = calculate_s(x, Integer(large_b, 16), Integer(session_value(session, :small_a), 16), u)
    hkdf = compute_hkdf(get_bytes_from_hex(pad_hex(s)), get_bytes_from_hex(pad_hex(u)))

    message = String.new(encoding: Encoding::BINARY)
    message << key_prefix.to_s
    message << key_user.to_s
    message << Base64.decode64(secret)
    message << session_value(session, :timestamp).to_s

    password_signature = Base64.strict_encode64(OpenSSL::HMAC.digest("sha256", hkdf, message))

    session.merge(
      salt: salt,
      secret: secret,
      large_b: large_b,
      password_signature: password_signature
    )
  end

  private_class_method :generate_small_a, :calculate_large_a, :compute_hkdf, :calculate_u, :calculate_s, :calculate_x,
                       :create_device_hash, :mod_pow, :read_key, :write_key, :session_value, :session_password_hash,
                       :sign_common_session
end
