# frozen_string_literal: true

require "minitest/autorun"
require_relative "../lib/cognito_srp_helper"

class CognitoSrpHelperTest < Minitest::Test
  SESSION = {
    username: "john.doe",
    password: "cd9896b264dc8dca270b0b74b039cf775ea70afb06bd253f5e0ffe7197224aa3",
    is_hashed: true,
    pool_id: "eu-west-2_eYpv1mFHB",
    pool_id_abbr: "eYpv1mFHB",
    timestamp: "Tue Feb 1 03:04:05 UTC 2000",
    small_a: "abcdef0123456789",
    large_a: "362be8c4c29e414549c30c6679ddbb556c27717d80c8feec68257bf5edcd855fbd23590841c1f792dd24a09243c00d4fbb8cc8047fbe1c95da7b467d29269d2db462c6268f10ef5a3c23f71865a54bae6e48523e6a7a9b65d115c66a2f5b4ec5b7384c9796dc6b2d422ea630e1821104ab05cb4a4f292f991d771be4fdba39bc6ff8dce0f0addaaaf172d908d08544d573a2222f1e198caf65f5e6445848ed23b5bbfff0b5bc00ca54b2831a200577220cfe4f5de20b66baffbfc8d3a16af6f6a7a590e0764ccdf918daf922df1ed0a695702c9bd63a69b09b4c2fb8a3bffee5f89744639607e1920ee006d81f09cba7682e75be5b407fb5cb1f706c0dbf7a9325b5c56ea53333ba1aecab647beae4b2b44c0912814609560fda8d86e6aff0b2317e339d2d3b422069d8e68fca8a39c43acb360d4285bb2dd076bb58b41e07be255f349537adaae3bf5260b2c7e066fb77904ebcee5005cc367f926482f9b405952f50e1182049ac49847a048fca4fbe13c6538eea38132c9bc43c9b05690bb7"
  }.freeze

  RESPONSE = {
    "ChallengeParameters" => {
      "SRP_B" => "bc071b539bfaa44b26a4f4a917dcc4b90291f3fea737baa555c0dfc792f11849902859dd52976fd7367130d91969670e8a0beb66d044641709d7a9ea609e2cc5baac6837e1ee8f8d9ccdce535be1dee59d4c893d9c9a1f06ddacb9d927e29c0e8bb1b8dda315f297e82c6095570ae3ab28a9110dfc4367296d77898b1d69d029f76e16ffebed59fc568548a9fb54a1a462440b19b4e4d89ae414374654788d599d0635f9b8a7a5c6a8556e675c4e01690d5324eecd092d269b2be31fa2dc7192cb0bec8a390ca4ce791c8e8cc9ed7258929430a2802a2b9dadd985a004d584e883621ff3518e223a6dbab5071bc844e4ee7d12f6c29bd9197f0fefcee91020b0903596cf170efd27648eb5de5ab2961032cf759dbc48dadb6db0dd585bb9c1e9f73bbea67a7ca406e26d4333c63d5339fa8c0f51fc12df554737da39fc780c0a648e884600f1bf9398cedddaee7d6db6ace4e0007d97f7322d7270dc25c6e6ae000e54b62f8cb868b16e16eadb4c8c87f3baae1c1b8e59aabb73771e62c0b898",
      "SALT" => "baf4431cdaa37c04c0d655a99f5e9b9b",
      "SECRET_BLOCK" => "gn7F/ENIPPk/KZ7P2xYr4S0pZhCn29Y0nxXBtEPEc8Tt2cqbQpWorIuwSAC0g3fpDW9djD5+b9v30TctMTiVt6xjGaZeuWzzgAnVrc0l0xROzJItEQM1V96ySkrfFbL4tKuZokrqiszsRkgwnu4SGBz3akVpUD8pZnAg1Ycfc3LLSyQETFTndRHjS8UFGIovw7wqQfxKNKDC1nY2XYWR1nFuEIvHXb+Tvc76IxNZcaEvl5sAuTjwpVlmfwPSOELXnYxvDxUcFYO3sNguNqahn6aH4j16ccEZ/Wqoubn7QkomXV3Qdo5khQbw4F9CWFaxCHoRZwFAc8RQ4oGiIHLvuMb/Y/JhGTL3HefSkBXQ+uvoPK7YdgY8yn3SejYv4xD8lw+KLTPy1EbCXX9Aq1uwgjzeSygLl7/tkf1C/YzhefXEOfaLk2eNRlAschYunQ7WeIZWBYzW+38+r4bQpaecj8GcH/ycAOpacfoLB+/q3E/dHsFOFlzetYO6Qll5AXEv4hzJZgNh1/2zK3N8j2JBUjZs2h60Rh8OS+ZcQGa7ICPfS7XDvSV8U6Xan3j2m0Azz2ara+1I4MYDVj5P4/BneVDh4L+6Dl3EWEAF9UO8Ur1/5seiOVcAQe3TlwN9UWgmOZHIq/UGU14ofpmZI46WWS3qB+yBPHbWWJ0MMFFtRwCTzFl+2kRGthRR5A+6MSuLCfdcQwqb6FYRZEdgXZzMa6Td0Pog/5TFqxygkRB0P3Yq4lfOnRKI6cC3+2g8uMsEmOJfzsVrsfi6GTAPrP+lIPpNe12ZquFzPGi9Z68Odj+aNDYChalBpuvJgxWR2EFuyj2MebKz6Zo/5V/w964aTTYjUt1pPHURLx3MKl7Ns1xF1lklQ1DAOQYNrVWxWJRs4TxipduEq4N02uh9XKWzXxLJuHsc1B9e1Dc+1sHs122POq7i/VYoln6LhO30o32lDHOGa56krde0N/+FY7034zB1pqL8VuDd2/8o8XZ+D/ez/1gBwQ2y1q6CRvvZmNyYBIC8an/Vgb++e5zgx6Cb43o9+PEFc8UEA8QljTgZ2m+kwjia1TSYeyYnKQOIqCKMkZa6IBIwMZ6AHIDSWk//IR/UMiq4QGfb5CJFPYOTKSGXEU9dFPYbx+pZmq/Fq7QgFCM/I7M6jKZPwn+T4/RGLEg1YNRwQS/oQI/uu5iF9sIbtWO5XTRQ8q2ld4s3tEFflYdmELHXrt1UuFaCi82iTJZAgFPeIx9mHPb0U+I7iutfEPogIE5b/2T+qJhIBgeIQUVsJuo+uLdriFm1c7YwBMBTJWC9R2mL+2x6quavpx7u0zgHrmbDxFx6+nBl0DEZxsY5h8AEDUVhyi2w+7aK9T/uh7Pz3/fH+AwXfWcA1cBueYYHX0Due6+3hRAHfOokXTbi27+YoS2AKuXDl2EibHedm5lb1Tg18V66dXtGsvpIn/OUWO2FphUGdtCMgZc51ahYTiN1m6Qqx+z1DFRM2BLw6HLxb1uT1OmDyucvCXIsMl4vNyyeIdJwstIbQrECxg1Fdow6jHrzKyJw/FKsYGSnyDRk++1jTt3J46wz16S45XaMSDG8RMH7AKKeAX/lfJ0d247ajB4U8Hei1h1kclX/DAYp7A0KyoCG7Qt9hZGsxhsloT2eYohHEKshPDs2WU48WtuHwgXydkTABvx3b1ixLp2CEuQiMyy3jZpvDD8WGaqWqbQgnH/yQw==",
      "USER_ID_FOR_SRP" => "a2c2e290-6d0f-4a08-a5ca-f0162935f3a6"
    }
  }.freeze

  def test_create_secret_hash
    assert_equal "QW3YkSgjkc9VNMtbTkuQflK54A6+9GS8ZiRDj0mSvPI=", CognitoSrpHelper.create_secret_hash(
      "a2c2e290-6d0f-4a08-a5ca-f0162935f3a6",
      "18u8119jgbpr464n28s1itk2mq",
      "ps50nb7hd1umdnmlt1xa9nwiscqvdvzy5ijw63vcacd09yihc2b"
    )
  end

  def test_create_srp_session_deterministic
    fixed_small_a = [SESSION[:small_a]].pack("H*")
    fixed_time = SESSION[:timestamp]

    random_stub = proc { |_n| fixed_small_a }
    time_stub = proc { fixed_time }

    session = CognitoSrpHelper.stub(:random_bytes, random_stub) do
      CognitoSrpHelper.stub(:create_timestamp, time_stub) do
        CognitoSrpHelper.create_srp_session("john.doe", SESSION[:password], "eu-west-2_eYpv1mFHB")
      end
    end

    assert_equal SESSION[:large_a], session[:large_a]
    assert_equal SESSION[:timestamp], session[:timestamp]
  end

  def test_sign_srp_session
    signed = CognitoSrpHelper.sign_srp_session(SESSION, RESPONSE)
    assert_equal "RrSiIBQazZkaxHQf34oRro1qjzfEvwdP6/Avltpd34E=", signed[:password_signature]
  end

  def test_sign_srp_session_with_device
    response = Marshal.load(Marshal.dump(RESPONSE))
    response["ChallengeParameters"].delete("USER_ID_FOR_SRP")
    response["ChallengeParameters"]["DEVICE_KEY"] = "eu-west-2_627477ae-3631-4248-bed9-d2e934100372"
    response["ChallengeParameters"]["SALT"] = "00eb96"

    signed = CognitoSrpHelper.sign_srp_session_with_device(
      SESSION,
      response,
      "-FDRunwQv",
      "BAUl"
    )

    assert_match(/\A[A-Za-z0-9+\/=]+\z/, signed[:password_signature])
  end

  def test_wraps_auth_requests
    wrapped_init = CognitoSrpHelper.wrap_initiate_auth(SESSION, { "AuthParameters" => { "USERNAME" => "john.doe" } })
    assert_equal SESSION[:large_a], wrapped_init["AuthParameters"]["SRP_A"]

    signed = SESSION.merge(secret: "secret", password_signature: "sig")
    wrapped_challenge = CognitoSrpHelper.wrap_auth_challenge(signed, { "ChallengeResponses" => { "USERNAME" => "john" } })
    assert_equal "sig", wrapped_challenge["ChallengeResponses"]["PASSWORD_CLAIM_SIGNATURE"]
    assert_equal SESSION[:timestamp], wrapped_challenge["ChallengeResponses"]["TIMESTAMP"]
  end
end
