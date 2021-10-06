import cwt
import json
import zlib
from base64 import b64encode
from cwt import COSEKey

with open('src/main/resources/ecc_p256.jwks') as jwks_file:
    private_key = COSEKey.from_jwk(json.load(jwks_file)['keys'][0])

payload = {
    "iss": "https://login.elixir-czech.org/oidc/",
    "sub": "766e0e9deb110dca86b4132485bcfe4daba72db6@elixir-europe.org",
    "cti": "58219d95-31be-48ce-847b-7620b967649c",
    "exp": 1949052270,
    "ga4gh_visa_v1": {
        "asserted": 1633519470,
        "by": "self",
        "source": "https://elixir-europe.org/",
        "type": "AcceptedTermsAndPolicies",
        "value": "https://doi.org/10.1038/s41431-018-0219-y"
    }
}
my_claim_names = {
    "ga4gh_visa_v1": -70001,
}
cwt.set_private_claim_names(my_claim_names)
token = cwt.encode(payload, private_key)
compressed_token = zlib.compress(token)
cwt_base64 = b64encode(token)
cwt_compressed_base64 = b64encode(compressed_token)
print('CWT hex: ', token.hex())
print('CWT base64: ', cwt_base64)
print("CWT base64 character length: ",len(cwt_base64))
print("CWT compressed base64 character length: ",len(cwt_compressed_base64))

# see structure at http://cbor.me/
# claims: https://www.iana.org/assignments/cwt/cwt.xhtml