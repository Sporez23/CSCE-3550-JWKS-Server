from flask import Flask, jsonify, request
from datetime import datetime, timedelta
from Crypto.PublicKey import RSA
from Crypto import Random
import jwt

app = Flask(__name__)

# Dictionary to store key pairs
key_pairs = {}

# Function to generate RSA key pair
def generate_rsa_key_pair(kid, expiry_time):
    random_generator = Random.new().read
    key = RSA.generate(2048, random_generator)
    public_key = key.publickey().exportKey()
    private_key = key.exportKey()
    key_pairs[kid] = {
        'kid': kid,
        'public_key': public_key,
        'private_key': private_key,
        'expiry_time': expiry_time
    }

# Function to serve JWKS endpoint
@app.route('/.well-known/jwks.json')
def serve_jwks():
    current_time = datetime.now()
    jwks = {
        'keys': [
            {
                'kid': kid,
                'pubkey': key['public_key']
            } for kid, key in key_pairs.items() if key['expiry_time'] > current_time
        ]
    }
    return jsonify(jwks)

# Function to issue JWT
@app.route('/auth', methods=['POST'])
def issue_jwt():
    kid = request.args.get('kid', '')
    use_expired = request.args.get('expired', '') == 'true'
    if kid in key_pairs:
        if use_expired or key_pairs[kid]['expiry_time'] > datetime.now():
            payload = {
                'exp': datetime.utcnow() + timedelta(hours=1),
                'iat': datetime.utcnow()
            }
            token = jwt.encode(payload, key_pairs[kid]['private_key'], algorithm='RS256')
            return token  # Return the token directly without decoding it
    return 'Failed to issue JWT.', 500


if __name__ == '__main__':
    # Generate key pairs
    generate_rsa_key_pair('Spore_1', datetime.now() + timedelta(hours=1))
    generate_rsa_key_pair('Spore_2', datetime.now() + timedelta(hours=2))
    app.run(debug=True, port=8080)


