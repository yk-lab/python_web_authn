import os, sys
import logging
import responder
import cbor2 as cbor
import sqlite3
from contextlib import closing
import json
import hashlib, base64
from cryptography.hazmat.primitives.asymmetric.ec import (ECDSA, EllipticCurvePublicNumbers, SECP256R1)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from OpenSSL import crypto
import codecs

logging.basicConfig(level=logging.DEBUG)

rpid_host = os.getenv('RPID_HOST', 'localhost')
allow_origins = os.getenv('ALLOW_ORIGINS', 'http://localhost:8000').split(';')

api = responder.API(
    cors=True,
    cors_params={
        'allow_origins': ['http://localhost:8000','http://localhost:8000/'],
        'allow_methods': ['GET', 'POST'],
        'allow_headers': ['*'],
        'expose_headers': ['*']
    },
    debug=True
)

@api.route("/")
class WebAuthn:
    async def on_get(self, req, resp):
        # TODO: return webauthnCreate challenge
        # TODO: return webauthnGet challenge
        pass

    async def on_post(self, req, resp):
        body = await req.media(format="json")
        raw_id = bytes(body.get('raw_id').values())
        client_data = json.loads(bytes(body.get('client_data').values()))
        client_data_hash = hashlib.sha256(bytes(body.get('client_data').values())).digest()

        logging.debug(f'raw_id {base64.urlsafe_b64encode(raw_id)}')
        logging.debug('===client_data===')
        for k in client_data.keys():
            logging.debug(f'{k} {client_data[k]}')

        # TODO: challenge check
        # TODO: tokenBinding check
        if client_data['origin'] in allow_origins:
            if client_data['type'] == 'webauthn.create':
                attestation = cbor.loads(bytes(body.get('attestation').values()))
                self.webauthnCreate(resp, raw_id, attestation, client_data_hash)
            elif client_data['type'] == 'webauthn.get':
                authenticator_data = bytes(body.get('authenticator_data').values())
                signature = bytes(body.get('signature').values())
                user_handle = bytes(body.get('user_handle').values())
                self.webauthnGet(resp, raw_id, authenticator_data, signature, user_handle, client_data_hash)
            else:
                resp.media = {'status': 'ng'}
                logging.info(body)
                return
        else:
            resp.media = {'status': 'ng'}
            logging.info('not allowed origin')

    def webauthnGet(self, resp, raw_id, authData, signature, user_handle, client_data_hash):
        logging.debug('===assertion===')
        if authData:
            logging.debug('authData')
            if authData[:32].hex() == hashlib.sha256(rpid_host.encode()).hexdigest():
                logging.debug('\trpidHash ' + str(authData[:32].hex()))
                flags = int.from_bytes(authData[32:33], 'big')
                logging.debug(f'\tflags {bin(flags)}, {bin(flags & 0b0100_0000)}, {bin(flags & 0b1000_0000)}')
                logging.debug('\tsigCount ' + str(int.from_bytes(authData[33:37], 'big')))

                with open(f"./keys/{base64.urlsafe_b64encode(raw_id).decode()}.cbor") as f:
                    public_key = cbor.loads(base64.b64decode(f.readline().encode()))
                if public_key[3] == -7:
                    # TODO: 他のアルゴリズムへの対応
                    verification_data = authData + client_data_hash
                    x = int(codecs.encode(public_key[-2], 'hex'), 16)
                    y = int(codecs.encode(public_key[-3], 'hex'), 16)
                    credential_public_key = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key(backend=default_backend())
                    try:
                        credential_public_key.verify(signature, verification_data, ECDSA(SHA256()))
                        resp.media = {'status': 'ok'}
                        logging.info('[success] navigator.credentials.get')
                    except InvalidSignature as e:
                        logging.info(f'InvalidSignature {e}')
                        resp.media = {'status': 'ng'}
                else:
                    logging.info('not support type')
                    resp.media = {'status': 'ng'}
            else:
                logging.info('not match RPID')
                logging.debug(f'{authData[:32].hex()}, {hashlib.sha256(rpid_host.encode()).hexdigest()} [{authData[:32].hex() == hashlib.sha256(rpid_host.encode()).hexdigest()}]')
                resp.media = {'status': 'ng'}
        else:
            logging.info('not find authData')
            resp.media = {'status': 'ng'}


    def webauthnCreate(self, resp, raw_id, attestation, client_data_hash):
        logging.debug('===attestation===')
        authData = attestation.get('authData')
        if authData:
            logging.debug('authData')
            if authData[:32].hex() == hashlib.sha256(rpid_host.encode()).hexdigest():
                logging.debug('\trpidHash ' + str(authData[:32].hex()))
                flags = int.from_bytes(authData[32:33], 'big')
                logging.debug(f'\tflags {bin(flags)}, {bin(flags & 0b0100_0000)}, {bin(flags & 0b1000_0000)}')
                logging.debug('\tsigCount ' + str(int.from_bytes(authData[33:37], 'big')))
                if flags & 0b0100_0000:
                    logging.debug('attestedCredentialData')
                    logging.debug('\taaguid ' + str(int.from_bytes(authData[37:53], 'big')))
                    credentialIdLength = int.from_bytes(authData[53:55], 'big')
                    logging.debug('\tcredentialIdLength ' + str(credentialIdLength))
                    credentialId = authData[55:55+credentialIdLength]
                    logging.debug('\tcredentialId ' + str(base64.b64encode(credentialId)))
                    credentialPublicKey = cbor.loads(authData[55+credentialIdLength:])
                    logging.debug('\tcredentialPublicKey')
                    logging.debug('\t\tkty ' + str(credentialPublicKey[1]))
                    logging.debug('\t\talg ' + str(credentialPublicKey[3]))
                    logging.debug('\t\tcrv ' + str(credentialPublicKey[-1]))
                    logging.debug('\t\tx ' + str(credentialPublicKey[-2]))
                    logging.debug('\t\ty ' + str(credentialPublicKey[-3]))
                if flags & 0b1000_0000:
                    logging.debug('extensions ' + str(cbor.loads(bytes(authData[37:]))))
                    logging.info('not support flags')
                    resp.media = {'status': 'ng'}
                    return

                logging.debug('fmt ' + str(attestation.get('fmt')))
                attStmt = attestation.get('attStmt')
                logging.debug('attStmt')
                for k in attStmt.keys():
                    logging.debug(f'\t{k} {attStmt[k]}')

                if attestation.get('fmt') == 'packed' and 'x5c' not in attStmt:
                    # TODO: 他のパターンへの対応
                    # TODO: 他のアルゴリズムへの対応
                    signature = attStmt['sig']
                    verification_data = authData + client_data_hash
                    x = int(codecs.encode(credentialPublicKey[-2], 'hex'), 16)
                    y = int(codecs.encode(credentialPublicKey[-3], 'hex'), 16)
                    credential_public_key = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key(backend=default_backend())
                    try:
                        credential_public_key.verify(signature, verification_data, ECDSA(SHA256()))
                        resp.media = {'status': 'ok'}
                        logging.info('[success] navigator.credentials.create')
                        with open(f'keys/{base64.urlsafe_b64encode(raw_id).decode()}.cbor', 'w') as f:
                            f.write(f'{base64.b64encode(authData[55+credentialIdLength:]).decode()}')
                    except InvalidSignature as e:
                        logging.info(f'InvalidSignature {e}')
                        resp.media = {'status': 'ng'}
                else:
                    logging.info('not support type')
                    resp.media = {'status': 'ng'}
            else:
                logging.info('not match RPID')
                logging.debug(f'{authData[:32].hex()}, {hashlib.sha256(rpid_host.encode()).hexdigest()} [{authData[:32].hex() == hashlib.sha256(rpid_host.encode()).hexdigest()}]')
                resp.media = {'status': 'ng'}
        else:
            logging.info('not find authData')
            resp.media = {'status': 'ng'}



if __name__ == '__main__':
    api.run()
