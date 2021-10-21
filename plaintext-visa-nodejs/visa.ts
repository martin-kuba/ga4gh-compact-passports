import { util, pki } from 'node-forge';
import base64url from 'base64url';

const ed25519Keys = {
    'rfc8032-7.1-test1': '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    'rfc8032-7.1-test2': '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'
}

/**
 * Create a compact visa with visa content, a key identifier - and signed by the corresponding key from the passed
 * in keyset.
 *
 * @param keys the definitions of all the keys (kid -> hex string of Ed25519 seed)
 * @param visaContent a string of visa content we want to sign
 * @param kid the selected kid to use for signing
 */
function makeVisaSigned(keys: { [kid: string]: string }, visaContent: string, kid: string): any {
    const keyPrivateHexString = keys[kid];

    if (!keyPrivateHexString) throw Error(`Cant make a visa with the unknown kid ${kid}`);

    const seed = util.hexToBytes(keyPrivateHexString);

    if (seed.length != 32) throw Error(`Private keys (seed) for ED25519 must be exactly 32 octets but for kid ${kid} was ${seed.length}`);

    const keypair = pki.ed25519.generateKeyPair({seed: seed});
    const msgBuffer = Buffer.from(visaContent, 'utf8');

    const signature = pki.ed25519.sign({
        message: msgBuffer,
        privateKey: keypair.privateKey,
    });

    return {
        v: visaContent,
        k: kid,
        s: base64url(Buffer.from(signature)),
    };
}

const visa1 = makeVisaSigned(ed25519Keys,
    "c:8XZF4195109CIIERC35P577HAM et:1665130508 iu:https://nagim.dev/p/wjaha-ppqrg-10000 iv:39a277efae72236a",
    'rfc8032-7.1-test1');

console.log(JSON.stringify(visa1, null, 2));
