const endPoint = "https://acme-staging-v02.api.letsencrypt.org/directory";
const url = "ssltest.rocketpanel.io";
const agent = "RocketPanel/TLS0.01";

const fetch = require("node-fetch");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const app = express();
const jose = require("node-jose");
const forge = require("node-forge");
const pki = forge.pki;


const keyStore = jose.JWK.createKeyStore();

async function signPayload(message, key, publicKey, url, newNonceURL, kid = undefined) {
    const nonce = await retreiveNonce(newNonceURL);
    let formattedMessage = JSON.stringify(message);
    if (message == '') {
        formattedMessage = '';
    }
    let fields = {
        alg: "RS256",
        url: url,
        nonce: nonce
    };
    if (kid == undefined) {
        fields.kid = null;
        fields.jwk = {
            e: publicKey.e,
            kty: publicKey.kty,
            n: publicKey.n
        };
    } else {
        fields.kid = kid;
        fields.jwk = null;
    }
    const thingy = await jose.JWS.createSign({
        format: "flattened",
        fields: fields,
    }, key).update(formattedMessage, "utf8").final();
    return JSON.stringify(thingy);
}

async function retreiveNonce(url) {
    const req = await fetch(url);
    return req.headers.get("replay-nonce");
}

async function makeRequest(url, body, key, publicKey, newNonceURL, kid = undefined) {
    let signed = await signPayload(body, key, publicKey, url, newNonceURL, kid);

    const req = await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/jose+json",
            "User-Agent": agent,
        },
        body: signed
    });
    const headers = await req.headers;
    const resp = await req.json();
    return [resp, headers];
}

async function makeTextRequest(url, body, key, publicKey, newNonceURL, kid = undefined) {
    let signed = await signPayload(body, key, publicKey, url, newNonceURL, kid);

    const req = await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/jose+json",
            "User-Agent": agent,
        },
        body: signed
    });
    const headers = await req.headers;
    const resp = await req.text();
    return [resp, headers];
}

const start = async function () {

    const endpointsReq = await fetch(endPoint);
    const endpointsResp = await endpointsReq.json();

    const newAccountURL = endpointsResp.newAccount;
    const newNonceURL = endpointsResp.newNonce;
    const newOrderURL = endpointsResp.newOrder;

    const key = await keyStore.generate("RSA", 2048, { alg: "RS256", key_ops: ["sign", "decrypt", "unwrap"] });
    const publicKey = keyStore.toJSON().keys[0];


    const [registrationResponse, registrationHeaders] = await makeRequest(newAccountURL, {
        contact: ["mailto:certs@rocketpanel.io"],
        termsOfServiceAgreed: true,
        onlyReturnExisting: false,
    }, key, publicKey, newNonceURL)
    const registrationHeaderss = registrationHeaders;


    if (registrationResponse.status == "valid") {
        const account = registrationHeaderss.get("location");

        const [orderResp, orderHeaders] = await makeRequest(newOrderURL, {
            identifiers: [
                {
                    type: 'dns',
                    value: url
                }
            ]
        }, key, publicKey, newNonceURL, account);

        const [authResp, authHeaders] = await makeRequest(orderResp.authorizations[0], '', key, publicKey, newNonceURL, account);

        if (authResp.status == "pending") {

            const challenge = authResp.challenges.find(a => a.type == "http-01");

            const challengeUrl = challenge.url;
            const challengeToken = challenge.token;

            app.get(`/.well-known/acme-challenge/${challengeToken}`, async (req, res) => {
                const thumb = await key.thumbprint("SHA-256");
                const usingThumbprint = thumb.toString("base64").split("/").join("_").replace("=", "").split("+").join("-"); // why the heck are these different? istg this is getting kinda dumb..

                res.send([
                    challengeToken,
                    usingThumbprint,
                ].join("."))
            })

            const [readyResp, readyHeaders] = await makeRequest(challengeUrl, {}, key, publicKey, newNonceURL, account);

            async function ACMEValidatedResponse(resp, headers) {

                const keys = forge.pki.rsa.generateKeyPair(2048);
                const csr = forge.pki.createCertificationRequest();
                csr.publicKey = keys.publicKey;

                csr.setSubject([
                    {
                        name: 'commonName',
                        value: url
                    }

                ]);
                csr.setAttributes({
                    extensions: [{
                        name: 'subjectAltName',
                        altNames: [{
                            type: 2,
                            value: url
                        }],
                    }]
                });


                csr.sign(keys.privateKey);
                const csrPem = forge.pki.certificationRequestToPem(csr)
                const msg = forge.pem.decode(csrPem)[0].body;

                const keyBody = forge.util.encode64(msg, 64).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

                fs.writeFileSync("./domain.key", forge.pki.privateKeyToPem(keys.privateKey))

                const [finalResp, finalHeaders] = await makeRequest(orderResp.finalize, {
                    csr: keyBody
                }, key, publicKey, newNonceURL, account);


                if (finalResp.status == "valid" && finalResp.certificate !== undefined){
                    const [certResp] = await makeTextRequest(finalResp.certificate, '', key, publicKey, newNonceURL, account);

                    fs.writeFileSync("./certificate.pem", certResp)

                    console.log("Successfully generated certificates!")
                }else{
                    throw new Error("Something went wrong while getting certificate from LetsEncrypt.")
                }

            }

            if (readyResp.status == "valid") {
                ACMEValidatedResponse(readyResp, readyHeaders);
            } else {

                let onTry = 0;

                const int = setInterval(async () => {
                    onTry++;
                    const [readyiResp, readyiHeaders] = await makeRequest(challengeUrl, '', key, publicKey, newNonceURL, account);

                    if (readyiResp.error !== undefined) {
                        throw new Error(`Was unable to verify certificate after ${onTry} tries. Error: ${readyiResp.error.detail}`)
                    } else {
                        if (readyiResp.status == "valid") {
                            ACMEValidatedResponse(readyiResp, readyiHeaders);
                            clearInterval(int);
                        } else {
                            console.log(`#${onTry}: Challenge did not pass on this attempt, trying again in 5 seconds`)
                            clearInterval(int);
                        }
                    }
                }, 5000)
            }

        } else {
            throw new Error("Invalid response for authorization data.")
        }
    } else {
        throw new Error("Something went wrong registering an account for LetsEncrypt.")
    }



}

app.listen(80);
start();