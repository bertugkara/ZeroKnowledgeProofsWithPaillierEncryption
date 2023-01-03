const bigInt = require('big-integer')
const crypto = require('crypto')
const requester = require("request");
const express = require('express');
const paillier = require("paillier-js")

const app = express();
app.use(express.json());

const port = 3002;

// Based on https://paillier.daylightingsociety.org/Paillier_Zero_Knowledge_Proof.pdf
// implementation by https://github.com/framp/paillier-in-set-zkp
// implementation of Dear Framp is customized due to needs of this application.
// Variables renamed with ChatGPT (openAI) to improve readability https://chat.openai.com/chat

// getCoprime :: Bits -> Number -> Number
// Generate a coprime number of target (their GCD should be 1)
const getCoprime = (target) => {
    const bits = Math.floor(Math.log2(target))
    while (true) {
        const lowerBound = bigInt(2).pow(bits-1).plus(1)
        const size = bigInt(2).pow(bits).subtract(lowerBound)
        let possible = lowerBound.plus(bigInt.rand(bits)).or(1)
        const result = bigInt(possible)
        if (possible.gt(bigInt(2).pow(1024))) return result
        while(target > 0) {
            [possible, target] = [target, possible.mod(target)]
        }
        if (possible.eq(bigInt(1))) return result
    }
}

// proofForEncryptedVote :: Paillier.PublickKEy -> Message, -> [Message] -> Bits
// Generate a message encryption and a Zero Knowledge proof that the message
// is among a set of valid messages
const proofForEncryptedVote = (publicKey, encryptedVote, validVote, bits = 512, randomValue) => {
    const as = []
    const es = []
    const zs = []

    const cipher = encryptedVote;
    const random = randomValue;

    const om = getCoprime(publicKey.n)
    const ap = om.modPow(publicKey.n, publicKey._n2)

    let mi = null
    validVote.forEach((mk, i) => {
        console.log(mk,i)
        const gmk = publicKey.g.modPow(bigInt(mk), publicKey._n2)
        const uk = cipher.times(gmk.modInv(publicKey._n2)).mod(publicKey._n2)
            const zk = getCoprime(publicKey.n)
            zs.push(zk)
            const ek = bigInt.randBetween(2, bigInt(2).pow(bits).subtract(1));
            es.push(ek)
            const zn = zk.modPow(publicKey.n, publicKey._n2)
            const ue = uk.modPow(ek, publicKey._n2)
            const ak = zn.times(ue.modInv(publicKey._n2)).mod(publicKey._n2)
            as.push(ak)
    })

    const hash = crypto.createHash('sha256').update(as.join('')).digest('hex');

    const esum = es.filter(Boolean).reduce((acc, ek) => acc.plus(ek).mod(bigInt(2).pow(256)), bigInt(0))
    const ep = bigInt(hash, 16).subtract(esum).mod(bigInt(2).pow(256))
    const rep = (Math.pow(random, ep) % publicKey.n);
    const zp = om * ((rep) % (publicKey.n))
    es[mi] = ep
    zs[mi] = zp

    const proof = [as, es, zs]
    return [cipher, proof]
}
// verifyProof :: Paillier.PublickKEy -> Paillier.Encryption, -> Proof -> [Message] -> Bool
// Verify a Zero Knowledge proof that an encrypted message is among a set of valid messages
const verifyProof = (publicKey, cipher, [as, es, zs], validMessages) => {
    const hash = crypto.createHash('sha256').update(as.join('')).digest('hex');

    const us = validMessages.map(mk => {
        const gmk = publicKey.g.modPow(mk, publicKey._n2)
        const uk = cipher.times(gmk.modInv(publicKey._n2)).mod(publicKey._n2)
        return uk
    })

    const esum = es.reduce((acc, ek) => acc.plus(ek).mod(bigInt(2).pow(256)), bigInt(0))
    if (!bigInt(hash, 16).eq(esum)) {
        return false
    }
    return zs.every((zk, i) => {
        const ak = as[i]
        const ek = es[i]
        const uk = us[i]
        const zkn = zk.modPow(publicKey.n, publicKey._n2)
        const uke = uk.modPow(ek, publicKey._n2)
        const akue = ak.times(uke).mod(publicKey._n2)
        return zkn.eq(akue)
    })
}

let publicKey;

function getPublicKey() {
    requester.get('http://localhost:3000/getPublicKey', (error, response, body) => {
        if (response) {
            let PublicKey = JSON.parse(response.body);
            publicKey = new paillier.PublicKey(BigInt(PublicKey.n), BigInt(PublicKey.g));
            console.log(publicKey)
            console.log(privateKey)
            console.log("------------------------------------------------------------")
            console.log("Zero Knowledge Provider Initialized, Waiting for Requests to create Proof.")
        } else if (error) console.log(error)

    });
}

function sumVoteArrayAndReturn(arr) {
    let result = publicKey.encrypt(0n);
    for (let i = 0; i < arr.length; i++) {
        result = publicKey.addition(result, BigInt(arr[i]))
    }
    return result;
}

app.post('/createProof', (request, response) => {
    let proofResponse;
    let validVote = [1]
    let bits = 32;
    if (request.body.vote && request.body.randomValue) {
        const message = sumVoteArrayAndReturn(JSON.parse(request.body.vote));
        const randomValue = JSON.parse(request.body.randomValue);

        console.log("Creating Proof... Please Wait...")
        const [cipher, proof] = proofForEncryptedVote(publicKey, message, validVote, bits, randomValue)
        const result = verifyProof(publicKey, cipher, proof, validVote)
        console.log("Proof Created Result is send back to the Client: " + result);
        proofResponse = {
            message: message,
            result: result
        }
    }

    //send to the server
    /*
    SEND TO SERVER LOGIC, LATER
     */

    response.status(200).send(proofResponse);
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
    getPublicKey()
});