const requester = require('request');
const paillier = require('paillier-js');
const express = require('express');
const bigInt = require('big-integer')

const app = express();
app.use(express.json());

const port = 3001;

let publicKey;

let optionNo = 0n, optionYes = 1n;
let candidate_one = [optionYes, optionNo, optionNo];
let candidate_two = [optionNo, optionYes, optionNo];
let candidate_three = [optionNo, optionNo, optionYes];

function sendRequest(vote, randomValue) {
    const postOptions = {
        method: 'POST',
        url: 'http://localhost:3002/createProof',
        body: {
            vote,
            randomValue
        },
        json: true
    };

    requester(postOptions, () => {
    });
}

app.post('/voteFirstCandidate', (request, response) => {
    console.log("------------------------------------------------------------")
    console.log("We are Encrypting your vote. Please Wait")
    let randomValue = generateRandomValue();
    for (let i = 0; i < candidate_one.length; i++) {
        candidate_one[i] = (publicKey.encrypt(candidate_one[i], randomValue)).toString();
    }
    sendRequest(JSON.stringify(candidate_one), randomValue)
    console.log("Success. First Candidate Voted")
    response.status(200).send("Done");
    candidate_one = [optionYes, optionNo, optionNo];
})

app.post('/voteSecondCandidate', (request, response) => {
    console.log("------------------------------------------------------------")
    console.log("We are Encrypting your vote. Please Wait")
    let randomValue = generateRandomValue();
    for (let i = 0; i < candidate_two.length; i++) {
        candidate_two[i] = (publicKey.encrypt(candidate_two[i], randomValue)).toString();
    }
    sendRequest(JSON.stringify(candidate_two), randomValue)
    console.log("Success. Second Candidate Voted")
    response.status(200).send("Done");
    candidate_two = [optionNo, optionNo, optionNo];
})

app.post('/voteThirdCandidate', (request, response) => {
    console.log("------------------------------------------------------------")
    console.log("We are Encrypting your vote. Please Wait")
    let randomValue = generateRandomValue();
    for (let i = 0; i < candidate_three.length; i++) {
        candidate_three[i] = (publicKey.encrypt(candidate_three[i], randomValue)).toString();
    }
    sendRequest(JSON.stringify(candidate_three), randomValue)
    console.log("Success. Third Candidate Voted")
    response.status(200).send("Done");
    candidate_three = [optionYes, optionYes, optionYes];
})

function getPublicKey() {
    requester.get('http://localhost:3000/getPublicKey', (error, response, body) => {
        if (response) {
            let PublicKey = JSON.parse(response.body);
            publicKey = new paillier.PublicKey(BigInt(PublicKey.n), BigInt(PublicKey.g));
            console.log(publicKey)
            console.log("------------------------------------------------------------")
            console.log("Application Initialized, Public Key is ready for Encryption.")
        } else if (error) console.log(error)

    });
}

function generateRandomValue(min = 1, max = (publicKey.n)) {
    return bigInt.randBetween(min, max) % 10000;
}

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
    getPublicKey()
});