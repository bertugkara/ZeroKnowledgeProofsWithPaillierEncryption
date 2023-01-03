const express = require('express');
const paillier = require('paillier-js');

const app = express();
app.use(express.json());

const port = 3000;

let optionNo = 0n;
let voteState = [];
let voteHolder = [];
let publicKey, privateKey;
let vote;

async function initKeys() {

    const keyPair = paillier.generateRandomKeys(128);
    publicKey = keyPair.publicKey;
    privateKey = keyPair.privateKey;
    console.log("----------------------------------------------------------------------------")
    console.log("Public and Private Key initialized. Ready for listening requests.")
    console.log(publicKey)
    console.log(privateKey)
    voteState = [publicKey.encrypt(optionNo), publicKey.encrypt(optionNo), publicKey.encrypt(optionNo)];
}

app.get('/getPublicKey', (request, response) => {
    let publicKeyObject = {
        n: (publicKey.n).toString(),
        g: (publicKey.g).toString()
    }
    console.log("----------------------------------------------------------------------------")
    console.log("Public Key Sent!")
    response.contentType("application/json").send(JSON.stringify(publicKeyObject));
});


app.post('/consumeVote', (request, response) => {
    vote = JSON.parse(request.body.array);
    for (let i = 0; i < vote.length; i++) {
        vote[i] = BigInt(vote[i]);
    }
    console.log("----------------------------------------------------------------------------")
    console.log("Reached an Proof, if Proof is Valid I am going to add the vote to the state.")
    voteHolder.push(vote);
});

function printResults() {
    console.log("Results are created and sent to The Requester.")
    return ("Aday 1:" + privateKey.decrypt(voteState[0]) + "\n"
        + "Aday 2:" + privateKey.decrypt(voteState[1]) + "\n"
        + "Aday 3:" + privateKey.decrypt(voteState[2]));
}

function calculateResults() {
    voteHolder.forEach((array) => {
        voteState[0] = publicKey.addition(array[0], voteState[0]);
        voteState[1] = publicKey.addition(array[1], voteState[1]);
        voteState[2] = publicKey.addition(array[2], voteState[2]);
    });
    console.log("----------------------------------------------------------------------------")
    return printResults();
}

app.get('/results', (request, response) => {
    response.status(200).send(calculateResults());
});

// start the server
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
    initKeys();
});



