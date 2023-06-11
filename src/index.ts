import express, { Application, Request, Response } from 'express';
import { authenticator } from 'otplib';
import * as speakeasy from 'speakeasy';
import bodyParser from 'body-parser';

// const a = require("solc")
import * as solc from 'solc';
import { readFileSync } from "fs"
import { ethers } from 'ethers';
import MerkleTree from 'merkletreejs';
import { bufferToHex } from 'ethereumjs-util'
import cors from 'cors';


const app: Application = express();

app.use(cors());
app.use(bodyParser.json());

let secret = ""
let latestTimeStamp = 0;
const globalLeafs: Pair[] = []
let tree: MerkleTree

app.get('/register', async (req: Request, res: Response): Promise<Response> => {

  if (secret == "") {
    secret = authenticator.generateSecret()
  }

  
  const otpauth = authenticator.keyuri('user', 'service', secret);
  return res.status(200).send({
    message: otpauth,
  });
});

function getTimestamps(number_of_timestamps: number, step: number): number[] {
  let now = new Date();
  now.setHours(0, 0, 0, 0)
  const timestamps: number[] = [];

  for(let i = 0; i < number_of_timestamps; i++) {
      // Convert Date object to UNIX timestamp and append to the list
      timestamps.push(Math.floor(now.getTime() / 1000));
      // Increment current time by step seconds
      now = new Date(now.getTime() + step * 1000);
  }
  
  return timestamps;
}

interface Pair {
  code: number,
  timestamp: number
}

function pairToBytesString(pair: Pair) {
  const timestampBN = ethers.BigNumber.from(pair.timestamp)
  const codeBN = ethers.BigNumber.from(pair.code)

  const bytes1 = ethers.utils.zeroPad(timestampBN.toHexString(), 16)
  const bytes2 = ethers.utils.zeroPad(codeBN.toHexString(), 16)
  const combined = ethers.utils.hexlify(ethers.utils.concat([bytes1, bytes2]))
  return combined
}

const hashFunction = (el: Buffer) => {
  return Buffer.from(ethers.utils.keccak256(el).slice(2), 'hex');
};

function generateMerkleTreeRoot(pairs: Pair[]) {
  const tree = getMerkletree(pairs)
  const root = bufferToHex(tree.getRoot())
  return root
}

function getMerkletree(pairs: Pair[]) {
  const data = pairs.map((p) => pairToBytesString(p))
  const tree = new MerkleTree(data, hashFunction)
  return tree
}

function getMerkleTreeProof(pairs: Pair[], leaf: Pair) {
  const tree = getMerkletree(pairs)
  const leafToSearch = pairToBytesString(leaf)

  // const proof = tree.getProof(leafToSearch)
  const proof = tree.getProof(leafToSearch).sort((a, b) => a.data.compare(b.data)).map(p => '0x' + p.data.toString('hex'))
  return proof
}

app.get('/create-totp', async (req: Request, res: Response): Promise<Response> => {
  if (secret == "") {
    return res.status(200).send({
      message: "Register first",
    });
  }

  if (globalLeafs.length == 0){
    const timestamps = getTimestamps(4096, 30)

    for (let index = 0; index < timestamps.length; index++) {
      const otpFuture = speakeasy.totp({
        secret: secret,
        time: timestamps[index],
        encoding: 'base32' // change encoding as per your secret format
      });
      globalLeafs.push( {
        timestamp: timestamps[index],
        code: parseInt(otpFuture)
      })
    }
    latestTimeStamp = timestamps[timestamps.length - 1]
  }

  const root = generateMerkleTreeRoot(globalLeafs)

  return res.status(200).send({
    message: root,
    latestTimestamp: latestTimeStamp,
  });
});

app.get('/get-closest', async (req: Request, res: Response): Promise<Response> => {
  if (secret == "") {
    return res.status(200).send({
      message: "Register first",
    });
  }

  if (globalLeafs.length == 0) {
    return res.status(200).send({
      message: "generate leafs",
    });
  }

  const now = (new Date()).getTime() / 1000

  for (let i = 0; i < globalLeafs.length; i++) {
    let leaf = globalLeafs[i]
    if (leaf.timestamp > now) {
      leaf = globalLeafs[i - 1]

      const proof = getMerkleTreeProof(globalLeafs, leaf)
      const leafToSend = pairToBytesString(leaf)
      

      const tree = getMerkletree(globalLeafs)
      const verified = tree.verify(proof, leafToSend, generateMerkleTreeRoot(globalLeafs));

      return res.status(200).send({
        message: {
          timestamp: leaf.timestamp,
          code: leaf.code,
          leaf: leafToSend,
          verified,
          proof
        }
      });
    }
  }

  return res.status(200).send({
    message: "NOT FOUND valid leaf",
  });
});

app.get('/test', async (req: Request, res: Response): Promise<Response> => {
  
  
  // Array of data (normally this would be more complex than just numbers)
  const data = ['data1', 'data2', 'data3', 'data4'].map(v => Buffer.from(v));
  
  // Create a MerkleTree
  const tree = new MerkleTree(data, hashFunction);
  
  // Get the Merkle root
  // This is used for verification and could be stored
  const root = tree.getRoot().toString('hex');
  
  // Get a proof for a data
  const proof = tree.getProof(data[0]);
  proof.sort((a, b) => a.data.compare(b.data));

  
  // Verify the proof
  const verified = tree.verify(proof, data[0], root);
  console.log(`Verified: ${verified}`);  // true

  return res.status(200).send({
    message: "proof " + verified,
    proof
  });
});

app.get('/secret', async (req: Request, res: Response): Promise<Response> => {
  return res.status(200).send({
    message: secret,
  });
});

app.get('/get-latest-timestamp', async (req: Request, res: Response): Promise<Response> => {
  return res.status(200).send({
    message: latestTimeStamp,
  });
});

app.get('/token', async (req: Request, res: Response): Promise<Response> => {
  if (secret == "") {
    secret = authenticator.generateSecret()
  }

  const token = authenticator.generate(secret);

  const otp = speakeasy.totp({
    secret: secret,
    encoding: 'base32' // change encoding as per your secret format
  });

  const targetTimestamp = Math.floor(Date.now() / 1000) + 30;

  const otpFuture = speakeasy.totp({
    secret: secret,
    time: targetTimestamp,
    encoding: 'base32' // change encoding as per your secret format
  });
  
 
  
  return res.status(200).send({
    authenticator: token,
    speakEasy: otp,
    speakEasyFuture: otpFuture,
  });
});

app.post('/validate', (req: express.Request, res: express.Response) => {
  console.log(req.body);  // Log the request body

  const tree = getMerkletree(globalLeafs)
  const verified = tree.verify(req.body.proof, req.body.leaf, req.body.root);

  return res.status(200).send({
    verified: verified,
  });
  res.send('Received a POST request');
});


const PORT = 3003;

try {
  app.listen(PORT, (): void => {
    console.log(`Connected successfully on port ${PORT}`);
  });
} catch (error: any) {
  console.error(`Error occured: ${error.message}`);
}
