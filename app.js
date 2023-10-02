//Crypto
import {Ed25519VerificationKey2018} from '@digitalbazaar/ed25519-verification-key-2018';
//API imports
import express from 'express';
import bodyParser from 'body-parser';
import axios from 'axios';

//init express js
var app = express();
var jsonParser = bodyParser.json()
var urlencodedParser = bodyParser.urlencoded({ extended: false })

//init server
var server = app.listen(3001, function () {
  var port = server.address().port
  console.log("CDCS API listening on localhost at port: ", port)
})

//API Routes
//generates Ed25519V2018 key pairs
app.get('/keygen', async function (req, res) {
  const edKeyPair = await Ed25519VerificationKey2018.generate();
  res.json(edKeyPair);
})

//init ed25519-2018 keypair
const keyPair = await Ed25519VerificationKey2018.from({
  type: "Ed25519VerificationKey2018",
  publicKeyBase58: "5NoimR5vPwsDgifz5MEMYNHGmKU7LYhDtTU9ETW6AUxt",
  privateKeyBase58: "26Ziu5CvGuWzGoBbxsiG53y27bBMKqn35rUHDFGiStZdSotn6YtZ3cGMvZgxtNYzQUecbceb1J47MyFcfkD2RjiC"
})
//Vanilla Signer
app.post('/signJson-ld', jsonParser ,async function (req, res) {

  var jsonld = req.body
  const {sign} = keyPair.signer();

  const data = Buffer.from(JSON.stringify(jsonld));
  const signatureValue = await sign({data});
  const date = new Date();
  const proof ={
                type: "Ed25519Signature2018",
                created: date.toISOString(),
                verificationMethod: "did:provider:key:123",
                proofPurpose: "assertionMethod",
                signature: signatureValue.toString('hex')
  }
  jsonld.dcsProof = proof
  res.json(jsonld)

})
//Vanilla Verifier
//self-description verification
async function selfDescriptionVerification(selfDescription){
  const selfDescriptionOg = JSON.parse(JSON.stringify(selfDescription));
  delete selfDescriptionOg.dcsProof
  //delete selfDescriptionOg.verifiableCredential[0].dcsProof
  delete selfDescriptionOg.verifiableCredential.dcsProof
  var verifResults
  try{
    verifResults = await axios.post("http://localhost:8081/verification",selfDescriptionOg)
  }catch{
    verifResults = {data : {lifecycleStatus:false}}
  }
  if(verifResults.data.lifecycleStatus === "active"){
    return {valid:true}
  }else{
    return {valid:false}
  }
}
app.post('/veri-sign', jsonParser ,async function (req, res) {

  var signedCredential = req.body
  const sdValidation = await selfDescriptionVerification(signedCredential)

  if(sdValidation.valid){
    const signature = signedCredential.dcsProof.signature
    delete signedCredential["dcsProof"]
    
    const {verify} = keyPair.verifier();
    const data = Buffer.from(JSON.stringify(signedCredential));
    const valid = await verify({data:data, signature: Buffer.from(signature,'hex') });
  
    res.json({validationResult:valid});
  }else{
    res.json({validationResult:sdValidation.valid,error:"Invalid Self-description signature"});
  }

})
//Provider Sign
app.post('/init-negotiate-provider', jsonParser ,async function (req, res) {

  var jsonld = req.body
  const {sign} = keyPair.signer();
  const sdValidation = await selfDescriptionVerification(jsonld)

  if(sdValidation.valid){
    const data = Buffer.from(JSON.stringify(jsonld));
    const signatureValue = await sign({data});
    const date = new Date();
    const proof = [{
                  type: "Ed25519Signature2018",
                  created: date.toISOString(),
                  verificationMethod: "did:provider:key:123",
                  proofPurpose: "assertionMethod",
                  signature: signatureValue.toString('hex')
    }]
    //jsonld.verifiableCredential[0].dcsProof = proof
    jsonld.verifiableCredential.dcsProof = proof
    res.json(jsonld)
  }else{
    res.json({validationResult:sdValidation.valid,error:"Invalid Self-description signature"});
  }

})
//Consumer Sign
app.post('/init-negotiate-consumer', jsonParser ,async function (req, res) {

  var jsonld = req.body
  const {sign} = keyPair.signer();
  const sdValidation = await selfDescriptionVerification(jsonld)

  if(sdValidation.valid){
    const providerValid =  (await validateParticipant(jsonld,true)).providerValid
    if(providerValid){
      const data = Buffer.from(JSON.stringify(jsonld));
      const signatureValue = await sign({data});
      const date = new Date();
      const proof = {
                    type: "Ed25519Signature2018",
                    created: date.toISOString(),
                    verificationMethod: "did:consumer:key:123",
                    proofPurpose: "assertionMethod",
                    signature: signatureValue.toString('hex')
      }
      //jsonld.verifiableCredential[0].dcsProof.push(proof)
      jsonld.verifiableCredential.dcsProof.push(proof)
      res.json(jsonld)
    }else{res.json({error : "Invalid Provider Signature"})}
  }else{
    res.json({validationResult:sdValidation.valid,error:"Invalid Self-description signature"});
  }
})
//DCS sign
async function  validateParticipant(jsonld,providerOnly=false){
  const {verify} = keyPair.verifier();
  var signedCredential = JSON.parse(JSON.stringify(jsonld))
  //const providerSignature = signedCredential.verifiableCredential[0].dcsProof[0].signature
  const providerSignature = signedCredential.verifiableCredential.dcsProof[0].signature
  var consumerSignature
  if(!providerOnly){
    //consumerSignature = signedCredential.verifiableCredential[0].dcsProof[1].signature
    consumerSignature = signedCredential.verifiableCredential.dcsProof[1].signature
  }
  //signedCredential.verifiableCredential[0].dcsProof.pop()
  signedCredential.verifiableCredential.dcsProof.pop()
  //validate consumer
  var consumerValid = ""
  if(!providerOnly){
  const consumerData = Buffer.from(JSON.stringify(signedCredential));
  consumerValid = await verify({data:consumerData, signature: Buffer.from(consumerSignature,'hex') });
  }
  //validate provider
  //delete signedCredential.verifiableCredential[0].dcsProof
  delete signedCredential.verifiableCredential.dcsProof
  const providerData = Buffer.from(JSON.stringify(signedCredential));
  const providerValid = await verify({data:providerData, signature: Buffer.from(providerSignature,'hex') });

  return {
    providerValid : providerValid,
    consumerValid : consumerValid
  };
}
//Sign the contract by the federation
app.post('/finalize', jsonParser ,async function (req, res) {

  var jsonld = JSON.parse(JSON.stringify(req.body))
  const sdValidation = await selfDescriptionVerification(jsonld)
  if(sdValidation.valid){
    const participantValidation = await validateParticipant(jsonld)

    if( participantValidation.providerValid && participantValidation.consumerValid){
      const {sign} = keyPair.signer();

      const data = Buffer.from(JSON.stringify(jsonld));
      const signatureValue = await sign({data});
      const date = new Date();
      const proof ={
                    type: "Ed25519Signature2018",
                    created: date.toISOString(),
                    verificationMethod: "did:dcs:key:123",
                    proofPurpose: "assertionMethod",
                    signature: signatureValue.toString('hex')
      }
      jsonld.dcsProof = proof
      res.json(jsonld)
    }else{
      res.json({error : "Invalid Participant(s) Signature",details : participantValidation})
    }}else{
      res.json({validationResult:sdValidation.valid,error:"Invalid Self-description signature"});
    }

})