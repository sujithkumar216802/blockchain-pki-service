const { PublicKeyInfo, CertificationRequest, AttributeTypeAndValue, setEngine, CryptoEngine, Certificate, Extension, BasicConstraints, AuthorityKeyIdentifier } = require('pkijs');
const { PrintableString, fromBER, Integer, OctetString } = require('asn1js');
const { generateKeyPairSync, createPublicKey, createPrivateKey, createHash, webcrypto, subtle } = require('crypto');
const { arrayBufferToString, toBase64, stringToArrayBuffer, fromBase64 } = require('pvutils');
const express = require('express');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.get('/', (req, res) => {
    res.send('Hello World!');
});

const index = {
    "subject": {
        "commonName": 0,
        "organization": 1,
        "locality": 2,
        "state": 3,
        "country": 4,
    },
    "issuer": {
        "commonName": 5,
        "organization": 6,
        "locality": 7,
        "state": 8,
        "country": 9,
    },
    "validity": {
        "notBefore": 10,
        "notAfter": 11,
    },
    "subjectAltName": {
        "dnsNames": 12,
        "ipAddresses": 13,
        "emailAddresses": 14,
        "uris": 15,
    },
    "publicKeyInfo": {
        "algorithm": 16,
        "keySize": 17,
        "publicKey": 18
    },
    "miscellaneous": {
        "version": 19,
        "serialNumber": 20,
        "signatureAlgorithm": 21,
    },
    "fingerprints": {
        "sha1": 22,
        "_sha256": 23,
    },
    "basicConstraints": {
        "isCA": 24,
        "pathLenConstraint": 25,
    },
    "extensions": {
        "subjectWalletAddress": 26,
        "issuerContractAddress": 27,
        "blockchainName": 28,
        "contractAddress": 29,
    },
    "subjectKeyIdentifier": 30,
    "authorityKeyIdentifier": 31,
    "signature": 32,
}

function formatPEM(pemString) {
    return pemString.match(/.{1,64}/g).join('\n');
}

function hexStringToArrayBuffer(hexString) {
    // remove the leading 0x
    hexString = hexString.replace(/^0x/, '');

    // Remove any spaces or non-hex characters from the string
    hexString = hexString.replace(/[^0-9a-fA-F]/g, '');

    // If the length of the string is odd, add a leading zero
    if (hexString.length % 2 !== 0) {
        hexString = '0' + hexString;
    }

    // Convert the hex string to an array of bytes
    const bytes = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < hexString.length; i += 2) {
        bytes[i / 2] = parseInt(hexString.substr(i, 2), 16);
    }

    // Return the bytes as an ArrayBuffer
    return bytes;
}

app.post('/generateKeys', async (req, res) => {
    const { password } = req.body;
    const { publicKey, privateKey } = generateKeys(password);
    res.send({ publicKey, privateKey });
});
app.post('/generateCSR', async (req, res) => {
    const { cert, publicKey, privateKey, password } = req.body;
    const csr = await generateCSR(JSON.parse(cert.toString()), publicKey, privateKey, password);
    res.send({ csr });
});
app.post('/issueCertificate', async (req, res) => {
    const { issuer, subject, issuerPrivateKey, password } = req.body;
    const { pem, signature, subjectKey } = await issueCertificate(JSON.parse(issuer), JSON.parse(subject), issuerPrivateKey, password);
    res.send({ pem, signature, subjectKey });
});
app.post('/issueCertificateFromCSR', async (req, res) => {
    const { issuer, subjectCSR, issuerPrivateKey, password, subjectWalletAddress, contractAddress, serialNumber } = req.body;
    const { pem, signature, subjectKey } = await issueCertificateFromCSR(JSON.parse(issuer), subjectCSR, issuerPrivateKey, password, subjectWalletAddress, contractAddress, serialNumber);
    res.send({ pem, signature, subjectKey });
});


function generateKeys(password) {
    const { publicKey, privateKey } = generateKeyPairSync('ec', {
        namedCurve: 'P-256',
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
            cipher: 'aes-256-cbc',
            passphrase: password
        }
    });

    return { publicKey, privateKey };
}

async function generateCSR(cert, requesterPublicKey, requesterPrivateKey, password) {
    const csr = new CertificationRequest();

    csr.version = 0;
    csr.subject.typesAndValues.push(new AttributeTypeAndValue({
        type: "2.5.4.6", // Country name
        value: new PrintableString({ value: cert[index['subject']['country']] })
    }));

    csr.subject.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.7', //localityName
        value: new PrintableString({ value: cert[index['subject']['locality']] })
    }));

    csr.subject.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.8', //stateOrProvinceName
        value: new PrintableString({ value: cert[index['subject']['state']] })
    }));

    csr.subject.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.10', //organizationName
        value: new PrintableString({ value: cert[index['subject']['organization']] })
    }));

    csr.subject.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.3', //commonName
        value: new PrintableString({ value: cert[index['subject']['commonName']] })
    }));

    // Set the public key in the CSR
    const berPublicKey = createPublicKey(requesterPublicKey).export({ type: 'spki', format: 'der' });
    const asn1 = fromBER(berPublicKey);
    const pubKey = new PublicKeyInfo({ schema: asn1.result });
    csr.subjectPublicKeyInfo = pubKey;

    // await csr.subjectPublicKeyInfo.importKey(publicKey);
    const berPrivateKey = createPrivateKey({ key: requesterPrivateKey, type: 'pkcs8', format: 'pem', passphrase: password }).export({
        format: 'der',
        type: 'pkcs8',
    });
    setEngine('OpenSSL', webcrypto, new CryptoEngine({
        name: 'OpenSSL',
        crypto: webcrypto,
        subtle: webcrypto.subtle
    }));

    const cryptoPrivateKey = await subtle.importKey('pkcs8', berPrivateKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);

    await csr.sign(cryptoPrivateKey, 'SHA-256');

    return `-----BEGIN CERTIFICATE REQUEST-----\n${formatPEM(
        toBase64(
            arrayBufferToString(
                csr.toSchema().toBER(false)
            )
        )
    )}\n-----END CERTIFICATE REQUEST-----`;
}

async function issueCertificate(issuer, subject, issuerPrivateKey, password) {

    const certificate = new Certificate();
    certificate.version = 2;
    certificate.serialNumber = new Integer({ value: subject[index['miscellaneous']['serialNumber']] });

    certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.3', //commonName
        value: new PrintableString({ value: subject[index['subject']['commonName']] })
    }));

    certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
        type: "2.5.4.6", // Country name
        value: new PrintableString({ value: subject[index['subject']['country']] })
    }));

    certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.7', //localityName
        value: new PrintableString({ value: subject[index['subject']['locality']] })
    }));

    certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.8', //stateOrProvinceName
        value: new PrintableString({ value: subject[index['subject']['state']] })
    }));

    certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.10', //organizationName
        value: new PrintableString({ value: subject[index['subject']['organization']] })
    }));


    certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.3', //commonName
        value: new PrintableString({ value: issuer[index['subject']['commonName']] })
    }));

    certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
        type: "2.5.4.6", // Country name
        value: new PrintableString({ value: issuer[index['subject']['country']] })
    }));

    certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.7', //localityName
        value: new PrintableString({ value: issuer[index['subject']['locality']] })
    }));

    certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.8', //stateOrProvinceName
        value: new PrintableString({ value: issuer[index['subject']['state']] })
    }));

    certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.10', //organizationName
        value: new PrintableString({ value: issuer[index['subject']['organization']] })
    }));

    // Set the public key
    const berPublicKey = createPublicKey(subject[index['publicKeyInfo']['publicKey']]).export({ type: 'spki', format: 'der' });
    const asn1 = fromBER(berPublicKey);
    const pubKey = new PublicKeyInfo({ schema: asn1.result });
    certificate.subjectPublicKeyInfo = pubKey;

    // Set the validity period (1 year)
    const notBefore = new Date();
    const notAfter = new Date(notBefore);
    notAfter.setFullYear(notBefore.getFullYear() + 1);
    certificate.notBefore.value = notBefore;
    certificate.notAfter.value = notAfter;

    const basicConstr = new BasicConstraints({
        cA: true,
        pathLenConstraint: 3
    });
    certificate.extensions = [];
    certificate.extensions.push(new Extension({
        extnID: "2.5.29.19",
        critical: false,
        extnValue: basicConstr.toSchema().toBER(false),
        parsedValue: basicConstr // Parsed value for well-known extensions
    }));

    const subjectKeyIdentifier = createHash('sha1').update(subject[index['publicKeyInfo']['publicKey']]).digest();
    certificate.extensions.push(new Extension({
        extnID: "2.5.29.14",
        extnValue: new OctetString({ valueHex: subjectKeyIdentifier }).toBER(false),
    }));

    const authorityKeyIdentifier = createHash('sha1').update(issuer[index['publicKeyInfo']['publicKey']]).digest();

    if (authorityKeyIdentifier.toString() !== subjectKeyIdentifier.toString()) {
        certificate.extensions.push(new Extension({
            extnID: "2.5.29.35",
            extnValue: new AuthorityKeyIdentifier({
                keyIdentifier: new OctetString({ valueHex: authorityKeyIdentifier }),
            }).toSchema().toBER(false),
        }));
    }

    certificate.extensions.push(new Extension({
        extnID: "2.5.29.5000", // X509v3 Subject Wallet Address, the OID is not registered
        extnValue: new OctetString({ valueHex: hexStringToArrayBuffer(subject[index['extensions']['subjectWalletAddress']]) }).toBER(false),
    }));

    certificate.extensions.push(new Extension({
        extnID: "2.5.29.5001", // X509v3 Issuer Contract identifier, the OID is not registered
        extnValue: new OctetString({ valueHex: hexStringToArrayBuffer(issuer[index['extensions']['contractAddress']]) }).toBER(false),
    }));

    certificate.extensions.push(new Extension({
        extnID: "2.5.29.5002", // X509v3 Blockchain name, the OID is not registered
        extnValue: new PrintableString({ value: issuer[index['extensions']['blockchainName']] }).toBER(false),
    }));

    if (subject[index['basicConstraints']['isCA']] === 'true' && authorityKeyIdentifier.toString() !== subjectKeyIdentifier.toString()) {
        certificate.extensions.push(new Extension({
            extnID: "2.5.29.5003", // X509v3 Contract identifier, the OID is not registered
            extnValue: new OctetString({ valueHex: hexStringToArrayBuffer(subject[index['extensions']['contractAddress']]) }).toBER(false),
        }));
    }
    // Sign the certificate with the private key
    const berPrivateKey = createPrivateKey({ key: issuerPrivateKey, type: 'pkcs8', format: 'pem', passphrase: password }).export({
        format: 'der',
        type: 'pkcs8',
    });
    setEngine('OpenSSL', webcrypto, new CryptoEngine({
        name: 'OpenSSL',
        crypto: webcrypto,
        subtle: subtle
    }));

    const cryptoPrivateKey = await subtle.importKey('pkcs8', berPrivateKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);

    await certificate.sign(cryptoPrivateKey, 'SHA-256');

    const pem = `-----BEGIN CERTIFICATE-----\n${formatPEM(
        toBase64(
            arrayBufferToString(
                certificate.toSchema().toBER(false)
            )
        )
    )}\n-----END CERTIFICATE-----`;
    const signature = certificate.signatureValue.toString(16);
    const subjectKey = Buffer.from(subjectKeyIdentifier).toString('hex');

    return { pem, signature, subjectKey };
}

async function issueCertificateFromCSR(issuer, subjectCSR, issuerPrivateKey, password, subjectWalletAddress, contractAddress, serialNumber) {
    const berSubjectCSR = subjectCSR.replace(/-----BEGIN CERTIFICATE REQUEST-----/, '').replace(/-----END CERTIFICATE REQUEST-----/, '').replace(/\n/g, '');
    const derSubjectCSR = stringToArrayBuffer(fromBase64(berSubjectCSR));
    const asn1 = fromBER(derSubjectCSR);
    const cert = new CertificationRequest({ schema: asn1.result });
    const subjectCert = new Array(33);
    subjectCert[index['subject']['commonName']] = cert.subject.typesAndValues.find(typeAndValue => typeAndValue.type === '2.5.4.3').value.valueBlock.value;
    subjectCert[index['subject']['country']] = cert.subject.typesAndValues.find(typeAndValue => typeAndValue.type === '2.5.4.6').value.valueBlock.value;
    subjectCert[index['subject']['locality']] = cert.subject.typesAndValues.find(typeAndValue => typeAndValue.type === '2.5.4.7').value.valueBlock.value;
    subjectCert[index['subject']['state']] = cert.subject.typesAndValues.find(typeAndValue => typeAndValue.type === '2.5.4.8').value.valueBlock.value;
    subjectCert[index['subject']['organization']] = cert.subject.typesAndValues.find(typeAndValue => typeAndValue.type === '2.5.4.10').value.valueBlock.value;
    subjectCert[index['publicKeyInfo']['publicKey']] = `-----BEGIN PUBLIC KEY-----\n${formatPEM(
        toBase64(
            arrayBufferToString(
                cert.subjectPublicKeyInfo.toSchema().toBER(false)
            )
        )
    )}\n-----END PUBLIC KEY-----`;
    subjectCert[index['miscellaneous']['serialNumber']] = serialNumber;
    subjectCert[index['extensions']['subjectWalletAddress']] = subjectWalletAddress;
    subjectCert[index['extensions']['contractAddress']] = contractAddress;
    return await issueCertificate(issuer, subjectCert, issuerPrivateKey, password);
}

module.exports = app;