import { Event, nip19, validateEvent, verifyEvent } from 'nostr-tools'
import { decode, encode } from 'cbor2'
import { bytesToHex } from '@noble/hashes/utils'
import { sha384 } from '@noble/hashes/sha2'
import { X509Certificate, X509ChainBuilder } from '@peculiar/x509'

interface AttestationData {
	public_key: Uint8Array
	certificate: Uint8Array
	cabundle: Uint8Array[]
	pcrs: Map<number, Uint8Array>
}

export function tv(e: Event, name: string) {
	return e.tags.find((t) => t.length > 1 && t[0] === name)?.[1]
}

export function pcrDigest(data: Buffer | Uint8Array | string) {
	return bytesToHex(
		sha384
			.create()
			// https://github.com/aws/aws-nitro-enclaves-cli/issues/446#issuecomment-1460766038
			// > The PCR registers start in a known zero state and each extend operation does a hash between the previous state and the data.
			.update(new Uint8Array(384 / 8))
			.update(data)
			.digest(),
	)
}

export function validateBuildCert(
	certData: string,
	pubkey: string,
	pcr8: string,
) {
	certData =
		'-----BEGIN CERTIFICATE-----\n' +
		certData +
		'\n-----END CERTIFICATE-----\n'
	const cert = new X509Certificate(certData)
	// console.log("cert", cert);
	if (!cert.isSelfSigned()) throw new Error('Cert not self-signed')
	const now = new Date()
	if (cert.notBefore > now || cert.notAfter < now)
		throw new Error('Cert expired')
	if (
		!cert.verify({
			publicKey: cert.publicKey,
		})
	)
		throw new Error('Invalid cert signature')
	const O = cert.issuer
		.split(',')
		.map((s) => s.trim())
		.find((s) => s.startsWith('O='))
		?.split('=')[1]
	if (O !== 'Nostr') throw new Error('Cert not for Nostr')
	const OU = cert.issuer
		.split(',')
		.map((s) => s.trim())
		.find((s) => s.startsWith('OU='))
		?.split('=')[1]
	const npub = nip19.npubEncode(pubkey)
	if (OU !== npub) throw new Error('Wrong cert pubkey')

	// pcr8 validation https://github.com/aws/aws-nitro-enclaves-cli/issues/446#issuecomment-1460766038
	const fingerprint = sha384(new Uint8Array(cert.rawData))
	const certPCR8 = pcrDigest(fingerprint)
	// console.log("certPCR8", certPCR8);
	if (certPCR8 !== pcr8) throw new Error('Invalid cert PCR8')
}

export function verifyBuildSignature(att: AttestationData, build: Event) {
	const enclavePCR8 = bytesToHex(att.pcrs.get(8) || new Uint8Array())
	if (!enclavePCR8) throw new Error('Bad attestation, no PCR8')
	// console.log("enclavePCR8", enclavePCR8);
	const buildPCR8 = build.tags.find(
		(t) => t.length > 1 && t[0] === 'PCR8',
	)?.[1]
	if (!buildPCR8) throw new Error('No PCR8 in build')
	if (enclavePCR8 !== buildPCR8) throw new Error('No matching PCR8')

	// it's not enough to just match pcr8 bcs this value is static
	// in a build and anyone can observe it after an instance is
	// launched and can commit to it by themselves and launch a new
	// instance of this build as if they built it. so we have to
	// actually check that buildCert matches pcr8 and check that buildCert
	// content points to the build.pubkey
	const buildCert = build.tags.find(
		(t) => t.length > 1 && t[0] === 'cert',
	)?.[1]
	if (!buildCert) throw new Error('No cert in build')

	// validate the cert is for build.pubkey and produces the expected pcr8
	validateBuildCert(buildCert, build.pubkey, enclavePCR8)
}

export function verifyInstanceSignature(att: AttestationData, instance: Event) {
	const enclavePCR4 = bytesToHex(att.pcrs.get(4) || new Uint8Array())
	if (!enclavePCR4) throw new Error('Bad attestation, no PCR4')
	// console.log("enclavePCR4", enclavePCR4);
	const instancePCR4 = instance.tags.find(
		(t) => t.length > 1 && t[0] === 'PCR4',
	)?.[1]
	if (!instancePCR4) throw new Error('No PCR4 in instance')
	// console.log("instancePCR4", instancePCR4);
	if (instancePCR4 !== enclavePCR4) throw new Error('No matching PCR4')
}

export async function validateInstance(e: Event) {
	// parse attestation content
	const binString = atob(e.content)
	const arr = Uint8Array.from(binString, (m) => m.codePointAt(0) as number)
	const COSE_Sign1 = decode(arr)
	// console.log(COSE_Sign1);

	// COSE_Sign1 object is an array of size 4 (protected headers, un protected headers, payload, and signature)
	if (!Array.isArray(COSE_Sign1) || COSE_Sign1.length !== 4)
		throw new Error('Bad attestation')

	// header size
	if (COSE_Sign1[0].length !== 4) throw new Error('Bad attestation')
	const ad_pheader = COSE_Sign1[0]
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const header: any = decode(ad_pheader)
	// console.log("header", header);
	if (!header) throw new Error('Invalid header')

	// should be negative 35 as it maps to the P-384 curve that Nitro Enclaves use
	if (header.get(1) !== -35) throw new Error('Bad header')

	const unheader = COSE_Sign1[1]
	// AWS Nitro Enclaves do not use unprotected headers. Therefore, the expected is a Type 5 (map) with zero items
	if (typeof unheader !== 'object' || Object.keys(unheader).length)
		throw new Error('Bad unprotected header')

	const signature = COSE_Sign1[3]
	// console.log("signature", signature);
	// The signature has to be a Type 2 (raw bytes) of exactly 96 bytes
	if (signature.length !== 96) throw new Error('Bad signature')

	const ad_signed = COSE_Sign1[2]
	const payload = decode(ad_signed) as AttestationData
	console.log('payload', payload)
	if (!payload) throw new Error('Invalid payload')

	// must match event pubkey
	const public_key = bytesToHex(payload.public_key)
	// console.log("public_key", public_key);
	if (public_key !== e.pubkey) throw new Error('Invalid pubkey')

	// now check that cert presented by our enclave is valid
	const cert = new X509Certificate(payload.certificate)
	console.log('cert', cert)

	// download from https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
	const rootBase64 =
		'MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEGBSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZEh8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkFR+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYCMQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPWrfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6NIwLz3/Y='
	const root = new X509Certificate(rootBase64)
	// console.log("root", root);

	// take root from external known good file
	const certificates = [root]
	// Skip the first one [0] as that is the Root CA and we want to read it from an external source
	for (let i = 1; i < payload.cabundle.length; i++) {
		certificates.push(new X509Certificate(payload.cabundle[i]))
	}
	// console.log("cabundle", certificates);

	// build a verified chain of certificates starting
	// with our attestation cert and ending on the known root
	const builder = new X509ChainBuilder({
		certificates,
	})
	const chain = await builder.build(cert)
	// console.log("chain", chain);
	if (chain[0].serialNumber !== cert.serialNumber)
		throw new Error('Invalid cert chain')
	if (chain[chain.length - 1].serialNumber !== root.serialNumber)
		throw new Error('Invalid cert chain root')

	// verify timestamps
	const signatureOnly = false
	for (const c of chain) {
		if (!c.verify({ signatureOnly }))
			throw new Error('Cert expired or invalid')
	}

	// now check that attestation was signed by the public key
	// of the certificate
	const algorithm = {
		...cert.publicKey.algorithm,
		...cert.signatureAlgorithm,
	}
	const publicKey = await cert.publicKey.export(algorithm, ['verify'], crypto)
	// console.log("publicKey", publicKey, algorithm);

	// Recreate COSE_Sign1 structure, and serilise it into a buffer
	// cbor_item_t * cose_sig_arr = cbor_new_definite_array(4);
	const cose_sig_arr = []
	// cbor_item_t * cose_sig_arr_0_sig1 = cbor_build_string("Signature1");
	const sig_header = 'Signature1'
	// cbor_item_t * cose_sig_arr_2_empty = cbor_build_bytestring(NULL, 0);
	const empty_array = new Uint8Array()

	// assert(cbor_array_push(cose_sig_arr, cose_sig_arr_0_sig1));
	cose_sig_arr.push(sig_header)
	// assert(cbor_array_push(cose_sig_arr, ad_pheader));
	cose_sig_arr.push(ad_pheader)
	// assert(cbor_array_push(cose_sig_arr, cose_sig_arr_2_empty));
	cose_sig_arr.push(empty_array)
	// assert(cbor_array_push(cose_sig_arr, ad_signed));
	cose_sig_arr.push(ad_signed)
	// console.log("cose_sig_arr", cose_sig_arr);

	// unsigned char sig_struct_buffer[SIG_STRUCTURE_BUFFER_S];
	// size_t sig_struct_buffer_len = cbor_serialize(cose_sig_arr, sig_struct_buffer, SIG_STRUCTURE_BUFFER_S);
	const sig_struct_buffer = encode(cose_sig_arr)
	// console.log("sig_struct_buffer", sig_struct_buffer);

	// verify signature
	const ok = await crypto.subtle.verify(
		cert.signatureAlgorithm,
		publicKey,
		signature,
		sig_struct_buffer,
	)
	// console.log("signature ok", ok);
	if (!ok) throw new Error('Invalid attestation signature')

	const instance = tv(e, 'instance')
	if (instance) {
		const ie = JSON.parse(instance)
		if (!validateEvent(ie) || !verifyEvent(ie))
			throw new Error('Invalid instance signature')
		verifyInstanceSignature(payload, ie)
	}
	const build = tv(e, 'build')
	if (build) {
		const be = JSON.parse(build)
		if (!validateEvent(be) || !verifyEvent(be))
			throw new Error('Invalid build signature')
		verifyBuildSignature(payload, be)
	}
}
