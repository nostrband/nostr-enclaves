import { Event, nip19, validateEvent, verifyEvent } from "nostr-tools";
import { decode, encode } from "cbor2";
import { bytesToHex } from "@noble/hashes/utils";
import { sha384 } from "@noble/hashes/sha2";
import { X509Certificate, X509ChainBuilder } from "@peculiar/x509";
import { base64ToUint8Array } from "./base64-utils";
import { getCrypto, getSubtleCrypto } from "./crypto-utils";

// download from https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
export const AWS_ROOT_CERT =
  "MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEGBSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZEh8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkFR+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYCMQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPWrfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6NIwLz3/Y=";

export const KIND_ANNOUNCEMENT = 13793;
export const KIND_ANNOUNCEMENT_OLD = 63793;

export const KIND_ROOT_CERT = 23793;
export const KIND_CERT = 23797;

export const KIND_BUILD_SIGNATURE = 23794;
export const KIND_INSTANCE_SIGNATURE = 23795;
export const KIND_RELEASE_SIGNATURE = 63794;

export const KIND_BUILD_SIGNATURE_OLD = 63795;
export const KIND_INSTANCE_SIGNATURE_OLD = 63796;
export const KIND_RELEASE_SIGNATURE_OLD = 63792;

export interface AttestationData {
  public_key: Uint8Array;
  certificate: Uint8Array;
  cabundle: Uint8Array[];
  pcrs: Map<number, Uint8Array>;
}

function now() {
  return Math.floor(Date.now() / 1000);
}

export function tv(e: Event, name: string) {
  return e.tags.find((t) => t.length > 1 && t[0] === name)?.[1];
}

export function pcrDigest(data: Buffer | Uint8Array | string) {
  return bytesToHex(
    sha384
      .create()
      // https://github.com/aws/aws-nitro-enclaves-cli/issues/446#issuecomment-1460766038
      // > The PCR registers start in a known zero state and each extend operation does a hash between the previous state and the data.
      .update(new Uint8Array(384 / 8))
      .update(data)
      .digest()
  );
}

interface CoseHeader {
  get(key: number): number;
  // add other required properties
}

export class Validator {
  private allowExpired?: boolean;
  private printLogs?: boolean;
  private expectedPcrs?: Map<number, Uint8Array>;
  private expectedRelease?: {
    ref: string;
    signerPubkeys: string[];
  };

  constructor(
    opts: {
      allowExpired?: boolean;
      printLogs?: boolean;
      expectedPcrs?: Map<number, Uint8Array>;
      expectedRelease?: {
        ref: string;
        signerPubkeys: string[];
      };
    } = {}
  ) {
    this.allowExpired = opts.allowExpired;
    this.printLogs = opts.printLogs;
    this.expectedPcrs = opts.expectedPcrs;
    this.expectedRelease = opts.expectedRelease;
  }

  public async validateBuildCert(
    certData: string,
    pubkey: string,
    pcr8: string
  ) {
    if (!certData || !pubkey || !pcr8) {
      throw new Error("Missing required parameters");
    }

    if (!certData.startsWith("--")) {
      certData =
        "-----BEGIN CERTIFICATE-----\n" +
        certData +
        "\n-----END CERTIFICATE-----\n";
    }
    const pemCertRegex =
      /^-----BEGIN CERTIFICATE-----\n([a-zA-Z0-9+/=\n]+)-----END CERTIFICATE-----$/m;
    if (!pemCertRegex.test(certData)) {
      throw new Error("Invalid certificate data format");
    }

    const cert = new X509Certificate(certData);
    // console.log("cert", cert);
    if (!cert.isSelfSigned()) throw new Error("Cert not self-signed");
    if (
      !(await cert.verify({
        signatureOnly: !!this.allowExpired,
      }))
    )
      throw new Error("Invalid cert signature");

    // helper
    const getField = (name: string) => {
      return cert.issuer
        .split(",")
        .map((s) => s.trim())
        .find((s) => s.startsWith(name + "="))
        ?.split("=")[1];
    };

    const O = getField("O");
    if (O !== "Nostr") throw new Error("Cert not for Nostr");

    const OU = getField("OU"); // deprecated, remove later
    const CN = getField("CN");
    const npub = nip19.npubEncode(pubkey);
    if (OU !== npub && CN !== npub) throw new Error("Wrong cert pubkey");

    // pcr8 validation https://github.com/aws/aws-nitro-enclaves-cli/issues/446#issuecomment-1460766038
    const fingerprint = sha384(new Uint8Array(cert.rawData));
    const certPCR8 = pcrDigest(fingerprint);
    // console.log("certPCR8", certPCR8);
    if (certPCR8 !== pcr8) throw new Error("Invalid cert PCR8");
  }

  public async verifyBuildSignature(att: AttestationData, build: Event) {
    const enclavePCR8 = bytesToHex(att.pcrs.get(8) || new Uint8Array());
    if (!enclavePCR8) throw new Error("Bad attestation, no PCR8");
    // console.log("enclavePCR8", enclavePCR8);
    const buildPCR8 = tv(build, "PCR8");
    if (!buildPCR8) throw new Error("No PCR8 in build");
    if (enclavePCR8 !== buildPCR8) throw new Error("No matching PCR8");

    // it's not enough to just match pcr8 bcs this value is static
    // in a build and anyone can observe it after an instance is
    // launched and can commit to it by themselves and launch a new
    // instance of this build as if they built it. so we have to
    // actually check that buildCert matches pcr8 and check that buildCert
    // content points to the build.pubkey
    const buildCert = tv(build, "cert");
    if (!buildCert) throw new Error("No cert in build");

    // validate the cert is for build.pubkey and produces the expected pcr8
    await this.validateBuildCert(buildCert, build.pubkey, enclavePCR8);
  }

  public async verifyInstanceSignature(att: AttestationData, instance: Event) {
    const enclavePCR4 = bytesToHex(att.pcrs.get(4) || new Uint8Array());
    if (!enclavePCR4) throw new Error("Bad attestation, no PCR4");
    // console.log("enclavePCR4", enclavePCR4);
    const instancePCR4 = tv(instance, "PCR4");
    if (!instancePCR4) throw new Error("No PCR4 in instance");
    // console.log("instancePCR4", instancePCR4);
    if (instancePCR4 !== enclavePCR4) throw new Error("No matching PCR4");
  }

  public async verifyReleaseSignature(att: AttestationData, instance: Event) {
    for (const i of [0, 1, 2]) {
      const enclavePCR = bytesToHex(att.pcrs.get(i) || new Uint8Array());
      if (!enclavePCR) throw new Error("Bad attestation, no PCR" + i);
      const instancePCR = instance.tags.find(
        (t) => t.length > 2 && t[0] === "x" && t[2] === "PCR" + i
      )?.[1] || tv(instance, "PCR"+i); // PCRx tags are deprecated, use 'x' only
      if (!instancePCR) throw new Error(`No PCR${i} in instance`);
      if (instancePCR !== enclavePCR) throw new Error("No matching PCR" + i);
    }
  }

  private fromBase64(base64: string): Uint8Array {
    return base64ToUint8Array(base64);
  }

  public async parseValidateAttestation(attestation: string, pubkey?: string) {
    if (attestation.length > 10000) throw new Error("Attestation size too big");

    // NOTE: based on https://aws.amazon.com/blogs/compute/validating-attestation-documents-produced-by-aws-nitro-enclaves/

    // parse attestation content
    const arr = this.fromBase64(attestation);
    const COSE_Sign1 = decode(arr);
    // console.log(COSE_Sign1);

    // COSE_Sign1 object is an array of size 4 (protected headers, un protected headers, payload, and signature)
    if (!Array.isArray(COSE_Sign1) || COSE_Sign1.length !== 4)
      throw new Error("Bad attestation");

    // header size
    if (COSE_Sign1[0].length !== 4) throw new Error("Bad attestation header");
    const ad_pheader = COSE_Sign1[0];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const header = decode(ad_pheader) as CoseHeader;
    // console.log("header", header);
    if (!header) throw new Error("Invalid header");

    // should be negative 35 as it maps to the P-384 curve that Nitro Enclaves use
    if (header.get(1) !== -35) throw new Error("Bad header");

    const unheader = COSE_Sign1[1];
    // AWS Nitro Enclaves do not use unprotected headers. Therefore, the expected is a Type 5 (map) with zero items
    if (typeof unheader !== "object" || Object.keys(unheader).length)
      throw new Error("Bad unprotected header");

    const signature = COSE_Sign1[3];
    // console.log("signature", signature);
    // The signature has to be a Type 2 (raw bytes) of exactly 96 bytes
    if (signature.length !== 96) throw new Error("Bad signature");

    const ad_signed = COSE_Sign1[2];
    const payload = decode(ad_signed) as AttestationData;
    if (this.printLogs) console.log("payload", payload);
    if (!payload) throw new Error("Invalid payload");

    // must match event pubkey
    if (pubkey) {
      const public_key = bytesToHex(payload.public_key);
      // console.log("public_key", public_key);
      if (public_key !== pubkey)
        throw new Error("Wrong pubkey certified by attestation");
    }

    // now check that cert presented by our enclave is valid
    const cert = new X509Certificate(payload.certificate);
    if (this.printLogs) console.log("cert", cert);

    const root = new X509Certificate(AWS_ROOT_CERT);
    // console.log("root", root);

    // take root from external known good file
    const certificates = [root];
    // Skip the first one [0] as that is the Root CA and we want to read it from an external source
    const MAX_CERT_BUNDLE_SIZE = 20; // adjust as needed
    if (payload.cabundle.length > MAX_CERT_BUNDLE_SIZE) {
      throw new Error("Certificate bundle too large");
    }
    for (let i = 0; i < payload.cabundle.length; i++) {
      certificates.push(new X509Certificate(payload.cabundle[i]));
    }
    // console.log("cabundle", certificates);

    // build a verified chain of certificates starting
    // with our attestation cert and ending on the known root
    const builder = new X509ChainBuilder({
      certificates,
    });
    const chain = await builder.build(cert);
    // console.log("chain", chain);
    if (chain[0].serialNumber !== cert.serialNumber)
      throw new Error("Invalid cert chain");
    if (chain[chain.length - 1].serialNumber !== root.serialNumber)
      throw new Error("Invalid cert chain root");

    // verify signer pubkeys and timestamps
    const signatureOnly = !!this.allowExpired;
    for (let i = 0; i < chain.length; i++) {
      const c = chain[i];
      // next cert is signer of current key, last cert (root) is self-signed
      const publicKey =
        i < chain.length - 1 ? chain[i + 1].publicKey : undefined;
      if (!(await c.verify({ publicKey, signatureOnly })))
        throw new Error("Cert expired or invalid");
    }

    // now check that attestation was signed by the public key
    // of the certificate
    const algorithm = {
      ...cert.publicKey.algorithm,
      ...cert.signatureAlgorithm,
    };
    const publicKey = await cert.publicKey.export(
      algorithm,
      ["verify"],
      await getCrypto()
    );
    // console.log("publicKey", publicKey, algorithm);

    // Recreate COSE_Sign1 structure, and serilise it into a buffer
    // cbor_item_t * cose_sig_arr = cbor_new_definite_array(4);
    const cose_sig_arr = [];
    // cbor_item_t * cose_sig_arr_0_sig1 = cbor_build_string("Signature1");
    const sig_header = "Signature1";
    // cbor_item_t * cose_sig_arr_2_empty = cbor_build_bytestring(NULL, 0);
    const empty_array = new Uint8Array();

    // assert(cbor_array_push(cose_sig_arr, cose_sig_arr_0_sig1));
    cose_sig_arr.push(sig_header);
    // assert(cbor_array_push(cose_sig_arr, ad_pheader));
    cose_sig_arr.push(ad_pheader);
    // assert(cbor_array_push(cose_sig_arr, cose_sig_arr_2_empty));
    cose_sig_arr.push(empty_array);
    // assert(cbor_array_push(cose_sig_arr, ad_signed));
    cose_sig_arr.push(ad_signed);
    // console.log("cose_sig_arr", cose_sig_arr);

    // unsigned char sig_struct_buffer[SIG_STRUCTURE_BUFFER_S];
    // size_t sig_struct_buffer_len = cbor_serialize(cose_sig_arr, sig_struct_buffer, SIG_STRUCTURE_BUFFER_S);
    const sig_struct_buffer = encode(cose_sig_arr);
    // console.log("sig_struct_buffer", sig_struct_buffer);

    // verify signature
    const ok = await (
      await getSubtleCrypto()
    ).verify(cert.signatureAlgorithm, publicKey, signature, sig_struct_buffer);
    // console.log("signature ok", ok);
    if (!ok) throw new Error("Invalid attestation signature");

    return payload;
  }

  private getCertTarget(cert: Event) {
    if (cert.kind === KIND_ROOT_CERT) return cert.pubkey;
    if (cert.kind !== KIND_CERT) throw new Error("Invalid cert kind");
    const pTags = cert.tags
      .filter((t) => t.length > 1 && t[0] === "p")
      .map((t) => t[1]);
    if (pTags.length !== 1)
      throw new Error("Exactly one pubkey required in cert");
    return pTags[0];
  }

  public async parseValidateRootCertAttestation(cert: Event) {
    if (cert.kind !== KIND_ROOT_CERT) throw new Error("Invalid root cert kind");
    if (!validateEvent(cert) || !verifyEvent(cert))
      throw new Error("Invalid root cert event");
    return await this.parseValidateAttestation(cert.content, cert.pubkey);
  }

  public async validateCert(cert: Event, pubkey: string) {
    if (cert.kind !== KIND_CERT) throw new Error("Invalid cert kind");
    if (!validateEvent(cert) || !verifyEvent(cert))
      throw new Error("Invalid cert event");
    if (this.getCertTarget(cert) !== pubkey)
      throw new Error("Wrong cert chain");
  }

  public async validateRootCert(cert: Event, pubkey: string) {
    if (cert.pubkey !== pubkey) throw new Error("Wrong root pubkey");
    await this.parseValidateRootCertAttestation(cert);
  }

  // Returns:
  // - 'true' if instance is valid AND matches the expectations.
  // - 'false' if info is valid but doesn't match the expectations.
  // Throws error if info is invalid.
  public async validateInstance(e: Event): Promise<boolean> {
    if (e.kind !== KIND_ANNOUNCEMENT && e.kind !== KIND_ANNOUNCEMENT_OLD)
      throw new Error("Invalid instance event kind");
    if (!validateEvent(e) || !verifyEvent(e))
      throw new Error("Invalid instance event");

    // attestation used to be in the content field, moved to tee_root tag
    const teeRootTag = e.tags.find(
      (t) => t.length > 1 && t[0] === "tee_root"
    )?.[1];
    const payload = teeRootTag
      ? await this.parseValidateRootCertAttestation(JSON.parse(teeRootTag))
      : await this.parseValidateAttestation(e.content, e.pubkey);

    // check expected image
    if (this.expectedPcrs) {
      for (const [k, a] of this.expectedPcrs.entries()) {
        const expected = bytesToHex(a);
        const pcr = bytesToHex(payload.pcrs.get(k) || new Uint8Array());
        if (this.printLogs) console.log("pcr", k, pcr, expected);
        if (pcr !== expected) {
          console.log(`wrong pcr ${k}:${pcr} expected ${expected}`);
          return false;
        }
      }
    }

    // verify the instance info
    const instance = tv(e, "instance");
    if (instance) {
      const ie = JSON.parse(instance);
      if (
        ie.kind !== KIND_INSTANCE_SIGNATURE &&
        ie.kind !== KIND_INSTANCE_SIGNATURE_OLD
      )
        throw new Error("Invalid instance signature event kind");
      if (!validateEvent(ie) || !verifyEvent(ie))
        throw new Error("Invalid instance signature");
      await this.verifyInstanceSignature(payload, ie);
    }

    // verify the build info
    const build = tv(e, "build");
    if (build) {
      const be = JSON.parse(build);
      if (
        be.kind !== KIND_BUILD_SIGNATURE &&
        be.kind !== KIND_BUILD_SIGNATURE_OLD
      )
        throw new Error("Invalid build signature event kind");
      if (!validateEvent(be) || !verifyEvent(be))
        throw new Error("Invalid build signature");
      await this.verifyBuildSignature(payload, be);
    }

    // verify the release signatures
    const releaseData: { ref: string; pubkey: string }[] = [];
    const releases = e.tags
      .filter((t) => t.length > 1 && t[0] === "release")
      .map((t) => t[1]);
    if (releases.length) {
      for (const release of releases) {
        const re = JSON.parse(release) as Event;
        if (
          re.kind !== KIND_RELEASE_SIGNATURE &&
          re.kind !== KIND_RELEASE_SIGNATURE_OLD
        )
          throw new Error("Invalid release signature event kind");
        if (!validateEvent(re) || !verifyEvent(re))
          throw new Error("Invalid release signature");
        await this.verifyReleaseSignature(payload, re);

        releaseData.push({
          ref: tv(re, "r") || "",
          pubkey: re.pubkey,
        });
      }
    }

    // check release expectations
    if (this.expectedRelease) {
      if (!releaseData.length) {
        console.log("No release data");
        return false;
      }

      // expected ref must match in all release signatures
      if (releaseData.find((d) => d.ref !== this.expectedRelease!.ref)) {
        console.log("Wrong release ref");
        return false;
      }

      // all expected pubkeys' release signatures must be present
      for (const p of this.expectedRelease.signerPubkeys) {
        if (!releaseData.find((d) => d.pubkey === p)) {
          console.log("Release signature not found for pubkey");
          return false;
        }
      }
    }

    return true;
  }

  public async validateEnclavedEvent(e: Event) {
    if (!validateEvent(e) || !verifyEvent(e)) throw new Error("Invalid event");

    // at least root must be present
    const rootTag = e.tags.find(
      (t) => t.length > 1 && t[0] === "tee_root"
    )?.[1];
    if (!rootTag) throw new Error("No tee_root tag");

    // certs are present if e.pubkey !== root.pubkey
    const certTags = e.tags
      .filter((t) => t.length > 1 && t[0] === "tee_cert")
      .map((t) => t[1]);

    // parse events
    const root = JSON.parse(rootTag) as Event;
    // certs must be ordered properly from root to leaf
    const certs = certTags.map((c) => JSON.parse(c) as Event);

    // fast kind check
    if (root.kind !== KIND_ROOT_CERT) throw new Error("Wrong root cert kind");

    // helpers
    const checkCertPubkey = (cert: Event, pubkey: string) => {
      const targetPubkey = this.getCertTarget(cert);
      if (targetPubkey !== pubkey) throw new Error("Broken pubkey chain");
      if (!this.allowExpired) {
        const expiration = parseInt(tv(cert, "expiration") || "0");
        if (expiration < now()) throw new Error("Cert expired");
      }
    };
    const getPrevCert = (i: number) => {
      return i ? certs[i - 1] : root;
    };

    // check refs first to exit faster on failure,
    // root_cert is attested by AWS,
    // and then first cert is by root_cert.pubkey linking to the
    // next cert, with last cert linking to e.pubkey
    for (let i = 0; i < certs.length; i++) {
      const cert = certs[i];
      if (cert.kind !== KIND_CERT) throw new Error("Wrong cert kind");

      // prev cert (or root) signs the current cert's pubkey
      checkCertPubkey(getPrevCert(i), cert.pubkey);
    }
    // last cert/root signs the event's pubkey
    checkCertPubkey(getPrevCert(certs.length), e.pubkey);

    // now that chain seems fine do real validation
    await this.parseValidateRootCertAttestation(root);

    // validate i'th pubkey against i-1'th cert
    const validate = async (i: number, pubkey: string) => {
      if (i) {
        await this.validateCert(certs[i - 1], pubkey);
      } else {
        await this.validateRootCert(root, pubkey);
      }
    };

    // loop over certs if any
    for (let i = 0; i < certs.length; i++) {
      const cert = certs[i];
      await validate(i, cert.pubkey);
    }
    // last cert signs the event's pubkey
    await validate(certs.length, e.pubkey);
  }
}
