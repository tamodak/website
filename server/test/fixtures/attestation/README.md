# Real attestation chains

Certificate chains produced by real phones, with the key descriptions Google parsed from them.
They are copied unchanged from the `testdata/` directory of
[android/keyattestation](https://github.com/android/keyattestation) (Apache License 2.0, see
`LICENSE.keyattestation`), fetched on 2026-10-05. File names are the source paths with `/` replaced
by `_`.

`realChains.test.ts` checks the server's verifier against them. Together they cover:

| Files | What they exercise |
|---|---|
| `walleye_sdk27`, `sony-xperia10-iii_sdk33` | Factory-provisioned chains whose certificates expired in May 2026, which must still verify |
| `blueline_sdk28` | A factory chain from Android 9 (Keymaster 4) |
| `akita_sdk34`, `caiman_sdk36_*` | Remote key provisioning (Droid CA2 / CA3) under the RSA root, TEE and StrongBox |
| `tegu_sdk36_*`, `frankel_sdk37` | RKP chains under the ECDSA P-384 root introduced in 2026 |
| `marlin_sdk29` | A software attestation root, which production must refuse |

The chains hold only public certificates. They attest Google's own test apps, not Killit, so the
tests set the expected package and signing digest from each `.json` file.
