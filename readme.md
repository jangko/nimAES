#**nimAES**
###Advanced Encryption Standard
####Rinjdael Algorithm written in Nim

example:

```nimrod
var aes = initAES()
let input = "0123456789ABCDEF"
let key = "FEDCBA9876543210"
if aes.setEncodeKey(key):
  let encrypted = aes.encryptECB(input)
  if aes.setDecodeKey(key):
    let decrypted = aes.decryptECB(encrypted)
    assert decrypted == input
```

both setEncodeKey and setDecodeKey accept 128, 192, and 256 bits key length

supported mode:

| MODE | Codec Pair | IV 16 bytes | IO | EncKey | DecKey |
|--------|------------|-------------|:----------:|--------|--------|
| ECB | yes | no | 1 block | yes | yes |
| CBC | yes | yes | n x blocks | yes | yes |
| CFB128 | yes | yes | n x blocks | yes | no |
| CFB8 | yes | yes | n x blocks | yes | no |
| CTR | no | yes | stream | yes | no |
| OFB | no | yes | n x blocks | yes | no |

output length always same with input length

1 block equal to 16 bytes

CTR mode accept arbitrary input length

IV = Initialization Vector

Codec Pair:

 - yes: have encrypt and decrypt
 - no: only one function both for encrypt and decrypt
