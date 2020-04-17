import ../nimAES, strutils

proc testECB() =
  var ctx: AESContext
  zeroMem(addr(ctx), sizeof(ctx))
  var key = "0123456789ABCDEF"
  var text = "hello there hone"
  assert ctx.setEncodeKey(key) == true

  var out1 = newString(16)
  var out3 = newString(16)
  var output1 = cstring(out1)
  var output3 = cstring(out3)
  ctx.encryptECB(cstring(text), output1)

  assert ctx.setDecodeKey(key) == true
  ctx.decryptECB(output1, output3)
  assert out3 == text

proc testCBC() =
  var ctx: AESContext
  zeroMem(addr(ctx), sizeof(ctx))
  var key = "0123456789ABCDEF"
  var text = "hello there hone0123456789ABCDEF"
  assert ctx.setEncodeKey(key) == true
  var ivs = repeat(chr(1), 16)
  var iv = cstring(ivs)
  var out1 = ctx.encryptCBC(iv, text)

  assert ctx.setDecodeKey(key) == true
  ivs = repeat(chr(1), 16)
  iv = cstring(ivs)
  var out2 = ctx.decryptCBC(iv, out1)
  assert out2 == text

proc testCFB128() =
  var ctx: AESContext
  zeroMem(addr(ctx), sizeof(ctx))
  var key = "0123456789ABCDEF"
  var text = "hello there hone0123456789ABCDEF"
  assert ctx.setEncodeKey(key) == true
  var ivs = repeat(chr(0), 16)
  var iv = cstring(ivs)
  var offset = 0
  var out1 = ctx.encryptCFB128(offset, iv, text)

  ivs = repeat(chr(0), 16)
  iv = cstring(ivs)
  offset = 0
  var out2 = ctx.decryptCFB128(offset, iv, out1)
  assert out2 == text

proc testCFB8() =
  var ctx: AESContext
  zeroMem(addr(ctx), sizeof(ctx))
  var key = "0123456789ABCDEF"
  var text = "hello there hone0123456789ABCDEF"
  assert ctx.setEncodeKey(key) == true
  var ivs = repeat(chr(0), 16)
  var iv = cstring(ivs)
  var out1 = ctx.encryptCFB8(iv, text)

  ivs = repeat(chr(0), 16)
  iv = cstring(ivs)
  var out2 = ctx.decryptCFB8(iv, out1)
  assert out2 == text

proc testCTR() =
  var ctx: AESContext
  zeroMem(addr(ctx), sizeof(ctx))
  var key = "0123456789ABCDEF"
  var text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit."
  assert ctx.setEncodeKey(key) == true
  var offset = 0
  var counter: array[0..15, uint8]
  var nonce = cast[cstring](addr(counter[0]))
  zeroMem(addr(counter), sizeof(counter))
  var out1 = ctx.cryptCTR(offset, nonce, text)
  offset = 0
  zeroMem(addr(counter), sizeof(counter))
  var out2 = ctx.cryptCTR(offset, nonce, out1)
  assert out2 == text

proc testOFB() =
  var ctx: AESContext
  zeroMem(addr(ctx), sizeof(ctx))
  var key = "0123456789ABCDEF"
  var text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit."
  text.setLen((text.len div 16) * 16) # must be 16 bytes per block
  assert ctx.setEncodeKey(key) == true
  var counter: array[0..15, uint8]
  var nonce = cast[cstring](addr(counter[0]))
  zeroMem(addr(counter), sizeof(counter))
  var out1 = ctx.cryptOFB(nonce, text)
  zeroMem(addr(counter), sizeof(counter))
  var out2 = ctx.cryptOFB(nonce, out1)
  assert out2 == text

proc pHex(input: string): string =
  result = newString(input.len div 2)
  for i in 0..result.len-1:
    result[i] = chr(parseHexInt(input[i*2] & input[i*2 + 1]))

const
  ecb128key = "2b7e151628aed2a6abf7158809cf4f3c"

  ecb128vec = ["6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97",
    "ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf",
    "30c81c46a35ce411e5fbc1191a0a52ef", "43b1cd7f598ece23881b00e3ed030688",
    "f69f2445df4f9b17ad2b417be66c3710", "7b0c785e27e8ad3f8223207104725dd4"]

  ecb192key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"

  ecb192vec = ["6bc1bee22e409f96e93d7e117393172a", "bd334f1d6e45f25ff712a214571fa5cc",
    "ae2d8a571e03ac9c9eb76fac45af8e51", "974104846d0ad3ad7734ecb3ecee4eef",
    "30c81c46a35ce411e5fbc1191a0a52ef", "ef7afd2270e2e60adce0ba2face6444e",
    "f69f2445df4f9b17ad2b417be66c3710", "9a4b41ba738d6c72fb16691603c18e0e"]

  ecb256key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"

  ecb256vec = ["6bc1bee22e409f96e93d7e117393172a", "f3eed1bdb5d2a03c064b5a7e3db181f8",
    "ae2d8a571e03ac9c9eb76fac45af8e51", "591ccb10d410ed26dc5ba74a31362870",
    "30c81c46a35ce411e5fbc1191a0a52ef", "b6ed21b99ca6f4f9f153e7b1beafed1d",
    "f69f2445df4f9b17ad2b417be66c3710", "23304b7a39f9f3ff067d8d8f9e24ecc7"]

  cbc128key = "2b7e151628aed2a6abf7158809cf4f3c"
  cbc192key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
  cbc256key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"

  cbc128vec = ["000102030405060708090A0B0C0D0E0F", "6bc1bee22e409f96e93d7e117393172a", "7649abac8119b246cee98e9b12e9197d",
    "7649ABAC8119B246CEE98E9B12E9197D", "ae2d8a571e03ac9c9eb76fac45af8e51", "5086cb9b507219ee95db113a917678b2",
    "5086CB9B507219EE95DB113A917678B2", "30c81c46a35ce411e5fbc1191a0a52ef", "73bed6b8e3c1743b7116e69e22229516",
    "73BED6B8E3C1743B7116E69E22229516", "f69f2445df4f9b17ad2b417be66c3710", "3ff1caa1681fac09120eca307586e1a7"]

  cbc192vec = ["000102030405060708090A0B0C0D0E0F", "6bc1bee22e409f96e93d7e117393172a", "4f021db243bc633d7178183a9fa071e8",
    "4F021DB243BC633D7178183A9FA071E8", "ae2d8a571e03ac9c9eb76fac45af8e51", "b4d9ada9ad7dedf4e5e738763f69145a",
    "B4D9ADA9AD7DEDF4E5E738763F69145A", "30c81c46a35ce411e5fbc1191a0a52ef", "571b242012fb7ae07fa9baac3df102e0",
    "571B242012FB7AE07FA9BAAC3DF102E0", "f69f2445df4f9b17ad2b417be66c3710", "08b0e27988598881d920a9e64f5615cd"]

  cbc256vec = ["000102030405060708090A0B0C0D0E0F", "6bc1bee22e409f96e93d7e117393172a", "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
    "F58C4C04D6E5F1BA779EABFB5F7BFBD6", "ae2d8a571e03ac9c9eb76fac45af8e51", "9cfc4e967edb808d679f777bc6702c7d",
    "9CFC4E967EDB808D679F777BC6702C7D", "30c81c46a35ce411e5fbc1191a0a52ef", "39f23369a9d9bacfa530e26304231461",
    "39F23369A9D9BACFA530E26304231461", "f69f2445df4f9b17ad2b417be66c3710", "b2eb05e2c39be9fcda6c19078c6a9d1b"]

  ofb128key = "2b7e151628aed2a6abf7158809cf4f3c"
  ofb192key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
  ofb256key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"

  ofb128vec = ["000102030405060708090A0B0C0D0E0F", "6bc1bee22e409f96e93d7e117393172a", "3b3fd92eb72dad20333449f8e83cfb4a",
    "50FE67CC996D32B6DA0937E99BAFEC60", "ae2d8a571e03ac9c9eb76fac45af8e51", "7789508d16918f03f53c52dac54ed825",
    "D9A4DADA0892239F6B8B3D7680E15674", "30c81c46a35ce411e5fbc1191a0a52ef", "9740051e9c5fecf64344f7a82260edcc",
    "A78819583F0308E7A6BF36B1386ABF23", "f69f2445df4f9b17ad2b417be66c3710", "304c6528f659c77866a510d9c1d6ae5e"]

  ofb192vec = ["000102030405060708090A0B0C0D0E0F", "6bc1bee22e409f96e93d7e117393172a", "cdc80d6fddf18cab34c25909c99a4174",
    "A609B38DF3B1133DDDFF2718BA09565E", "ae2d8a571e03ac9c9eb76fac45af8e51", "fcc28b8d4c63837c09e81700c1100401",
    "52EF01DA52602FE0975F78AC84BF8A50", "30c81c46a35ce411e5fbc1191a0a52ef", "8d9a9aeac0f6596f559c6d4daf59a5f2",
    "BD5286AC63AABD7EB067AC54B553F71D", "f69f2445df4f9b17ad2b417be66c3710", "6d9f200857ca6c3e9cac524bd9acc92a"]

  ofb256vec = ["000102030405060708090A0B0C0D0E0F", "6bc1bee22e409f96e93d7e117393172a", "dc7e84bfda79164b7ecd8486985d3860",
    "B7BF3A5DF43989DD97F0FA97EBCE2F4A", "ae2d8a571e03ac9c9eb76fac45af8e51", "4febdc6740d20b3ac88f6ad82a4fb08d",
    "E1C656305ED1A7A6563805746FE03EDC", "30c81c46a35ce411e5fbc1191a0a52ef", "71ab47a086e86eedf39d1c5bba97c408",
    "41635BE625B48AFC1666DD42A09D96E7", "f69f2445df4f9b17ad2b417be66c3710", "0126141d67f37be8538f5a8be740e484"]

  cfb128_128key = "2b7e151628aed2a6abf7158809cf4f3c"
  cfb128_192key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
  cfb128_256key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"

  cfb128_128vec = ["000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172a", "3b3fd92eb72dad20333449f8e83cfb4a",
    "3B3FD92EB72DAD20333449F8E83CFB4A", "ae2d8a571e03ac9c9eb76fac45af8e51", "c8a64537a0b3a93fcde3cdad9f1ce58b",
    "C8A64537A0B3A93FCDE3CDAD9F1CE58B", "30c81c46a35ce411e5fbc1191a0a52ef", "26751f67a3cbb140b1808cf187a4f4df",
    "26751F67A3CBB140B1808CF187A4F4DF", "f69f2445df4f9b17ad2b417be66c3710", "c04b05357c5d1c0eeac4c66f9ff7f2e6"]

  cfb128_192vec = ["000102030405060708090A0B0C0D0E0F", "6bc1bee22e409f96e93d7e117393172a", "cdc80d6fddf18cab34c25909c99a4174",
    "CDC80D6FDDF18CAB34C25909C99A4174", "ae2d8a571e03ac9c9eb76fac45af8e51", "67ce7f7f81173621961a2b70171d3d7a",
    "67CE7F7F81173621961A2B70171D3D7A", "30c81c46a35ce411e5fbc1191a0a52ef", "2e1e8a1dd59b88b1c8e60fed1efac4c9",
    "2E1E8A1DD59B88B1C8E60FED1EFAC4C9", "f69f2445df4f9b17ad2b417be66c3710", "c05f9f9ca9834fa042ae8fba584b09ff"]

  cfb128_256vec = ["000102030405060708090A0B0C0D0E0F", "6bc1bee22e409f96e93d7e117393172a", "DC7E84BFDA79164B7ECD8486985D3860",
    "DC7E84BFDA79164B7ECD8486985D3860", "ae2d8a571e03ac9c9eb76fac45af8e51", "39ffed143b28b1c832113c6331e5407b",
    "39FFED143B28B1C832113C6331E5407B", "30c81c46a35ce411e5fbc1191a0a52ef", "df10132415e54b92a13ed0a8267ae2f9",
    "DF10132415E54B92A13ED0A8267AE2F9", "f69f2445df4f9b17ad2b417be66c3710", "75a385741ab9cef82031623d55b1e471"]

  ctr128key = "2b7e151628aed2a6abf7158809cf4f3c"
  ctr128iv  = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
  ctr192key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
  ctr192iv  = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
  ctr256key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
  ctr256iv  = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"

  ctr128vec = ["6bc1bee22e409f96e93d7e117393172a", "874d6191b620e3261bef6864990db6ce",
    "ae2d8a571e03ac9c9eb76fac45af8e51", "9806f66b7970fdff8617187bb9fffdff",
    "30c81c46a35ce411e5fbc1191a0a52ef", "5ae4df3edbd5d35e5b4f09020db03eab",
    "f69f2445df4f9b17ad2b417be66c3710", "1e031dda2fbe03d1792170a0f3009cee"]

  ctr192vec = ["6bc1bee22e409f96e93d7e117393172a", "1abc932417521ca24f2b0459fe7e6e0b",
    "ae2d8a571e03ac9c9eb76fac45af8e51", "090339ec0aa6faefd5ccc2c6f4ce8e94",
    "30c81c46a35ce411e5fbc1191a0a52ef", "1e36b26bd1ebc670d1bd1d665620abf7",
    "f69f2445df4f9b17ad2b417be66c3710", "4f78a7f6d29809585a97daec58c6b050"]

  ctr256vec = ["6bc1bee22e409f96e93d7e117393172a", "601ec313775789a5b7a7f504bbf3d228",
    "ae2d8a571e03ac9c9eb76fac45af8e51", "f443e3ca4d62b59aca84e990cacaf5c5",
    "30c81c46a35ce411e5fbc1191a0a52ef", "2b0930daa23de94ce87017ba2d84988d",
    "f69f2445df4f9b17ad2b417be66c3710", "dfc9c58db67aada613c2dd08457941a6"]

proc testECB(key: string, vec: openArray[string]) =
  var ctx: AESContext
  zeroMem(addr(ctx), sizeof(ctx))
  assert ctx.setEncodeKey(pHex(key)) == true

  var result = newString(16)
  var res = cstring(result)

  for i in 0..3:
    let input = pHex(vec[i*2])
    let output = pHex(vec[i*2+1])
    ctx.encryptECB(cstring(input), res)
    assert result == output

proc testCBC(key: string, vec: openArray[string]) =
  var ctx: AESContext
  zeroMem(addr(ctx), sizeof(ctx))
  assert ctx.setEncodeKey(pHex(key)) == true

  for i in 0..3:
    let ivs = pHex(vec[i*3])
    let input = pHex(vec[i*3+1])
    let output = pHex(vec[i*3+2])
    var iv = cstring(ivs)
    let result = ctx.encryptCBC(iv, input)
    assert result == output

proc testOFB(key: string, vec: openArray[string]) =
  var ctx: AESContext
  zeroMem(addr(ctx), sizeof(ctx))
  assert ctx.setEncodeKey(pHex(key)) == true

  for i in 0..3:
    let ivs = pHex(vec[i*3])
    let input = pHex(vec[i*3+1])
    let output = pHex(vec[i*3+2])
    var iv = cstring(ivs)
    let result = ctx.cryptOFB(iv, input)
    assert result == output

proc testCFB128(key: string, vec: openArray[string]) =
  var ctx: AESContext
  zeroMem(addr(ctx), sizeof(ctx))
  assert ctx.setEncodeKey(pHex(key)) == true

  for i in 0..3:
    let ivs = pHex(vec[i*3])
    let input = pHex(vec[i*3+1])
    let output = pHex(vec[i*3+2])
    var iv = cstring(ivs)
    var offset = 0
    let result = ctx.encryptCFB128(offset, iv, input)
    assert result == output

proc testCTR(key: string, ivc: string, vec: openArray[string]) =
  var ctx: AESContext
  zeroMem(addr(ctx), sizeof(ctx))
  assert ctx.setEncodeKey(pHex(key)) == true
  var ivs = pHex(ivc)
  var iv  = cstring(ivs)

  for i in 0..3:
    let input = pHex(vec[i*2])
    let output = pHex(vec[i*2+1])
    var offset = 0
    let result = ctx.cryptCTR(offset, iv, input)
    assert result == output

proc testECB2() =
  var aes = initAES()
  let input = "0123456789ABCDEF"
  let key = "FEDCBA9876543210"
  if aes.setEncodeKey(key):
    let encrypted = aes.encryptECB(input)
    if aes.setDecodeKey(key):
      let decrypted = aes.decryptECB(encrypted)
      echo decrypted.len
      echo decrypted
      assert decrypted == input

proc testCTR_offset() =
  var cipher = initAES()
  let key = "abcdefghijklmnop"
  discard cipher.setEncodeKey(key)

  let text = "Some text to show that there is no error."
  echo "Text -> ", text

  var offset: int = 0
  var nonce = "0123456701234567"
  var encrypted = cipher.cryptCTR(offset, nonce, text[0..20])
  encrypted &= cipher.cryptCTR(offset, nonce, text[21..text.high])
  echo "Encrypted -> ", encrypted
  offset = 0
  nonce = "0123456701234567"
  var decrypted = cipher.cryptCTR(offset, nonce, encrypted)
  echo "Decrypted -> ", decrypted
  assert decrypted == text

proc test() =
  testECB()
  testCBC()
  testCFB128()
  testCFB8()
  testCTR()
  testOFB()

  echo "ECBvector"
  testECB(ecb128key, ecb128vec)
  testECB(ecb192key, ecb192vec)
  testECB(ecb256key, ecb256vec)

  echo "CBCvector"
  testCBC(cbc128key, cbc128vec)
  testCBC(cbc192key, cbc192vec)
  testCBC(cbc256key, cbc256vec)

  echo "OFBvector"
  testOFB(ofb128key, ofb128vec)
  testOFB(ofb192key, ofb192vec)
  testOFB(ofb256key, ofb256vec)

  echo "CFB128vector"
  testCFB128(cfb128_128key, cfb128_128vec)
  testCFB128(cfb128_192key, cfb128_192vec)
  testCFB128(cfb128_256key, cfb128_256vec)

  echo "CTRvector"
  testCTR(ctr128key, ctr128iv, ctr128vec)
  testCTR(ctr192key, ctr192iv, ctr192vec)
  testCTR(ctr256key, ctr256iv, ctr256vec)

  testECB2()
  testCTR_offset()
  echo "OK"

test()
