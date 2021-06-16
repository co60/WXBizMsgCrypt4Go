// MIT License
//
// Copyright (c) 2021 co60
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package WXBizMsgCrypt4Go

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestXMLParseGenerate(t *testing.T) {
	expect_xml := `<xml>
<Encrypt><![CDATA[msg_encrypt]]></Encrypt>
<MsgSignature><![CDATA[msg_signaturet]]></MsgSignature>
<TimeStamp>timestamp</TimeStamp>
<Nonce><![CDATA[nonce]]></Nonce>
</xml>`
	expect_xml = RemoveSurplusCharactorsInXmlOrJson(expect_xml)

	xmlParse := XMLParse{}
	resp_xml := xmlParse.generate("msg_encrypt", "msg_signaturet", "timestamp", "nonce")
	resp_xml = RemoveSurplusCharactorsInXmlOrJson(resp_xml)

	// t.Logf("\n%s\n%s\n", expect_xml, resp_xml)
	if resp_xml != expect_xml {
		t.Error("XMLParse generate xml error")
	}
}

func TestXMLParseExtract(t *testing.T) {
	xml_str := `<xml><ToUserName><![CDATA[gh_10f6c3c3ac5a]]></ToUserName>
<FromUserName><![CDATA[oyORnuP8q7ou2gfYjqLzSIWZf0rs]]></FromUserName>
<CreateTime>1409735668</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[abcdteT]]></Content>
<Encrypt><![CDATA[EncryptabcdteT]]></Encrypt>
<MsgId>6054768590064713728</MsgId>
</xml>`
	xmlParse := XMLParse{}
	encrypt, to_user, errcode := xmlParse.extract(xml_str)
	if errcode != WXBizMsgCrypt_OK {
		t.Errorf("%d\n", errcode)
	}
	// t.Logf("Encrypt: %s\nToUserName: %s\n", encrypt, to_user)
	if encrypt != "EncryptabcdteT" {
		t.Error("XMLParse extract ToUserName error")
	}
	if to_user != "gh_10f6c3c3ac5a" {
		t.Error("XMLParse extract Encrypt error")
	}
}

func TestPKCS7EncoderEncode(t *testing.T) {
	encoder := NewDefaultPKCS7Encoder()
	testbytes := []byte{23, 56, 87}
	testbytesLength := 3
	result := encoder.encode(testbytes)
	if testbytes[0] != result[0] || testbytes[1] != result[1] || testbytes[2] != result[2] {
		t.Error("PKCSEncoder encode error: false value")
	}
	if len(result)%encoder.BlockSize != 0 {
		t.Error("PKCSEncoder encode error: for padding block")
	}
	len := len(result)
	expect_pad_value := byte(encoder.BlockSize - testbytesLength)
	for i := testbytesLength; i < len-testbytesLength; i++ {
		if expect_pad_value != result[i] {
			t.Error("PKCSEncoder encode error: for padding value")
		}
	}
}

func TestPKCS7EncoderDecode(t *testing.T) {
	encoder := NewDefaultPKCS7Encoder()
	expectbytes := []byte{23, 56, 87}
	testbytes := [32]byte{} // 32 for encoder.BlockSize, while 29 for padding value for expectbytes
	for i := 0; i < 32; i++ {
		testbytes[i] = byte(29)
	}
	testbytes[0] = expectbytes[0]
	testbytes[1] = expectbytes[1]
	testbytes[2] = expectbytes[2]
	resultbytes := encoder.decode(testbytes[:])
	if expectbytes[0] != resultbytes[0] || expectbytes[1] != resultbytes[1] || expectbytes[2] != resultbytes[2] {
		t.Error("PKCSEncoder encode error: false value")
	}
}

func TestPrpcryptEncryptAndDecrypt(t *testing.T) {
	expect_data := `{
"ToUserName": "gh_bb2bb93f8347",
"FromUserName": "or5715HsCeFmycfU8gz0wx0sXfso",
"CreateTime": 1623398596,
"MsgType": "text",
"Content": "还是睡吧",
"MsgId": 23241477706429916
}`
	testbytes, _ := base64.StdEncoding.DecodeString("ipVu9915NKvK5ZRRXn9pkTF1FoOJF7nk1CEk8NJoudd" + "=")
	crypter := Prpcrypt{testbytes, AES_MODE_CBC}

	encrypted, errcode := crypter.encrypt(expect_data, "wx4ab900c96f6b0360")
	if errcode != WXBizMsgCrypt_OK {
		t.Error("Prpcrypt encrypt error: encrypt failed")
	}

	var decrypt string
	encrypted = "jG+iGb/r82M4jUBFYa/wuQHj+E4X/oddKjzAAwtlc49HC/xhAPq/Gm0gIXD3llPRnzVSonZGcjcUGOe5yh5HtTGAQexL1ZVJHlaLlBjXUVcxwLk6I7rQwjFMlenRyb4uOYgIm+qh946y5sHIUnziRpFo+3t8QcZTmR4EPs+0tJN+P9P9BWiSaMnFmJEywSgk8FH+nrEMPx30Y59qAOqtUfaxdoh4LJfTFsBF8gCuXjhpyixdIFbmUYOp3A1OWnfQNcLjzaBPglpeGgyuUByXb/Od++wFTnCugNuZruxk1As="
	decrypt, errcode = crypter.decrypt(encrypted, "wx4ab900c96f6b0360")
	if errcode != WXBizMsgCrypt_OK {
		t.Error("Prpcrypt decrypt error: encrypt failed")
	}
	t.Logf("\n%s\n", decrypt)

	expect_data = strings.Replace(expect_data, " ", "", -1)
	expect_data = strings.Replace(expect_data, "\n", "", -1)
	decrypt = strings.Replace(decrypt, " ", "", -1)
	decrypt = strings.Replace(decrypt, "\n", "", -1)
	if expect_data != decrypt {
		t.Error("Prpcrypt encrypt error: false encrypted data")
	}
}

func TestWXBizMsgCryptEncryptAndDecryptWithXml(t *testing.T) {
	encodingAESKey := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	to_xml := "<xml><ToUserName><![CDATA[oia2TjjewbmiOUlr6X-1crbLOvLw]]></ToUserName><FromUserName><![CDATA[gh_7f083739789a]]></FromUserName><CreateTime>1407743423</CreateTime><MsgType>  <![CDATA[video]]></MsgType><Video><MediaId><![CDATA[eYJ1MbwPRJtOvIEabaxHs7TX2D-HV71s79GUxqdUkjm6Gs2Ed1KF3ulAOA9H1xG0]]></MediaId><Title><![CDATA[testCallBackReplyVideo]]></Title><Descript  ion><![CDATA[testCallBackReplyVideo]]></Description></Video></xml>"
	token := "spamtest"
	nonce := "1320562132"
	appid := "wx2c2769f8efd9abc2"
	timestamp := "1409735669"
	msg_sign := "da92199ec168271c91d301577f90671fd3a7943e" // "5d197aaffba7e9b25a30732f161a50dee96bd5fa"
	encryp_test := NewDefaultWXBizMsgCrypt(token, encodingAESKey, appid)
	encrypt_xml, errcode := encryp_test.EncryptMsg(to_xml, nonce, timestamp)
	if errcode != WXBizMsgCrypt_OK {
		t.Error("WXBizMsgCrypt encrypt with xml error")
	}
	t.Logf("encrypt xml is:\n%s\n", encrypt_xml)

	// from_xml := "<xml><ToUserName><![CDATA[gh_10f6c3c3ac5a]]></ToUserName><FromUserName><![CDATA[oyORnuP8q7ou2gfYjqLzSIWZf0rs]]></FromUserName><CreateTime>1409735668</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[abcdteT]]></Content><MsgId>6054768590064713728</MsgId><Encrypt><![CDATA[hyzAe4OzmOMbd6TvGdIOO6uBmdJoD0Fk53REIHvxYtJlE2B655HuD0m8KUePWB3+LrPXo87wzQ1QLvbeUgmBM4x6F8PGHQHFVAFmOD2LdJF9FrXpbUAh0B5GIItb52sn896wVsMSHGuPE328HnRGBcrS7C41IzDWyWNlZkyyXwon8T332jisa+h6tEDYsVticbSnyU8dKOIbgU6ux5VTjg3yt+WGzjlpKn6NPhRjpA912xMezR4kw6KWwMrCVKSVCZciVGCgavjIQ6X8tCOp3yZbGpy0VxpAe+77TszTfRd5RJSVO/HTnifJpXgCSUdUue1v6h0EIBYYI1BD1DlD+C0CR8e6OewpusjZ4uBl9FyJvnhvQl+q5rv1ixrcpCumEPo5MJSgM9ehVsNPfUM669WuMyVWQLCzpu9GhglF2PE=]]></Encrypt></xml>"
	from_xml := encrypt_xml
	decrypt_test := NewDefaultWXBizMsgCrypt(token, encodingAESKey, appid)
	var decryp_xml string
	decryp_xml, errcode = decrypt_test.DecryptMsg(from_xml, msg_sign, timestamp, nonce)
	if errcode != WXBizMsgCrypt_ValidateSignatureError { // ignore signature validation :(
		t.Error("WXBizMsgCrypt decrypt with xml error")
	}
	t.Logf("decrypt xml is:\n%s\n", decryp_xml)
}

func TestWXBizMsgCryptEncryptAndDecryptWithJson(t *testing.T) {
	encodingAESKey := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	// in compacity mode (with Content... and Encrypt)
	to_json := `{
  "ToUserName":"gh_bb2bb93f8347",
  "FromUserName":"or5715HsCeFmycfU8gz0wx0sXfso",
  "CreateTime":1623398596,
  "MsgType":"text",
  "Content":"还是睡吧",
  "MsgId":23241477706429916,
  "Encrypt":"v62EYjaWEIZ9VqALyzuv5rgM7jAXJAjR1K4jCoBHCAL/etsrtCnPgFAWQ8iCTACUoSY+boCpb4DWTRDa8QvCwanZLia8Need/RQaOE+THnTFq2U7vL/3jgCm6HdzvrqjqPSq7RSrzh40IASLkY1BXsO942AYG04wQdRq6P3GqqIjpZsklIyAwBL1c9I9+E+qoMsHO52DeHV4MOHaywX/itt0B77uaTVfEJSNznE/1OlLPSMczATH21RsR5Dwt8V0XhHt5F6QdJA8T6NDfeZs/e32uQcX74Bx4AKMORnfWHc="
}`
	token := "spamtest"
	nonce := "1320562132"
	appid := "wx2c2769f8efd9abc2"
	timestamp := "1409735669"
	msg_sign := "da92199ec168271c91d301577f90671fd3a7943e"                          // "5d197aaffba7e9b25a30732f161a50dee96bd5fa"
	encryp_test := NewTestWXBizMsgCrypt(token, encodingAESKey, appid, "json", true) // !!!IGNORE!!! signature validation :(
	encrypt_json, errcode := encryp_test.EncryptMsg(to_json, nonce, timestamp)
	if errcode != WXBizMsgCrypt_OK {
		t.Error("WXBizMsgCrypt encrypt with json error")
	}
	t.Logf("encrypt xml is:\n%s\n", encrypt_json)

	from_json := encrypt_json
	decrypt_test := NewTestWXBizMsgCrypt(token, encodingAESKey, appid, "json", true) // !!!IGNORE!!! signature validation :(
	var decrypt_json string
	decrypt_json, errcode = decrypt_test.DecryptMsg(from_json, msg_sign, timestamp, nonce)
	if errcode != WXBizMsgCrypt_OK {
		t.Error("WXBizMsgCrypt decrypt with json error")
	}
	t.Logf("decrypt json is:\n%s\n", decrypt_json)

	if RemoveSurplusCharactorsInXmlOrJson(to_json) != RemoveSurplusCharactorsInXmlOrJson(decrypt_json) {
		t.Error("WXBizMsgCrypt decrypt with json error")
	}
}
