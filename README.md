# WXBizMsgCrypt4Go
WXBizMsgCrypt's golang version, support xml / json format

---

## Installation

Install `WXBizMsgCrypt4Go` by running following command in terminal:
	
```shell
go get -u github.com/co60/WXBizMsgCrypt4Go
```

Then import it like this:

```golang
import "github.com/co60/WXBizMsgCrypt4Go"
```

Main methods' Definition:
	
```golang
	func NewDefaultWXBizMsgCrypt(token, keyStr, appid string) WXBizMsgCrypt {  // WXBizMsgCrypt for XML
	
	... ...
	
	func NewWXBizMsgCrypt(token, keyStr, appid, format string) WXBizMsgCrypt { // WXBizMsgCrypt for specified format (`xml` | `json`)
```

---

## Examples

* XML (default)
	
```golang
	encodingAESKey := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	to_xml := "<xml><ToUserName><![CDATA[oia2TjjewbmiOUlr6X-1crbLOvLw]]></ToUserName><FromUserName><![CDATA[gh_7f083739789a]]></FromUserName><CreateTime>1407743423</CreateTime><MsgType>  <![CDATA[video]]></MsgType><Video><MediaId><![CDATA[eYJ1MbwPRJtOvIEabaxHs7TX2D-HV71s79GUxqdUkjm6Gs2Ed1KF3ulAOA9H1xG0]]></MediaId><Title><![CDATA[testCallBackReplyVideo]]></Title><Descript  ion><![CDATA[testCallBackReplyVideo]]></Description></Video></xml>"
	token := "spamtest"
	nonce := "1320562132"
	appid := "wx2c2769f8efd9abc2"
	timestamp := "1409735669"
	msg_sign := "da92199ec168271c91d301577f90671fd3a7943e" // "5d197aaffba7e9b25a30732f161a50dee96bd5fa"
	encryp_test := WXBizMsgCrypt4Go.NewDefaultWXBizMsgCrypt(token, encodingAESKey, appid)
	encrypt_xml, errcode := encryp_test.EncryptMsg(to_xml, nonce, timestamp)
	if errcode != WXBizMsgCrypt4Go.WXBizMsgCrypt_OK {
		fmt.Println("WXBizMsgCrypt encrypt with xml error")
	}
	fmt.Printf("encrypt xml is:\n%s\n", encrypt_xml)

	// from_xml := "<xml><ToUserName><![CDATA[gh_10f6c3c3ac5a]]></ToUserName><FromUserName><![CDATA[oyORnuP8q7ou2gfYjqLzSIWZf0rs]]></FromUserName><CreateTime>1409735668</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[abcdteT]]></Content><MsgId>6054768590064713728</MsgId><Encrypt><![CDATA[hyzAe4OzmOMbd6TvGdIOO6uBmdJoD0Fk53REIHvxYtJlE2B655HuD0m8KUePWB3+LrPXo87wzQ1QLvbeUgmBM4x6F8PGHQHFVAFmOD2LdJF9FrXpbUAh0B5GIItb52sn896wVsMSHGuPE328HnRGBcrS7C41IzDWyWNlZkyyXwon8T332jisa+h6tEDYsVticbSnyU8dKOIbgU6ux5VTjg3yt+WGzjlpKn6NPhRjpA912xMezR4kw6KWwMrCVKSVCZciVGCgavjIQ6X8tCOp3yZbGpy0VxpAe+77TszTfRd5RJSVO/HTnifJpXgCSUdUue1v6h0EIBYYI1BD1DlD+C0CR8e6OewpusjZ4uBl9FyJvnhvQl+q5rv1ixrcpCumEPo5MJSgM9ehVsNPfUM669WuMyVWQLCzpu9GhglF2PE=]]></Encrypt></xml>"
	from_xml := encrypt_xml
	decrypt_test := WXBizMsgCrypt4Go.NewDefaultWXBizMsgCrypt(token, encodingAESKey, appid)
	var decryp_xml string
	decryp_xml, errcode = decrypt_test.DecryptMsg(from_xml, msg_sign, timestamp, nonce)
	fmt.Printf("decrypt xml is:\n%s\n", decryp_xml)
```

* JSON (in compacity mode)

```golang
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
	encryp_test := WXBizMsgCrypt4Go.NewTestWXBizMsgCrypt(token, encodingAESKey, appid, "json", true) // !!!IGNORE!!! signature validation :(
	encrypt_json, errcode := encryp_test.EncryptMsg(to_json, nonce, timestamp)
	if errcode != WXBizMsgCrypt4Go.WXBizMsgCrypt_OK {
		fmt.Println("WXBizMsgCrypt encrypt with json error")
		return
	}
	fmt.Printf("encrypt xml is:\n%s\n", encrypt_json)

	from_json := encrypt_json
	decrypt_test := WXBizMsgCrypt4Go.NewTestWXBizMsgCrypt(token, encodingAESKey, appid, "json", true) // !!!IGNORE!!! signature validation :(
	var decrypt_json string
	decrypt_json, errcode = decrypt_test.DecryptMsg(from_json, msg_sign, timestamp, nonce)
	if errcode != WXBizMsgCrypt4Go.WXBizMsgCrypt_OK {
		fmt.Printf("WXBizMsgCrypt decrypt with json error\n")
		return
	}
	fmt.Printf("decrypt json is:\n%s\n", decrypt_json)
```

---

## Link
[Wechat miniprogram](https://developers.weixin.qq.com/miniprogram/dev/framework/server-ability/message-push.html#option-url)

---

## License
WXBizMsgCrypt4Go is MIT licensed.
