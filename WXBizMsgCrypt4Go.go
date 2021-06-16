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
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"math/rand"
	"sort"
	"strings"
	"time"
)

const AES_Block_Size int32 = 32

const EncodingAESKeyLen int32 = 16
const DataLengthLen uint32 = 4

type AES_Mode int

const (
	AES_MODE_ECB     AES_Mode = 1
	AES_MODE_CBC     AES_Mode = 2
	AES_MODE_CFB     AES_Mode = 3
	AES_MODE_OFB     AES_Mode = 5
	AES_MODE_CTR     AES_Mode = 6
	AES_MODE_OPENPGP AES_Mode = 7
	AES_MODE_CCM     AES_Mode = 8
	AES_MODE_EAX     AES_Mode = 9
	AES_MODE_SIV     AES_Mode = 10
	AES_MODE_GCM     AES_Mode = 11
	AES_MODE_OCB     AES_Mode = 12
)

type WXBizMsgCryptErr int32

const (
	WXBizMsgCrypt_OK                     WXBizMsgCryptErr = 0
	WXBizMsgCrypt_ValidateSignatureError WXBizMsgCryptErr = -40001
	WXBizMsgCrypt_ParseXmlError          WXBizMsgCryptErr = -40002
	WXBizMsgCrypt_ComputeSignatureError  WXBizMsgCryptErr = -40003
	WXBizMsgCrypt_IllegalAesKey          WXBizMsgCryptErr = -40004
	WXBizMsgCrypt_ValidateAppidError     WXBizMsgCryptErr = -40005
	WXBizMsgCrypt_EncryptAESError        WXBizMsgCryptErr = -40006
	WXBizMsgCrypt_DecryptAESError        WXBizMsgCryptErr = -40007
	WXBizMsgCrypt_IllegalBuffer          WXBizMsgCryptErr = -40008
	WXBizMsgCrypt_EncodeBase64Error      WXBizMsgCryptErr = -40009
	WXBizMsgCrypt_DecodeBase64Error      WXBizMsgCryptErr = -40010
	WXBizMsgCrypt_GenReturnXmlError      WXBizMsgCryptErr = -40011
)

func GetErrMessage(errcode WXBizMsgCryptErr) string {
	switch errcode {
	case WXBizMsgCrypt_ValidateSignatureError:
		return "签名验证错误"
	case WXBizMsgCrypt_IllegalAesKey:
		return "SymmetricKey非法"
	case WXBizMsgCrypt_ValidateAppidError:
		return "appid校验失败"
	case WXBizMsgCrypt_EncryptAESError:
		return "aes加密失败"
	case WXBizMsgCrypt_DecryptAESError:
		return "aes解密失败"
	case WXBizMsgCrypt_ParseXmlError:
		return "xml解析失败"
	case WXBizMsgCrypt_IllegalBuffer:
		return "解密后得到的buffer非法"
	case WXBizMsgCrypt_EncodeBase64Error:
		return "base64加密错误"
	case WXBizMsgCrypt_DecodeBase64Error:
		return "base64解密错误"
	case WXBizMsgCrypt_GenReturnXmlError:
		return "xml生成失败"
	default:
		return "成功"
	}
}

type SHA1 struct{}

func (hashlib SHA1) getSHA1(token, timestamp, nonce, encrypt string) (string, WXBizMsgCryptErr) {
	sortlist := []string{token, timestamp, nonce, encrypt}
	sort.Strings(sortlist)
	hashmaker := sha1.New()
	_, err := io.WriteString(hashmaker, strings.Join(sortlist, ""))
	if err != nil {
		return "", WXBizMsgCrypt_ComputeSignatureError
	}
	hashBytes := hashmaker.Sum(nil)
	return fmt.Sprintf("%x", hashBytes), WXBizMsgCrypt_OK
}

type CDATA struct {
	Text string `xml:",cdata"`
}

/**
 * `<xml>
 * <Encrypt><![CDATA[%(msg_encrypt)s]]></Encrypt>
 * <MsgSignature><![CDATA[%(msg_signaturet)s]]></MsgSignature>
 * <TimeStamp>%(timestamp)s</TimeStamp>
 * <Nonce><![CDATA[%(nonce)s]]></Nonce>
 * </xml>`
 */
type AesTextResp struct {
	XMLName      xml.Name `xml:"xml"`
	MsgEncrypt   CDATA    `xml:"Encrypt"`
	MsgSignature CDATA    `xml:"MsgSignature"`
	TimeStamp    string   `xml:"TimeStamp"`
	Nonce        CDATA    `xml:"Nonce"`
}

/**
 * <xml><ToUserName><![CDATA[gh_10f6c3c3ac5a]]></ToUserName>
 * <FromUserName><![CDATA[oyORnuP8q7ou2gfYjqLzSIWZf0rs]]></FromUserName>
 * <CreateTime>1409735668</CreateTime>
 * <MsgType><![CDATA[text]]></MsgType>
 * <Content><![CDATA[abcdteT]]></Content>
 * <MsgId>6054768590064713728</MsgId>
 * </xml>
 */
type TextMsg struct {
	XMLName    xml.Name `xml:"xml"`
	ToUserName CDATA    `xml:"ToUserName"`
	CreateTime CDATA    `xml:"CreateTime"`
	MsgType    CDATA    `xml:"MsgType"`
	Content    CDATA    `xml:"Content"`
	Encrypt    CDATA    `xml:"Encrypt"`
	MsgId      CDATA    `xml:"MsgId"`
}

type XMLParse struct{}

func (parse XMLParse) extract(xmltext string) (string, string, WXBizMsgCryptErr) {
	v := TextMsg{
		ToUserName: CDATA{""},
	}
	err := xml.Unmarshal([]byte(xmltext), &v)
	if err != nil {
		log.Printf("%s\n", err.Error())
		return "", "", WXBizMsgCrypt_ParseXmlError
	}
	return v.Encrypt.Text, v.ToUserName.Text, WXBizMsgCrypt_OK
}

func (parse XMLParse) generate(encrypt, signature, timestamp, nonce string) string {
	msg := AesTextResp{
		MsgEncrypt:   CDATA{encrypt},
		MsgSignature: CDATA{signature},
		TimeStamp:    timestamp,
		Nonce:        CDATA{nonce},
	}
	// respBytes, err := xml.Marshal(msg)
	respBytes, err := xml.MarshalIndent(msg, "", "\r")
	if err != nil {
		log.Printf("generate xml error: %s, xml param: %+v\n", err, msg)
	}
	resp_xml := string(respBytes)
	log.Printf("xml: %s\n", resp_xml)
	return string(resp_xml)
}

type PKCS7Encoder struct {
	BlockSize int
}

func NewDefaultPKCS7Encoder() PKCS7Encoder {
	return PKCS7Encoder{32}
}

/**
 * 对需要加密的明文进行填充补位
 * @param text: 需要进行填充补位操作的明文
 * @return: 补齐明文字符串
 */
func (encoder PKCS7Encoder) encode(text []byte) []byte {
	text_length := len(text)
	amount_to_pad := encoder.BlockSize - (text_length % encoder.BlockSize)
	if amount_to_pad == 0 {
		amount_to_pad = encoder.BlockSize
	}
	pad := byte(amount_to_pad)
	resultBytes := make([]byte, text_length+amount_to_pad)
	copy(resultBytes, text)
	for i := 0; i < amount_to_pad; i++ {
		resultBytes[i+text_length] = pad
	}
	return resultBytes
}

/**
 * 删除解密后明文的补位字符
 * @param decrypted: 解密后的明文
 * @return: 删除补位字符后的明文
 */
func (encoder PKCS7Encoder) decode(decrypted []byte) []byte {
	length := len(decrypted)
	if length > 0 {
		unPadding := int(decrypted[length-1])
		return decrypted[:(length - unPadding)]
	}
	return decrypted
}

type Prpcrypt struct {
	Key  []byte
	Mode AES_Mode
}

/**
 * 随机生成16位字符串
 * @return: 16位字符串
 */
func (pc Prpcrypt) get_random_str() string {
	length := 16
	str := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < length; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}

/**
 * 对明文进行加密
 * @param text: 需要加密的明文
 * @return: 加密得到的字符串
 */
func (pc Prpcrypt) encrypt(rawData string, appid string) (string, WXBizMsgCryptErr) {
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, uint32(len(rawData)))
	text := pc.get_random_str() + string(bs) + rawData + appid
	var plainTextBytes []byte = []byte(text)
	pkcs7 := NewDefaultPKCS7Encoder()
	plainTextBytes = pkcs7.encode(plainTextBytes)
	cryptor, errCipher := aes.NewCipher(pc.Key)
	if errCipher != nil {
		return "", WXBizMsgCrypt_EncryptAESError
	}
	encrypter := cipher.NewCBCEncrypter(cryptor, pc.Key[:EncodingAESKeyLen])
	encrypter.CryptBlocks(plainTextBytes, plainTextBytes)
	resultData := base64.StdEncoding.EncodeToString(plainTextBytes)
	return resultData, WXBizMsgCrypt_OK
}

/**
 * 对解密后的明文进行补位删除
 * @param encryptedData: 密文
 * @param appid: 小程序AppId
 * @return: 删除填充补位后的明文
 */
func (pc Prpcrypt) decrypt(encryptedData string, appid string) (string, WXBizMsgCryptErr) {
	cryptor, errCipher := aes.NewCipher(pc.Key)
	if errCipher != nil {
		return "", WXBizMsgCrypt_DecryptAESError
	}
	cipherTextBytes, errChipherText := base64.StdEncoding.DecodeString(encryptedData)
	if errChipherText != nil {
		return "", WXBizMsgCrypt_DecodeBase64Error
	}
	plainTextBytes := make([]byte, len(cipherTextBytes))
	decrypter := cipher.NewCBCDecrypter(cryptor, pc.Key[:EncodingAESKeyLen])
	decrypter.CryptBlocks(plainTextBytes, cipherTextBytes)
	pkcs7Encoder := NewDefaultPKCS7Encoder()
	plainTextBytes = pkcs7Encoder.decode(plainTextBytes)
	plainTextBytes = plainTextBytes[EncodingAESKeyLen:]
	plainTextBytesLen := plainTextBytes[:DataLengthLen]
	rawLen := binary.BigEndian.Uint32(plainTextBytesLen)
	resultBytes := plainTextBytes[DataLengthLen : rawLen+DataLengthLen]
	// rawAppId := plainTextBytes[rawLen+4:]
	// fmt.Printf("raw AppId is %s\n", string(rawAppId))
	return string(resultBytes), WXBizMsgCrypt_OK
}

type WXBizMsgCrypt struct {
	Token  string
	Key    []byte
	Appid  string
	Format string // json or xml (default) format output
	IgnSig bool   // ignore signature validation (just in test mode)
}

func NewDefaultWXBizMsgCrypt(token, keyStr, appid string) WXBizMsgCrypt {
	keyBytes, _ := base64.StdEncoding.DecodeString(keyStr + "=")
	return WXBizMsgCrypt{token, keyBytes, appid, "xml", false}
}

func NewWXBizMsgCrypt(token, keyStr, appid, format string) WXBizMsgCrypt {
	keyBytes, _ := base64.StdEncoding.DecodeString(keyStr + "=")
	if strings.ToLower(format) != "xml" {
		return WXBizMsgCrypt{token, keyBytes, appid, "json", false}
	}
	return WXBizMsgCrypt{token, keyBytes, appid, "xml", false}
}

func NewTestWXBizMsgCrypt(token, keyStr, appid, format string, ignoreSig bool) WXBizMsgCrypt {
	keyBytes, _ := base64.StdEncoding.DecodeString(keyStr + "=")
	return WXBizMsgCrypt{token, keyBytes, appid, format, ignoreSig}
}

func (wxcrypt WXBizMsgCrypt) EncryptMsg(replyData string, nonce string, timestamp string) (string, WXBizMsgCryptErr) {
	pc := Prpcrypt{wxcrypt.Key, AES_MODE_CBC}
	encrypt, errcode := pc.encrypt(replyData, wxcrypt.Appid)
	if errcode != WXBizMsgCrypt_OK {
		return "", errcode
	}
	if timestamp == "" {
		timestamp = fmt.Sprintf("%d", time.Now().Unix())
	}
	// xml processes
	if wxcrypt.Format == "xml" {
		hashlib := SHA1{}
		signature, err := hashlib.getSHA1(wxcrypt.Token, timestamp, nonce, encrypt)
		if err != WXBizMsgCrypt_OK {
			log.Printf("%s", GetErrMessage(WXBizMsgCrypt_OK))
			return "", err
		}
		xmlParse := XMLParse{}
		encrypt = xmlParse.generate(encrypt, signature, timestamp, nonce)
		return encrypt, WXBizMsgCrypt_OK
	}
	return encrypt, WXBizMsgCrypt_OK
}

func (wxcrypt WXBizMsgCrypt) DecryptMsg(postData string, msgSignature string, timestamp string, nonce string) (string, WXBizMsgCryptErr) {
	encrypt := postData
	// xml processes
	toUserName := ""
	if wxcrypt.Format == "xml" {
		xmlParse := XMLParse{}
		encrypt_data, touser_name, ret := xmlParse.extract(postData)
		if ret != WXBizMsgCrypt_OK {
			return "", WXBizMsgCrypt_ParseXmlError
		}
		encrypt = encrypt_data
		toUserName = touser_name
		log.Printf("\nDecrypt message to user name: %s\n", toUserName)
	}
	hashlib := SHA1{}
	signature, errcode := hashlib.getSHA1(wxcrypt.Token, timestamp, nonce, encrypt)
	if errcode != WXBizMsgCrypt_OK {
		return "", errcode
	}
	if !wxcrypt.IgnSig && signature != msgSignature {
		return "", WXBizMsgCrypt_ValidateSignatureError
	}
	pc := Prpcrypt{wxcrypt.Key, AES_MODE_CBC}
	raw, ec := pc.decrypt(encrypt, wxcrypt.Appid)
	return raw, ec
}

func RemoveSurplusCharactorsInXmlOrJson(src string) string {
	dst := src
	dst = strings.Replace(dst, " ", "", -1)
	dst = strings.Replace(dst, "\n", "", -1)
	dst = strings.Replace(dst, "\r", "", -1)
	return dst
}

// func IsLittleEndian() bool {
// 	var i int32 = 0x01020304
// 	u := unsafe.Pointer(&i)
// 	pb := (*byte)(u)
// 	b := *pb
// 	return (b == 0x04)
// }
