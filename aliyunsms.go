package aliyun

import (
	"fmt"
	"errors"
	"encoding/json"
	"regexp"
	"net/url"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"sort"
	"time"
	"strconv"
	"net/http"
	"github.com/satori/go.uuid"
)


type Sms struct {
	accessKeyId string
	accessSercret string
	signName string
	dict map[string]string
}

// 网络请求返回的数据格式
type (
	SmsResponse struct {
		RequestId string `json:"RequestId"`
		Code string `json:"Code"`
		Message string `json:"Message"`
		BizId string `json:"BizId"`
	}
)

type para struct {
	key string
	value string
}

type paras []para

func (c paras) Len() int {
	return len(c)
}
func (c paras) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}
func (c paras) Less(i, j int) bool {
	return c[i].key < c[j].key
}

func New(accessKeyId string, accessSercret string, signName string) *Sms {
	return &Sms{
		accessKeyId,
		accessSercret,
		signName,
		map[string]string{
			"OK": "请求成功",
			"isp.RAM_PERMISSION_DENY": "RAM权限DENY",
			"isv.OUT_OF_SERVICE": "业务停机",
			"isv.PRODUCT_UN_SUBSCRIPT": "未开通云通信产品的阿里云客户",
			"isv.PRODUCT_UNSUBSCRIBE": "产品未开通",
			"isv.ACCOUNT_NOT_EXISTS": "账户不存在",
			"isv.ACCOUNT_ABNORMAL": "账户异常",
			"isv.SMS_TEMPLATE_ILLEGAL": "短信模板不合法",
			"isv.SMS_SIGNATURE_ILLEGAL": "短信签名不合法",
			"isv.INVALID_PARAMETERS": "参数异常",
			"isp.SYSTEM_ERROR": "系统错误",
			"isv.MOBILE_NUMBER_ILLEGAL": "非法手机号",
			"isv.MOBILE_COUNT_OVER_LIMIT": "手机号码数量超过限制",
			"isv.TEMPLATE_MISSING_PARAMETERS": "模板缺少变量",
			"isv.BUSINESS_LIMIT_CONTROL": "业务限流",
			"isv.INVALID_JSON_PARAM": "JSON参数不合法，只接受字符串值",
			"isv.BLACK_KEY_CONTROL_LIMIT": "黑名单管控",
			"isv.PARAM_LENGTH_LIMIT": "参数超出长度限制",
			"isv.PARAM_NOT_SUPPORT_URL": "不支持URL",
			"isv.AMOUNT_NOT_ENOUGH": "账户余额不足",
		},
	}
}
func trans(i int) string {
	if i < 10 {
		return "0" + strconv.Itoa(i)  
	}
	return strconv.Itoa(i)  
}
func (s *Sms) genRequestUrl  (
	phoneNumbers string, 
	templateParam string, templateCode string) string{
	parasSlice := make(paras, 0)
	now := time.Now().UTC()
	timestamp := trans(now.Year()) + "-" + trans(int(now.Month())) + "-" + trans(now.Day()) + "T"+ trans(now.Hour()) + ":" + trans(now.Minute()) + ":" 	+ trans(now.Second()) + "Z";
	// 1. 系统参数
	parasSlice = append(parasSlice,para{"SignatureMethod","HMAC-SHA1"})
	parasSlice = append(parasSlice,para{"SignatureNonce",uuid.NewV4().String()})
	parasSlice = append(parasSlice,para{"AccessKeyId",s.accessKeyId})
	parasSlice = append(parasSlice,para{"SignatureVersion","1.0"})
	parasSlice = append(parasSlice,para{
		"Timestamp",
		timestamp,
	})
	parasSlice = append(parasSlice,para{"Format","JSON"})
	// 2. 业务API参数
	parasSlice = append(parasSlice,para{"Action","SendSms"})	
	parasSlice = append(parasSlice,para{"Version","2017-05-25"})
	parasSlice = append(parasSlice,para{"RegionId","cn-hangzhou"})
	parasSlice = append(parasSlice,para{"PhoneNumbers",phoneNumbers})
	parasSlice = append(parasSlice,para{"SignName",s.signName})
	if templateParam != "" {
		parasSlice = append(parasSlice,para{"TemplateParam",templateParam})
	}
	parasSlice = append(parasSlice,para{"TemplateCode",templateCode})
	// 4. 参数KEY排序
	sort.Sort(parasSlice)
	// 5. 构造待签名的字符串
	var sortQueryStringTmp string
	for _, _para := range parasSlice {
		_key := specialUrlEncode(_para.key) 
		_value := specialUrlEncode(_para.value) 
		sortQueryStringTmp += "&" + _key + "=" + _value
	}

	reg := regexp.MustCompile(`^&`)
	sortedQueryString := reg.ReplaceAllString(sortQueryStringTmp, "")
	stringToSign := "GET&"
	stringToSign += specialUrlEncode("/") + "&"
	stringToSign += specialUrlEncode(sortedQueryString)
	sign := sign(s.accessSercret + "&", stringToSign)

	// 6. 签名最后也要做特殊URL编码
	signature := specialUrlEncode(sign);

	return "http://dysmsapi.aliyuncs.com/?Signature=" + signature + sortQueryStringTmp
}

func sign(accessSercret string, stringToSign string) string {
	key := []byte(accessSercret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func specialUrlEncode(value string) string {
	value = url.QueryEscape(value)
	reg := regexp.MustCompile(`\+`)
	value = reg.ReplaceAllString(value,"%20")
	reg = regexp.MustCompile(`\*`)
	value = reg.ReplaceAllString(value,"%2A")
	reg = regexp.MustCompile(`%7E`)
	value = reg.ReplaceAllString(value,"-")
	reg = regexp.MustCompile(`=$`)
	value = reg.ReplaceAllString(value,"")
	return value
}

func (s *Sms) Send(phoneNumbers string,
	templateParam map[string]interface{}, templateCode string) (SmsResponse, error) {
		templateParamString, terr := json.MarshalIndent(templateParam, "", "	")
		if terr != nil {
			return SmsResponse{}, terr
		}
		uri := s.genRequestUrl(phoneNumbers,string(templateParamString),templateCode);
		resp, err := http.Get(uri)
		if err != nil {
			return SmsResponse{}, err
		}
		defer resp.Body.Close()
	
		var sr SmsResponse
		// var sresult SmsResult
		err = json.NewDecoder(resp.Body).Decode(&sr)
		if err != nil {
			return SmsResponse{}, err
		}
		if sr.Code == "OK" {
			return sr, nil
		}else if _, exists := s.dict[sr.Code]; exists {
			return SmsResponse{}, errors.New(s.dict[sr.Code])
		}else {
			fmt.Println(sr);
			return SmsResponse{}, errors.New("unknown error")
		}
	}