package doh

import (
	"encoding/base64"
	"errors"
	"github.com/miekg/dns"
	"io/ioutil"
	"net/http"
)



type Doh struct {
}

func (rd *Doh)Resolve(domain string) (string,error){
	query := dns.Msg{}
	query.SetQuestion(domain+".", dns.TypeA)
	msg, _ := query.Pack()
	b64 := base64.RawURLEncoding.EncodeToString(msg)
	resp, err := http.Get("https://dns.alidns.com/dns-query?dns=" + b64)
	if err != nil {
		return "",err;
	}
	defer resp.Body.Close()
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	response := dns.Msg{}
	err=response.Unpack(bodyBytes)
	if err==nil {
		for _, v := range response.Answer {
			record, isType := v.(*dns.A)
			if isType {
				return record.A.String(), nil;
			}
		}
	}
	return "",errors.New("error")
}


