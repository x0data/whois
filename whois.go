package whois

//https://data.iana.org/TLD/tlds-alpha-by-domain.txt
//https://publicsuffix.org/list/public_suffix_list.dat

import (
	"bytes"
	"fmt"
	"github.com/lanzay/x0Data/utils"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

var (
	REGISTRATOR_WHOIS = []byte("Registrar WHOIS Server")
	NO_MATCH          = []byte("No match")
	LABEL_SUFFIX      = []byte(": ")
)

//TODO списком, многопоточно
//парсер

func GetWhoisArr(domains []string) {

	//TODO !!! WHOIS

}

//Simple connection to whois servers with default timeout 5 sec
func GetWhois(domain string) ([]byte, bool, error) {

	return GetWhoisTimeout(domain, time.Second*5)
}

//Connection to whois servers with various time.Duration
func GetWhoisTimeout(domain string, timeout time.Duration) ([]byte, bool, error) {

	domain = strings.ToLower(domain)
	domain, _ = utils.GetDomainMain(domain)
	domain = strings.TrimSpace(domain)

	var (
		err    error
		res    []byte
		parts  []string
		zone   string
		resReg []byte
	)

	parts = strings.Split(domain, ".")
	if len(parts) < 2 {
		err = fmt.Errorf("Domain(%s) name is wrong!", domain)
		return nil, false, err
	}
	//last part of domain is zome
	zone = parts[len(parts)-1]

	server, ok := servers[zone]
	if !ok {
		err = fmt.Errorf("No such server for zone %s. Domain %s.", zone, domain)
		return nil, false, err
	}

	resZone, err := getResp(domain, server, timeout)
	if err != nil || len(resZone) == 0 {
		return res, false, err
	}

	if bytes.EqualFold(NO_MATCH, resZone[:len(NO_MATCH)]) {
		return res, false, err
	}

	if regWhoIs, ok := GetLabel(resZone, REGISTRATOR_WHOIS); ok {
		resReg, err = getResp(domain, string(regWhoIs), timeout)
	}

	res = append(res, resZone...)
	res = append(res, resReg...)
	return res, true, err
}

func getResp(domain, server string, timeout time.Duration) ([]byte, error) {

	domain = strings.ToLower(domain)
	domain = strings.TrimSpace(domain)

	connection, err := net.DialTimeout("tcp", net.JoinHostPort(server, "43"), timeout)
	if err != nil {
		return nil, err
	}
	defer connection.Close()

	connection.Write([]byte(domain + "\r\n"))
	buffer, err := ioutil.ReadAll(connection)
	if err != nil {
		return nil, err
	}

	buffer = bytes.ReplaceAll(buffer, []byte("\r\n"), []byte("\n"))
	buffer = bytes.ReplaceAll(buffer, []byte("\r"), []byte("\n"))
	return buffer, nil
}
func GetLabelMust(body []byte, label string) string {
	if res, ok := GetLabel(body, []byte(label)); ok {
		return string(res)
	}
	return ""
}

func GetLabel(body []byte, label []byte) ([]byte, bool) {

	label = append(label, LABEL_SUFFIX...)

	if start := bytes.Index(body, label); start > 0 {
		start += len(label)
		if end := bytes.Index(body[start:], []byte("\n")); end >= 0 {
			end += start
			res := body[start:end]
			return res, true
		}
		return body[start:], true
	}
	return nil, false
}
