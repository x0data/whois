package whois

import (
	"bytes"
	"fmt"
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

//Simple connection to whois servers with default timeout 5 sec
func GetWhois(domain string) ([]byte, bool, error) {

	return GetWhoisTimeout(domain, time.Second*5)
}

//Connection to whois servers with various time.Duration
func GetWhoisTimeout(domain string, timeout time.Duration) ([]byte, bool, error) {

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
	if regWhoIs, ok := GetLabel(resZone, REGISTRATOR_WHOIS); ok {
		resReg, err = getResp(domain, string(regWhoIs), timeout)
	}

	if bytes.EqualFold(NO_MATCH, resZone[:len(NO_MATCH)]) {
		return res, false, err
	}

	res = append(res, resZone...)
	res = append(res, resReg...)
	return res, true, err
}

func getResp(domain, server string, timeout time.Duration) ([]byte, error) {

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
		if end := bytes.Index(body[start:], []byte("\n")); end > 0 {
			end += start - 1
			res := body[start:end]
			return res, true
		}
		return body[start:], true
	}
	return nil, false
}
