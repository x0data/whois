# golang-whois

golang-whois is light golang module for checking domain's whois using root servers.

## Overview

whois.go: A golang module for domain whois query.

servers.go: Worldwide [servers list](servers.md) for getting whois info. 

extra.go: some extra functions to parse whois info

## Installation

    go get github.com/x0data/whois

## Importing

    import (
        "github.com/x0data/whois"
    )

## How to use

    func GetWhois(domain string) (result string, err error)

    func GetWhoisTimeout(domain string, timeout time.Duration) (result string, err error)
    
    GetLabelMust(body []byte, label string) string 

## Example

    if res, ok, err := whois.GetWhois("att.com"); ok {
    		println(string(whois.GetLabelMust(res, "Domain Name")))
    		println(string(whois.GetLabelMust(res, "Registrant Organization")))
    		println(string(whois.GetLabelMust(res, "Registrant Email")))
    		println(string(whois.GetLabelMust(res, "Registrant Phone")))
    
    		println(string(whois.GetLabelMust(res, "Admin Organization")))
    		println(string(whois.GetLabelMust(res, "Admin Email")))
    		println(string(whois.GetLabelMust(res, "Admin Phone")))
    
    		println(string(whois.GetLabelMust(res, "Tech Organization")))
    		println(string(whois.GetLabelMust(res, "Tech Email")))
    		println(string(whois.GetLabelMust(res, "Tech Phone")))
    	} else {
    		println("[E]", err)
    	}

## LICENSE

Copyright 2019, undiabler, Lanzay 

Apache License, Version 2.0

