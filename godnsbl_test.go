package dnsbl

import (
	"net"
	"reflect"
	"testing"
)

type testSet struct {
	name      string
	blacklist Blacklist
	got       string
	want      *Result
}

var tests = []testSet{
	testSet{
		blacklist: BlacklistUceProtect,
		got:       "127.1.1.7",
		want:      &Result{},
	},
	testSet{
		blacklist: BlacklistUceProtect,
		got:       "1.2.3.4",
		want:      nil,
	},
	testSet{
		blacklist: BlacklistUceProtect,
		got:       "1.2.3.4",
		want:      &Result{},
	},
	testSet{
		blacklist: BlacklistBarracudaCentral,
		got:       "1.2.3.4",
		want:      &Result{},
	},
	testSet{
		blacklist: BlacklistEmailBasura,
		got:       "212.227.126.171",
		want:      &Result{},
	},
	testSet{
		blacklist: BlacklistSpamhausZen,
		got:       "127.0.0.1",
		want:      &Result{},
	},
	testSet{
		blacklist: BlacklistSpamCannibal,
		got:       "212.227.126.171",
		want:      &Result{},
	},
	testSet{
		blacklist: Blacklist("%d.%d.%d.%d.bl.emailbasura.org"),
		got:       "212.227.126.171",
		want:      &Result{},
	},
}

func TestXxx(t *testing.T) {
	for _, test := range tests {
		result, err := Check(test.blacklist, net.ParseIP(test.got))
		if err != nil {
			t.Errorf("Test failed for test blacklist %s with ip %s: %s", test.blacklist, test.got, err)
		}

		if !reflect.DeepEqual(result, test.want) {
			t.Errorf("Test failed for blacklist %s with ip %s\nGot: %#v, want: %#v", test.blacklist, test.got, result, test.want)
		}

	}
}
