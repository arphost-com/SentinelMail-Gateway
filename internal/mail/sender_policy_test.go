package mail

import (
	"reflect"
	"testing"
)

func TestSenderListLookupAddressesIncludesReplyTo(t *testing.T) {
	got := senderListLookupAddresses(
		"info@texas5.texasd7.com",
		`"Blocked Reply" <blocked@example.net>`,
	)
	want := []string{"info@texas5.texasd7.com", "blocked@example.net"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("senderListLookupAddresses = %#v, want %#v", got, want)
	}
}

func TestSenderListLookupAddressesParsesMultipleReplyToValues(t *testing.T) {
	got := senderListLookupAddresses(
		"info@texas5.texasd7.com",
		`Sales <reply@example.net>, abuse@example.org`,
		"INFO@TEXAS5.TEXASD7.COM",
	)
	want := []string{"info@texas5.texasd7.com", "reply@example.net", "abuse@example.org"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("senderListLookupAddresses = %#v, want %#v", got, want)
	}
}
