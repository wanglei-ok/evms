package evms

import (
	"testing"
)

var verifySignDatas = []struct {
	sig  string
	msg  string
	addr string
	want bool
}{
	//error
	{"", "", "0x57B8ab5a4Dbbbc9D7B27260333e0D8440c2Fd0", false},
	{"0xerror", "", "0x57B8ab5a4Dbbbe6c9D7B27260333e0D8440c2Fd0", false},
	{"0x7e", "", "0x57B8ab5a4Dbbbe6c9D7B27260333e0D8440c2Fd0", false},
	{"0x7e46a58802f8e329266d017bf46300c8e4ddbe9126eba29e7faa704aa456f67d785c6f62b9e896cb04974f81680ebe3db0e5024f335574a281a3f18b69a0287402", "wangleitest", "0x57B8ab5a4Dbbbe6c9D7B27260333e0D8440c2Fd0", false},
	{"0x7e46a58802f8e329266d017bf46300c8e4ddbe9126eba29e7faa704aa456f67d785c6f62b9e896cb04974f81680ebe3db0e5024f335574a281a3f18b69a0287401", "", "0x57B8ab5a4Dbbbe6c9D7B27260333e0D8440c2Fd0", false},

	//success
	{"0x7e46a58802f8e329266d017bf46300c8e4ddbe9126eba29e7faa704aa456f67d785c6f62b9e896cb04974f81680ebe3db0e5024f335574a281a3f18b69a0287401", "wangleitest", "0x57B8ab5a4Dbbbe6c9D7B27260333e0D8440c2Fd0", true},
	{"0x85589aa36c3d5e1080e17220ae33768c42054b519cf90934bffd92b341dc1b6e4f2f632e21cf3ad104db746a02c8126a2cbb4232ee5c5b7d40085e598e5460351c", "Signing a Message with the first best available private key for 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf. | 20 APR 2017 09:46:48", "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", true},
	{"0x76f2609d7232ca9332463ad53e03146de7c0304b760f2b35596d9512558d7734023414a412d91f10d9d6f061631afb5c917bb754ef2e8ba4fa72c2155b4ecdd61b", "labas", "0x047BF4652cA38E616c4eB365F31411269Ce03114", true},
	{"0x075d5c86c5067199e5b0bc37cdd72e39686753cf133f653e2107ecb72c270cd733185130247e24198c04181d1fb3cea11d805f045749674ec4bfe9b6b2f6c2031b", "I certify that the address 0xddb6e01f91d5ebbb0cbb9a24a0cf32c7206e943d is mine. CODE=NC6QLJSH", "0xddb6e01f91d5ebbb0cbb9a24a0cf32c7206e943d", true},
	{"0x833a3715a1292d7aebf11da675afb9926a2d680b1f61d66eca03557b5d5b59b812ae99a9aefe6a1a41a0e8b4e829c75e57c57017a4881421847d05eee799105c1c", "[Etherscan.io 09/05/2018 17:26:39] I, hereby verify that the information provided is accurate and I am the owner/creator of the token contract address [0x8e517df4b2378b2ab021368081841b95b193bac7]", "0x9d568cf46c4b595532f9cffd5c82508d15d40d77", true},
	{"0x9e0e81bd8cb9ad047be2fa3f8e7f7fb730111d2da37ecf2a130b767eaf2adfd976d97fbe98c15ad97e11f89d35cb9f77f9a0efdbee2de450ab5b5cf65e49c9691b", "[Etherscan.io 07/05/2018 09:58:33] I, hereby verify that the information provided is accurate and I am the owner/creator of the token contract address [0x7fe52904070ef775e87c0b6c24575f8119a29154]", "0x89235ea0373b437c9d64fa348c7eb991887acbef", true},
	{"0x34ff4b97a0ec8f735f781f250dcd3070a72ddb640072dd39553407d0320db79939e3b080ecaa2e9f248214c6f0811fb4b4ba05b7bcff254c053e47d8513e820900", "Christopher Pearce", "0x36d85Dc3683156e63Bf880A9fAb7788CF8143a27", true},
	{"0xf4cf5582a0eb9234c8798123eadc75a60d503a0a95be856a8ee62e2de9d84a037990e271f02daf16ed815f485c6963eee2e0a64fcc7a5fb570025f7ac1a4b6d21b", "[Etherscan.io 15/05/2018 08:41:00] I, hereby verify that the information provided is accurate and I am the owner/creator of the Minerall.io address [0x09ab1303d3ccaf5f018cd511146b07a240c70294]", "0x09ab1303d3ccaf5f018cd511146b07a240c70294", true},
	{"0x42190b8157174b1f6a269006d40bdd488ea0d998e86257445df26ede9995dc650e631cf09a14c9c636fe31ab18e8e5c00760f375ab0119de8e7568bc481c08f71b", "VIN6LBdxPb1CvEnEiiGt65QJkyFLhhzsHJy6K3QXeYpSRuS8rYAtW", "0x279e58a1718b9348fd0f54ba980251c47b4c5559", true},
}

func testVerifyMessage() {

}

func TestVerifyMessages(t *testing.T) {
	for _, vsd := range verifySignDatas {
		err, _ := VerifyMessage(vsd.addr, vsd.sig, vsd.msg)
		var pass bool
		if err != nil {
			pass = false
		} else {
			pass = true
		}
		if pass != vsd.want {
			t.Errorf("want:%v %v.", pass, err)
		}
	}
}
