package srp

import (
	"fmt"
	"math/big"
)

// Group represents an SRP group with its parameters N (prime) and g (generator).
// These groups are defined in RFC5054 Section 3.
//
// Security Considerations:
// @risk Spoofing: Weak group parameters allow offline attacks. Always use standard
// RFC5054 groups rather than custom parameters.
// @risk Denial of Service: Larger groups (4096-bit) provide more security but require
// more CPU time. Balance security needs with performance requirements.
type Group struct {
	// N is the large safe prime (N = 2q + 1, where q is also prime)
	N *big.Int

	// g is the generator modulo N
	g *big.Int

	// BitLength is the size of N in bits
	BitLength int
}

// GetGroup returns the SRP group parameters for the specified group ID.
// Valid group IDs: 3 (2048-bit), 4 (3072-bit), 5 (4096-bit).
//
// Returns an error if the group ID is invalid.
func GetGroup(groupID int) (*Group, error) {
	switch groupID {
	case 3:
		return getGroup3(), nil
	case 4:
		return getGroup4(), nil
	case 5:
		return getGroup5(), nil
	default:
		return nil, fmt.Errorf("invalid group ID: %d (valid: 3, 4, 5)", groupID)
	}
}

// getGroup3 returns the 2048-bit group from RFC5054.
// This is the recommended minimum for most applications.
func getGroup3() *Group {
	// RFC5054 Appendix A, 2048-bit Group
	N := new(big.Int)
	N.SetString(""+
		"AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050"+
		"A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50"+
		"E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8"+
		"55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B"+
		"CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748"+
		"544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6"+
		"AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6"+
		"94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
		16)

	g := big.NewInt(2)

	return &Group{
		N:         N,
		g:         g,
		BitLength: 2048,
	}
}

// getGroup4 returns the 3072-bit group from RFC5054.
// Provides stronger security at the cost of performance.
func getGroup4() *Group {
	// RFC5054 Appendix A, 3072-bit Group
	N := new(big.Int)
	N.SetString(""+
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"+
		"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"+
		"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"+
		"98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"+
		"9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"+
		"3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"+
		"A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"+
		"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"+
		"D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"+
		"08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
		16)

	g := big.NewInt(5)

	return &Group{
		N:         N,
		g:         g,
		BitLength: 3072,
	}
}

// getGroup5 returns the 4096-bit group from RFC5054.
// Provides the strongest security but with significant performance cost.
func getGroup5() *Group {
	// RFC5054 Appendix A, 4096-bit Group
	N := new(big.Int)
	N.SetString(""+
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"+
		"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"+
		"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"+
		"98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"+
		"9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"+
		"3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"+
		"A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"+
		"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"+
		"D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"+
		"08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"+
		"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8"+
		"DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"+
		"233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"+
		"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
		16)

	g := big.NewInt(5)

	return &Group{
		N:         N,
		g:         g,
		BitLength: 4096,
	}
}

// k computes the multiplier parameter k = H(N | g) as defined in SRP-6a.
// This is used during both registration and authentication.
func (grp *Group) k() *big.Int {
	// k = H(N | PAD(g))
	// where PAD(g) pads g to the same length as N
	NBytes := grp.N.Bytes()
	gBytes := grp.g.Bytes()

	// Pad g to the same length as N
	paddedG := make([]byte, len(NBytes))
	copy(paddedG[len(paddedG)-len(gBytes):], gBytes)

	// Concatenate N and g
	combined := append(NBytes, paddedG...)

	// Hash the result
	hash := hashSHA256(combined)

	// Convert to big.Int
	k := new(big.Int).SetBytes(hash)
	return k
}

// GetGenerator returns the generator g for this group.
func (grp *Group) GetGenerator() *big.Int {
	return new(big.Int).Set(grp.g)
}

// GetPrime returns the prime N for this group.
func (grp *Group) GetPrime() *big.Int {
	return new(big.Int).Set(grp.N)
}
